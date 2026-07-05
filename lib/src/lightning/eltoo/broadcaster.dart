// Copyright (c) 2026 Soqucoin Labs Inc.
// Distributed under the MIT software license.
//
// broadcaster.dart — first-class broadcast orchestration for B1 eLTOO channels.
//
// Dart mirror of soq-lightning-sdk/src/eltoo-broadcast.ts (EltooBroadcaster). Where
// DilithiumEltooBuilder (eltoo_builder.dart) emits OPAQUE transport hex with a single sig in
// scriptSig (the LSP co-sign path), this composes the node-pinned keyhash/sighash/serialization
// primitives into the broadcastable graph: build the unsigned tx, each party signs ONLY its own
// partial, and combine the two into a witness-serialized tx ready for sendrawtransaction.
//
// PURE composition — no new crypto/scripts/serializers. Proven live on stagenet via the TS
// equivalent (self-custody-canary: funded 2-of-2 → co-signed round → user broadcast update +
// settlement WITHOUT the LSP). The locktime/fee/0x42-amount conventions match that proven path.

import 'dart:typed_data';

import 'keyhash.dart';
import 'script.dart';
import 'serialization.dart';
import 'sighash.dart';

/// Static, per-channel context (spec §E). Everything needed to deterministically rebuild +
/// co-sign any state's txs. Unlike [EltooBuilderOpts] it holds NO secret key (each party signs
/// separately) and adds [feeSat].
class ChannelParams {
  final OutPoint funding; // the funding 2-of-2 keyhash outpoint
  final BigInt capacitySat; // funding output value
  final Uint8List initiatorPub; // A — raw 1312-byte ML-DSA-44
  final Uint8List peerPub; // B — raw 1312-byte ML-DSA-44
  final Uint8List initiatorScriptPubKey; // A's settlement payout
  final Uint8List peerScriptPubKey; // B's settlement payout
  final int settlementCsv; // explicit (spec §H: a channel-open param)
  final BigInt feeSat; // fixed per-tx fee (v1 policy, spec §H)

  const ChannelParams({
    required this.funding,
    required this.capacitySat,
    required this.initiatorPub,
    required this.peerPub,
    required this.initiatorScriptPubKey,
    required this.peerScriptPubKey,
    required this.settlementCsv,
    required this.feeSat,
  });
}

/// A fully-assembled, broadcastable transaction. [hex] is BIP141 witness-serialized; [txid] is
/// internal byte order; [txidDisplay] is reversed for display.
class SignedTx {
  final Tx tx;
  final String hex;
  final Uint8List txid;
  final String txidDisplay;
  const SignedTx(this.tx, this.hex, this.txid, this.txidDisplay);
}

bool _bytesEqual(Uint8List a, Uint8List b) {
  if (a.length != b.length) return false;
  for (var i = 0; i < a.length; i++) {
    if (a[i] != b[i]) return false;
  }
  return true;
}

/// Builds, partial-signs, and assembles the broadcastable txs of a B1 eLTOO channel: the
/// funding→update, update-supersedes-update, settlement (ELSE/CSV), and cooperative close.
class EltooBroadcaster {
  final ChannelParams p;

  EltooBroadcaster(this.p) {
    if (p.initiatorPub.length != 1312 || p.peerPub.length != 1312) {
      throw ArgumentError('initiatorPub/peerPub must be raw 1312-byte ML-DSA-44 keys');
    }
  }

  // ── scripts ──

  /// The funding output's witnessScript: `<kh(B)> CDKH <kh(A)> CDKH OP_1` (bare 2-of-2 keyhash).
  Uint8List fundingWitnessScript() =>
      keyhashFunding2of2(p.initiatorPub, p.peerPub).witnessScript;

  /// The eLTOO update output's witnessScript for [stateNum] (IF/CLTV ratchet | ELSE/CSV settle).
  Uint8List eltooScript(int stateNum) =>
      eltooUpdateScriptV6(stateNum, p.initiatorPub, p.peerPub, settlementCsv: p.settlementCsv);

  // ── unsigned tx builders (deterministic) ──

  /// Tu,0 — spend the funding 2-of-2 to a fresh eLTOO(stateNum) output. value = capacity − fee.
  /// nLockTime = stateNum+1 (spec §B.3 / LSP Task-7; the funding has no CLTV so consensus ignores
  /// it, but the LSP rejects locktime 0).
  Tx buildFundingUpdateTx(int stateNum) => Tx(
        version: 2,
        locktime: stateNum + 1,
        vin: [TxIn(prevout: p.funding, sequence: 0xffffffff, scriptPubKey: Uint8List(0))],
        vout: [TxOut(p.capacitySat - p.feeSat, p2wshV6(eltooScript(stateNum)))],
      );

  /// Tu,next — spend a prior eLTOO output via the IF (supersession) branch into a fresh
  /// eLTOO(newState) output. nLockTime defaults to prevState+1 to clear the spent floor; sequence
  /// is non-final (0xfffffffe) so CLTV is active.
  Tx buildSupersedeTx({
    required OutPoint prevOutpoint,
    required BigInt prevValueSat,
    required int prevState,
    required int newState,
    int? lockTime,
  }) {
    if (newState < prevState) {
      throw ArgumentError('supersede: newState must be ≥ prevState (monotonic)');
    }
    return Tx(
      version: 2,
      locktime: lockTime ?? prevState + 1,
      vin: [TxIn(prevout: prevOutpoint, sequence: 0xfffffffe, scriptPubKey: Uint8List(0))],
      vout: [TxOut(prevValueSat - p.feeSat, p2wshV6(eltooScript(newState)))],
    );
  }

  /// Ts — spend an eLTOO output via the ELSE/CSV branch, paying both balances. The two outputs
  /// MUST sum to (updateValue − fee) (balance conservation, spec §D.2/§1.5).
  Tx buildSettlementTx({
    required OutPoint updateOutpoint,
    required BigInt updateValueSat,
    required BigInt initiatorBalanceSat,
    required BigInt peerBalanceSat,
  }) {
    _assertConserves(updateValueSat, initiatorBalanceSat, peerBalanceSat);
    return Tx(
      version: 2,
      locktime: 0,
      vin: [TxIn(prevout: updateOutpoint, sequence: p.settlementCsv, scriptPubKey: Uint8List(0))],
      vout: [
        TxOut(initiatorBalanceSat, p.initiatorScriptPubKey),
        TxOut(peerBalanceSat, p.peerScriptPubKey),
      ],
    );
  }

  /// Ts,0 — the state-0 full-refund settlement (self-funded open, spec §3.2). The channel opens
  /// with ALL funds on the initiator's side, so the settlement spends the state-0 update output
  /// via the ELSE/CSV branch to a SINGLE output (the initiator's payout = updateValue − fee). This
  /// is NOT [buildSettlementTx] with a zero peer balance: the LSP REJECTS a 2-output state-0
  /// settlement (manager rule 7 requires exactly one output — no dust peer output at open), and
  /// [peerScriptPubKey] is not yet known at open time.
  Tx buildRefundSettlementTx({
    required OutPoint updateOutpoint,
    required BigInt updateValueSat,
  }) {
    final refund = updateValueSat - p.feeSat;
    if (refund <= BigInt.zero) {
      throw ArgumentError('refund settlement: updateValue $updateValueSat ≤ fee ${p.feeSat}');
    }
    return Tx(
      version: 2,
      locktime: 0,
      vin: [TxIn(prevout: updateOutpoint, sequence: p.settlementCsv, scriptPubKey: Uint8List(0))],
      vout: [TxOut(refund, p.initiatorScriptPubKey)],
    );
  }

  /// Cooperative close (spec §F.1) — spend the funding 2-of-2 directly to final balances: no
  /// eLTOO output, no CSV. Outputs MUST sum to (capacity − fee).
  Tx buildCooperativeCloseTx({
    required BigInt initiatorBalanceSat,
    required BigInt peerBalanceSat,
  }) {
    _assertConserves(p.capacitySat, initiatorBalanceSat, peerBalanceSat);
    return Tx(
      version: 2,
      locktime: 0,
      vin: [TxIn(prevout: p.funding, sequence: 0xffffffff, scriptPubKey: Uint8List(0))],
      vout: [
        TxOut(initiatorBalanceSat, p.initiatorScriptPubKey),
        TxOut(peerBalanceSat, p.peerScriptPubKey),
      ],
    );
  }

  // ── partial signing (each party, own key only) ──

  /// One party's partial over a funding-2-of-2 spend (Tu,0 or cooperative close). amount =
  /// capacity. hashType 0x42 (eLTOO update) or 0x01 (SIGHASH_ALL close).
  KeyhashPartial signFundingPartial(
    Tx tx,
    Uint8List secretKey,
    Uint8List pubKey,
    MlDsaSign sign, {
    int hashType = sighashAnyprevoutAnyscript,
  }) {
    if (hashType != sighashAnyprevoutAnyscript && hashType != sighashAll) {
      throw ArgumentError('funding-spend hashType must be 0x42 or 0x01');
    }
    return partialSignKeyhash2of2(
        fundingWitnessScript(), tx, 0, hashType, p.capacitySat, secretKey, pubKey, sign);
  }

  /// One party's partial over an eLTOO branch spend (supersede or settlement). Always 0x42:
  /// ANYPREVOUTANYSCRIPT empties the scriptCode in the digest, so the empty scriptCode here is
  /// byte-identical to signing over the spent eLTOO script. amount = the spent output's value.
  KeyhashPartial signEltooPartial(
    Tx tx,
    BigInt spentValueSat,
    Uint8List secretKey,
    Uint8List pubKey,
    MlDsaSign sign,
  ) =>
      partialSignKeyhash2of2(Uint8List(0), tx, 0, sighashAnyprevoutAnyscript, spentValueSat,
          secretKey, pubKey, sign);

  // ── assemble fully-signed broadcastable tx from two partials ──

  /// Assemble a funding-2-of-2 spend (Tu,0 or coop close). combineKeyhash2of2Witness is
  /// order-robust. Trailing pubkey defaults to the initiator's (any party key is valid).
  SignedTx assembleFundingSpend(Tx tx, List<KeyhashPartial> partials, {Uint8List? trailingPubKey}) {
    final wit = combineKeyhash2of2Witness(fundingWitnessScript(), partials,
        trailingPubKey: trailingPubKey ?? dilithiumWitnessPubKey(p.initiatorPub));
    return _signed(tx, wit);
  }

  /// Assemble a supersession (IF-branch) spend of the eLTOO(prevState) output.
  SignedTx assembleSupersede(Tx tx, int prevState, List<KeyhashPartial> partials,
      {Uint8List? trailingPubKey}) {
    final ab = _orderAB(partials);
    final wit = eltooUpdateBranchWitness(eltooScript(prevState), ab.a.sig, ab.a.pubKey, ab.b.sig,
        ab.b.pubKey, trailingPubKey ?? dilithiumWitnessPubKey(p.initiatorPub));
    return _signed(tx, wit);
  }

  /// Assemble a settlement (ELSE/CSV-branch) spend of the eLTOO(prevState) output.
  SignedTx assembleSettlement(Tx tx, int prevState, List<KeyhashPartial> partials,
      {Uint8List? trailingPubKey}) {
    final ab = _orderAB(partials);
    final wit = eltooSettlementBranchWitness(eltooScript(prevState), ab.a.sig, ab.a.pubKey, ab.b.sig,
        ab.b.pubKey, trailingPubKey ?? dilithiumWitnessPubKey(p.initiatorPub));
    return _signed(tx, wit);
  }

  // ── internals ──

  /// Match the two partials to the initiator (A) / peer (B) slots by pubkey, rejecting a partial
  /// whose key is neither (a footgun that would silently build an invalid witness).
  ({KeyhashPartial a, KeyhashPartial b}) _orderAB(List<KeyhashPartial> partials) {
    final khA = dilithiumKeyHash(p.initiatorPub);
    final khB = dilithiumKeyHash(p.peerPub);
    KeyhashPartial? a, b;
    for (final part in partials) {
      final kh = dilithiumKeyHash(part.pubKey);
      if (_bytesEqual(kh, khA)) {
        a = part;
      } else if (_bytesEqual(kh, khB)) {
        b = part;
      } else {
        throw ArgumentError('partial pubkey matches neither the initiator nor the peer channel key');
      }
    }
    if (a == null || b == null) {
      throw ArgumentError('need exactly one partial from the initiator and one from the peer');
    }
    return (a: a, b: b);
  }

  void _assertConserves(BigInt inputValueSat, BigInt initiatorBalanceSat, BigInt peerBalanceSat) {
    if (initiatorBalanceSat < BigInt.zero || peerBalanceSat < BigInt.zero) {
      throw ArgumentError('balances must be non-negative');
    }
    if (initiatorBalanceSat + peerBalanceSat != inputValueSat - p.feeSat) {
      throw ArgumentError(
          'balance conservation violated: $initiatorBalanceSat + $peerBalanceSat ≠ $inputValueSat − ${p.feeSat} (fee)');
    }
  }

  SignedTx _signed(Tx tx, List<Uint8List> witness) {
    final i = tx.vin[0];
    final wtx = Tx(
      version: tx.version,
      locktime: tx.locktime,
      vin: [
        TxIn(prevout: i.prevout, sequence: i.sequence, scriptPubKey: i.scriptPubKey, witness: witness)
      ],
      vout: tx.vout,
    );
    return SignedTx(wtx, serializeTxHex(wtx), txidInternal(tx), txid(tx));
  }
}
