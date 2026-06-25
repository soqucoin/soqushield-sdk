// Copyright (c) 2026 Soqucoin Labs Inc.
// Distributed under the MIT software license.
//
// eltoo_builder.dart — Opt3 P5: the real DilithiumEltooBuilder.
//
// Byte-for-byte port of channel.ts:570-643. This is the piece that flips Opt2 → Opt3: it
// implements the same UpdateTxBuilder seam the PlaceholderTxBuilder satisfies, so dropping it
// into SoqLightning(txBuilder: ...) makes payments self-custodial with ZERO facade/UI change.
//
// For each state transition it builds the canonical eLTOO tx graph (update output re-commits the
// state-N script; settlement spends it via the CSV branch paying both balances), signs the update
// input with SIGHASH_ANYPREVOUTANYSCRIPT (0x42, rebindable), and returns the opaque transport hex
// + the CTV hash committing the settlement payout.
//
// ⚠️ NOT YET NODE-VALIDATED. Like the TS source, the exact tx graph must be byte-checked against a
// node vector + accepted on stagenet (P6) before any real broadcast. The crypto PRIMITIVES it
// composes (serialization, APO-0x42 sighash, CTV, keyhash funding) are individually node-pinned
// (P1–P4); the GRAPH assembly is not. Do not broadcast builder output to mainnet until P6 passes.

import 'dart:typed_data';

import '../update_tx_builder.dart';
import 'ctv.dart';
import 'script.dart';
import 'serialization.dart';
import 'sighash.dart';

/// Inputs for the eLTOO builder. [funding] is the channel funding (or genesis) outpoint;
/// [fundingAmountSat] is the capacity (the input amount the update spends). [initiatorPub]/
/// [peerPub] are the two ML-DSA-44 pubkeys; [initiatorScriptPubKey]/[peerScriptPubKey] are the
/// settlement payout scripts. [secretKey] is OUR ML-DSA-44 key (signs the update with 0x42).
/// [sign] injects the ML-DSA signer (e.g. DilithiumNative.instance.sign).
class EltooBuilderOpts {
  final OutPoint funding;
  final BigInt fundingAmountSat;
  final Uint8List initiatorPub;
  final Uint8List peerPub;
  final Uint8List initiatorScriptPubKey;
  final Uint8List peerScriptPubKey;
  final Uint8List secretKey;
  final MlDsaSign sign;
  final int settlementCsv;

  const EltooBuilderOpts({
    required this.funding,
    required this.fundingAmountSat,
    required this.initiatorPub,
    required this.peerPub,
    required this.initiatorScriptPubKey,
    required this.peerScriptPubKey,
    required this.secretKey,
    required this.sign,
    this.settlementCsv = 288,
  });
}

/// Real self-custodial eLTOO TX builder (Opt3). Plugs into [SoqLightning] via [UpdateTxBuilder].
class DilithiumEltooBuilder implements UpdateTxBuilder {
  final EltooBuilderOpts o;
  const DilithiumEltooBuilder(this.o);

  /// The update TX for state [stateNum]: spends the funding output into a v6 output that
  /// re-commits the state-N eLTOO script. locktime = stateNum+1 satisfies the prior script's
  /// IF-branch CLTV (newer state supersedes older).
  Tx buildUpdateTx(int stateNum) {
    final ws = eltooUpdateScript(stateNum, o.initiatorPub, o.peerPub, settlementCsv: o.settlementCsv);
    return Tx(
      version: 2,
      locktime: stateNum + 1,
      vin: [TxIn(prevout: o.funding, sequence: 0, scriptPubKey: Uint8List(0))],
      vout: [TxOut(o.fundingAmountSat, p2wshV6(ws))],
    );
  }

  /// The settlement TX spending the update output (n=0) via the relative-CSV ELSE branch,
  /// paying both balances out to their settlement scripts.
  Tx buildSettlementTx(
      Uint8List updateTxid, BigInt initiatorBalanceSat, BigInt peerBalanceSat) {
    return Tx(
      version: 2,
      locktime: 0,
      vin: [TxIn(prevout: OutPoint(updateTxid, 0), sequence: o.settlementCsv, scriptPubKey: Uint8List(0))],
      vout: [
        TxOut(initiatorBalanceSat, o.initiatorScriptPubKey),
        TxOut(peerBalanceSat, o.peerScriptPubKey),
      ],
    );
  }

  @override
  Future<UpdateTx> build(UpdateContext ctx) async {
    final stateNum = ctx.nextStateIndex;
    final updateTx = buildUpdateTx(stateNum);

    // Sign the update input with 0x42 (empty scriptCode — rebindable across states).
    final witnessSig = signApoWitness(
        Uint8List(0), updateTx, 0, sighashAnyprevoutAnyscript, o.fundingAmountSat, o.secretKey, o.sign);

    // Attach the sig as the input's scriptSig surrogate for opaque transport (broadcast uses
    // the witness). The txid commits the UNSIGNED form, so compute it before attaching.
    final updateTxid = txidInternal(updateTx);
    final signedUpdate = Tx(
      version: updateTx.version,
      locktime: updateTx.locktime,
      vin: [
        TxIn(
          prevout: updateTx.vin[0].prevout,
          sequence: updateTx.vin[0].sequence,
          scriptPubKey: Uint8List(0),
          scriptSig: witnessSig,
        ),
      ],
      vout: updateTx.vout,
    );

    final settlementTx = buildSettlementTx(
      updateTxid,
      BigInt.from(ctx.nextInitiatorBalanceSat),
      BigInt.from(ctx.nextPeerBalanceSat),
    );

    return UpdateTx(
      updateTxHex: toHex(serializeTxLegacy(signedUpdate)),
      settlementTxHex: toHex(serializeTxLegacy(settlementTx)),
      ctvHash: toHex(ctvHash(settlementTx, 0)),
    );
  }
}
