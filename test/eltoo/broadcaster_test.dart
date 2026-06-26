// Copyright (c) 2026 Soqucoin Labs Inc.
// Distributed under the MIT software license.
//
// broadcaster_test.dart — the broadcast orchestration + F1 LSP round (Dart mirror of
// soq-lightning-sdk/test/{eltoo_broadcast,two_party_broadcast}.test.mjs).
//
// Asserts STRUCTURE + the round logic (not cryptographic sig validity — the mock signer is
// structural; real ML-DSA verification rides on the vector_mldsa/FFI workstream, and the §E
// flow is proven live on stagenet via the TS self-custody-canary). Covers: the unsigned tx
// graph (locktime = stateNum+1, fee-deducted values), witness assembly, balance conservation,
// wrong-key rejection, the LSP round stitch, and the logical-vs-settlement balance seam.

import 'dart:typed_data';

import 'package:soqushield_sdk/src/lightning/eltoo/broadcaster.dart';
import 'package:soqushield_sdk/src/lightning/eltoo/script.dart';
import 'package:soqushield_sdk/src/lightning/eltoo/serialization.dart';
import 'package:soqushield_sdk/src/lightning/lsp_models.dart';
import 'package:soqushield_sdk/src/lightning/two_party_round.dart';
import 'package:test/test.dart';

void main() {
  final userPub = Uint8List.fromList(List.generate(1312, (i) => i % 256)); // A
  final lspPub = Uint8List.fromList(List.generate(1312, (i) => (i + 7) % 256)); // B
  final malPub = Uint8List.fromList(List.generate(1312, (i) => (i + 13) % 256));
  final skA = Uint8List.fromList(List.filled(32, 0x11));
  final skB = Uint8List.fromList(List.filled(32, 0x22));
  final skM = Uint8List.fromList(List.filled(32, 0x33));

  // Deterministic mock ML-DSA signer (structure only).
  Uint8List mockSign(Uint8List message, Uint8List secretKey) {
    final out = Uint8List(2420);
    for (var i = 0; i < 2420; i++) {
      out[i] = (secretKey[0] + message[i % message.length] + i) & 0xff;
    }
    return out;
  }

  final cap = BigInt.from(1000000000);
  final fee = BigInt.from(2000000);
  const state = 100;
  const csv = 6;
  final fundingOutpoint = OutPoint(Uint8List.fromList(List.filled(32, 0xfd)), 0);
  final spkA = p2wshV6(Uint8List.fromList([0x51]));
  final spkB = p2wshV6(Uint8List.fromList([0x51, 0x51]));

  ChannelParams params() => ChannelParams(
        funding: fundingOutpoint,
        capacitySat: cap,
        initiatorPub: userPub,
        peerPub: lspPub,
        initiatorScriptPubKey: spkA,
        peerScriptPubKey: spkB,
        settlementCsv: csv,
        feeSat: fee,
      );

  group('EltooBroadcaster', () {
    test('buildFundingUpdateTx: locktime stateNum+1, value capacity-fee, v6 output', () {
      final bc = EltooBroadcaster(params());
      final tx = bc.buildFundingUpdateTx(state);
      expect(tx.locktime, state + 1);
      expect(tx.vout.single.value, cap - fee);
      expect(tx.vout.single.scriptPubKey[0], Op.witnessV6);
      expect(tx.vin.single.prevout, fundingOutpoint);
    });

    test('assembleFundingSpend: two partials → witness-serialized broadcastable tx', () {
      final bc = EltooBroadcaster(params());
      final tx = bc.buildFundingUpdateTx(state);
      final pa = bc.signFundingPartial(tx, skA, userPub, mockSign);
      final pb = bc.signFundingPartial(tx, skB, lspPub, mockSign);
      final signed = bc.assembleFundingSpend(tx, [pa, pb]);
      expect(signed.hex.startsWith('020000000001'), isTrue); // version ‖ segwit marker/flag
      expect(signed.txidDisplay.length, 64);
    });

    test('assembleSettlement: ELSE/CSV branch, sequence=csv, fee-deducted balances', () {
      final bc = EltooBroadcaster(params());
      final update = bc.buildFundingUpdateTx(state);
      final uValue = update.vout[0].value;
      final init = BigInt.from(600000000);
      final peer = uValue - fee - init; // sum = capacity - 2*fee
      final settleTx = bc.buildSettlementTx(
        updateOutpoint: OutPoint(txidInternal(update), 0),
        updateValueSat: uValue,
        initiatorBalanceSat: init,
        peerBalanceSat: peer,
      );
      expect(settleTx.vin.single.sequence, csv);
      expect(settleTx.vout[0].value, init);
      final pa = bc.signEltooPartial(settleTx, uValue, skA, userPub, mockSign);
      final pb = bc.signEltooPartial(settleTx, uValue, skB, lspPub, mockSign);
      final signed = bc.assembleSettlement(settleTx, state, [pa, pb]);
      expect(signed.hex.startsWith('020000000001'), isTrue);
    });

    test('assembleSupersede is order-robust (either partial order → same bytes)', () {
      final bc = EltooBroadcaster(params());
      final update = bc.buildFundingUpdateTx(state);
      final sup = bc.buildSupersedeTx(
          prevOutpoint: OutPoint(txidInternal(update), 0),
          prevValueSat: cap - fee,
          prevState: state,
          newState: state);
      final pa = bc.signEltooPartial(sup, cap - fee, skA, userPub, mockSign);
      final pb = bc.signEltooPartial(sup, cap - fee, skB, lspPub, mockSign);
      expect(bc.assembleSupersede(sup, state, [pa, pb]).hex,
          bc.assembleSupersede(sup, state, [pb, pa]).hex);
    });

    test('buildSettlementTx rejects non-conserving balances', () {
      final bc = EltooBroadcaster(params());
      expect(
          () => bc.buildSettlementTx(
              updateOutpoint: OutPoint(Uint8List(32), 0),
              updateValueSat: cap - fee,
              initiatorBalanceSat: BigInt.one,
              peerBalanceSat: BigInt.one),
          throwsArgumentError);
    });

    test('assembleSettlement rejects a partial from a non-channel key', () {
      final bc = EltooBroadcaster(params());
      final tx = bc.buildSupersedeTx(
          prevOutpoint: OutPoint(Uint8List.fromList(List.filled(32, 1)), 0),
          prevValueSat: cap - fee,
          prevState: state,
          newState: state);
      final pa = bc.signEltooPartial(tx, cap - fee, skA, userPub, mockSign);
      final pm = bc.signEltooPartial(tx, cap - fee, skM, malPub, mockSign);
      expect(() => bc.assembleSupersede(tx, state, [pa, pm]), throwsArgumentError);
    });
  });

  group('lspUpdateRound (F1 stitch)', () {
    // A mock LSP that rebuilds the round's txs and co-signs BOTH with its key (the F1 response).
    LspUpdateStateFn mockLsp({bool omitSettlement = false}) => (UpdateStateReq req) async {
          final bc = EltooBroadcaster(params());
          final updateTx = bc.buildFundingUpdateTx(req.stateIndex);
          final uValue = updateTx.vout[0].value;
          // req carries the settlement balances directly here (no reqBalances in these tests).
          final settleTx = bc.buildSettlementTx(
            updateOutpoint: OutPoint(txidInternal(updateTx), 0),
            updateValueSat: uValue,
            initiatorBalanceSat: BigInt.from(req.initiatorBalanceSat),
            peerBalanceSat: BigInt.from(req.peerBalanceSat),
          );
          final up = bc.signFundingPartial(updateTx, skB, lspPub, mockSign);
          final st = bc.signEltooPartial(settleTx, uValue, skB, lspPub, mockSign);
          return UpdateStateResp(
            accepted: true,
            peerSignatureHex: toHex(up.sig),
            settlementSignatureHex: omitSettlement ? null : toHex(st.sig),
          );
        };

    test('stitches both LSP partials → closeable (Tu, Ts) chained', () async {
      final bc = EltooBroadcaster(params());
      final uValue = cap - fee;
      final init = BigInt.from(600000000);
      final peer = uValue - fee - init;
      final round = await lspUpdateRound(bc, mockLsp(),
          stateNum: state,
          initiatorBalanceSat: init,
          peerBalanceSat: peer,
          userSecretKey: skA,
          userPub: userPub,
          lspPub: lspPub,
          mldsa: mockSign);
      expect(round.update.hex.startsWith('020000000001'), isTrue);
      expect(round.settlement.hex.startsWith('020000000001'), isTrue);
      // settlement spends the update output → txid chains
      expect(round.settlement.tx.vin[0].prevout.txid, round.update.txid);
    });

    test('throws if the LSP omits the settlement partial (F1 not deployed)', () async {
      final bc = EltooBroadcaster(params());
      expect(
          () => lspUpdateRound(bc, mockLsp(omitSettlement: true),
              stateNum: state,
              initiatorBalanceSat: BigInt.from(600000000),
              peerBalanceSat: (cap - fee) - fee - BigInt.from(600000000),
              userSecretKey: skA,
              userPub: userPub,
              lspPub: lspPub,
              mldsa: mockSign),
          throwsStateError);
    });

    test('combineLspRound rejects the legacy "countersigned" stub', () {
      final bc = EltooBroadcaster(params());
      final updateTx = bc.buildFundingUpdateTx(state);
      final uValue = cap - fee;
      final settleTx = bc.buildSettlementTx(
        updateOutpoint: OutPoint(txidInternal(updateTx), 0),
        updateValueSat: uValue,
        initiatorBalanceSat: BigInt.from(600000000),
        peerBalanceSat: uValue - fee - BigInt.from(600000000),
      );
      final uUser = bc.signFundingPartial(updateTx, skA, userPub, mockSign);
      final sUser = bc.signEltooPartial(settleTx, uValue, skA, userPub, mockSign);
      expect(
          () => combineLspRound(bc,
              updateTx: updateTx,
              settlementTx: settleTx,
              prevState: state,
              userUpdate: uUser,
              userSettle: sUser,
              lspPub: lspPub,
              lspUpdateSigHex: 'countersigned',
              lspSettleSigHex: '00' * 2421),
          throwsStateError);
    });

    test('seam: LSP gets LOGICAL balances (sum=capacity); settlement outputs fee-deducted',
        () async {
      final bc = EltooBroadcaster(params());
      final settleInit = BigInt.from(600000000);
      final settlePeer = BigInt.from(396000000); // sum 996M = cap - 2*fee
      const logicalInit = 604000000; // settleInit + 2*fee
      const logicalPeer = 396000000; // logicalInit + logicalPeer = 1B = capacity
      UpdateStateReq? captured;
      final lsp = (UpdateStateReq req) async {
        captured = req;
        final updateTx = bc.buildFundingUpdateTx(req.stateIndex);
        final uValue = updateTx.vout[0].value;
        final settleTx = bc.buildSettlementTx(
          updateOutpoint: OutPoint(txidInternal(updateTx), 0),
          updateValueSat: uValue,
          initiatorBalanceSat: settleInit,
          peerBalanceSat: settlePeer,
        );
        final up = bc.signFundingPartial(updateTx, skB, lspPub, mockSign);
        final st = bc.signEltooPartial(settleTx, uValue, skB, lspPub, mockSign);
        return UpdateStateResp(
            accepted: true,
            peerSignatureHex: toHex(up.sig),
            settlementSignatureHex: toHex(st.sig));
      };
      final round = await lspUpdateRound(bc, lsp,
          stateNum: state,
          initiatorBalanceSat: settleInit,
          peerBalanceSat: settlePeer,
          reqBalances: (initiatorSat: logicalInit, peerSat: logicalPeer),
          userSecretKey: skA,
          userPub: userPub,
          lspPub: lspPub,
          mldsa: mockSign);
      // LSP received LOGICAL balances summing to capacity.
      expect(captured!.initiatorBalanceSat + captured!.peerBalanceSat, cap.toInt());
      expect(captured!.initiatorBalanceSat, logicalInit);
      // settlement outputs are fee-deducted (sum = capacity - 2*fee).
      expect(round.settlement.tx.vout[0].value + round.settlement.tx.vout[1].value, cap - BigInt.two * fee);
    });
  });
}
