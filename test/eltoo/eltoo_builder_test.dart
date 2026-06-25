// Copyright (c) 2026 Soqucoin Labs Inc.
// Distributed under the MIT software license.
//
// eltoo_builder_test.dart — Opt3 P5: the DilithiumEltooBuilder assembles the eLTOO tx graph
// correctly and plugs into the UpdateTxBuilder seam. Verification here is STRUCTURAL +
// self-consistency (the composed primitives are individually node-pinned in P1–P4; the graph
// itself is validated on stagenet in P6, not against an offline vector).

import 'dart:typed_data';

import 'package:soqushield_sdk/eltoo.dart';
import 'package:soqushield_sdk/lightning.dart';
import 'package:test/test.dart';

void main() {
  final initiatorPub = Uint8List.fromList(List.generate(1312, (i) => i % 256));
  final peerPub = Uint8List.fromList(List.generate(1312, (i) => (i + 7) % 256));
  final initiatorSpk = Uint8List.fromList([0x51, 0x20, ...List.generate(32, (i) => i)]); // v1 spk
  final peerSpk = Uint8List.fromList([0x51, 0x20, ...List.generate(32, (i) => 0xff - i)]);
  final secretKey = Uint8List.fromList(List.filled(32, 0x11));
  final funding = OutPoint(Uint8List.fromList(List.filled(32, 0xfd)), 0);
  final fundingAmount = BigInt.from(100000000);

  Uint8List mockSign(Uint8List message, Uint8List sk) {
    final out = Uint8List(2420);
    for (var i = 0; i < 2420; i++) {
      out[i] = (sk[0] + message[i % message.length] + i) & 0xff;
    }
    return out;
  }

  DilithiumEltooBuilder builder({int csv = 288}) => DilithiumEltooBuilder(EltooBuilderOpts(
        funding: funding,
        fundingAmountSat: fundingAmount,
        initiatorPub: initiatorPub,
        peerPub: peerPub,
        initiatorScriptPubKey: initiatorSpk,
        peerScriptPubKey: peerSpk,
        secretKey: secretKey,
        sign: mockSign,
        settlementCsv: csv,
      ));

  // A minimal UpdateContext (the builder reads only the next-state fields).
  UpdateContext ctx({int state = 1, int init = 80000000, int peer = 20000000}) => UpdateContext(
        channel: const LnChannel(
          channelId: 'ch_1',
          initiatorPubKeyHex: '',
          peerPubKeyHex: '',
          capacitySat: 100000000,
          initiatorBalanceSat: 100000000,
          peerBalanceSat: 0,
          stateIndex: 0,
          state: 'open',
          csvDelay: 288,
          createdAtUnix: 0,
        ),
        nextStateIndex: state,
        nextInitiatorBalanceSat: init,
        nextPeerBalanceSat: peer,
      );

  group('Opt3 P5 — tx graph construction', () {
    test('buildUpdateTx: v2, locktime=state+1, funding input, v6 output at capacity', () {
      final tx = builder().buildUpdateTx(5);
      expect(tx.version, 2);
      expect(tx.locktime, 6); // state + 1
      expect(tx.vin.length, 1);
      expect(toHex(tx.vin[0].prevout.txid), toHex(funding.txid));
      expect(tx.vin[0].sequence, 0);
      expect(tx.vout.length, 1);
      expect(tx.vout[0].value, fundingAmount);
      // output re-commits the state-N B1 eLTOO script as a v6 program
      final expectedSpk = p2wshV6(eltooUpdateScriptV6(5, initiatorPub, peerPub, settlementCsv: 288));
      expect(toHex(tx.vout[0].scriptPubKey), toHex(expectedSpk));
    });

    test('buildSettlementTx: v2, CSV sequence, 2 balance outputs spending the update', () {
      final updateTxid = txidInternal(builder().buildUpdateTx(1));
      final s = builder().buildSettlementTx(updateTxid, BigInt.from(80000000), BigInt.from(20000000));
      expect(s.version, 2);
      expect(s.vin[0].sequence, 288); // relative CSV (ELSE branch)
      expect(toHex(s.vin[0].prevout.txid), toHex(updateTxid)); // spends the update
      expect(s.vout.length, 2);
      expect(s.vout[0].value, BigInt.from(80000000));
      expect(toHex(s.vout[0].scriptPubKey), toHex(initiatorSpk));
      expect(s.vout[1].value, BigInt.from(20000000));
      expect(toHex(s.vout[1].scriptPubKey), toHex(peerSpk));
    });
  });

  group('Opt3 P5 — build(ctx) seam + self-consistency', () {
    test('is a drop-in UpdateTxBuilder (the Opt2→Opt3 swap)', () {
      expect(builder(), isA<UpdateTxBuilder>());
    });

    test('build() returns real hex + a ctv_hash consistent with the settlement graph', () async {
      final b = builder();
      final r = await b.build(ctx());

      // ctv_hash must equal the CTV hash of the settlement tx the builder derives.
      final updateTxid = txidInternal(b.buildUpdateTx(1));
      final settlement = b.buildSettlementTx(updateTxid, BigInt.from(80000000), BigInt.from(20000000));
      expect(r.ctvHash, toHex(ctvHash(settlement, 0)));

      // update hex carries the 0x42 signature (legacy/opaque transport): much larger than an
      // unsigned tx, and the placeholder is gone.
      expect(r.updateTxHex.length, greaterThan(2 * 2420)); // >2420-byte sig embedded
      expect(r.updateTxHex, isNot('placeholder'));
      expect(r.settlementTxHex, isNot('placeholder'));
    });

    test('deterministic for a fixed ctx (mock signer) and sensitive to balance changes', () async {
      final b = builder();
      final a1 = await b.build(ctx());
      final a2 = await b.build(ctx());
      expect(a1.updateTxHex, a2.updateTxHex);
      expect(a1.ctvHash, a2.ctvHash);

      final diff = await b.build(ctx(init: 70000000, peer: 30000000));
      expect(diff.ctvHash, isNot(a1.ctvHash)); // settlement payout changed → CTV changed
    });
  });
}
