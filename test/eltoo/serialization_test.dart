// Copyright (c) 2026 Soqucoin Labs Inc.
// Distributed under the MIT software license.
//
// serialization_test.dart — Opt3 P1: pins the Dart consensus serializer to the SAME
// node-proven golden vectors (test/fixtures/onchain_vectors.json) the TS port is pinned to.
// These vectors were emitted by soq-signer's node-proven txbuilder (Phase-4 byte-less CTxOut).
// If rawTxHex + txid are byte-equal here, the serialization foundation is correct.

import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:soqushield_sdk/src/lightning/eltoo/serialization.dart';
import 'package:test/test.dart';

void main() {
  final v = jsonDecode(
      File('test/fixtures/onchain_vectors.json').readAsStringSync()) as Map<String, dynamic>;

  // Deterministic fixture inputs (onchain.test.mjs:23-25).
  final senderPub = Uint8List.fromList(List.generate(1312, (i) => i % 256));
  final fillerSig = Uint8List.fromList(List.filled(2420, 0xab));

  // Build the identical tx the node generator built (onchain.test.mjs buildFixtureTx +
  // the witness assembly), using the vector's scriptPubKeys directly so this test isolates
  // the serializer (address/script derivation is a later phase).
  Tx buildFixtureTx() {
    final witness = <Uint8List>[
      concatBytes([fillerSig, u8(0x01)]), // sig ‖ SIGHASH_ALL  → 2421
      concatBytes([u8(0x00), senderPub]), // 0x00 ‖ pubkey       → 1313
    ];
    return Tx(
      version: v['txVersion'] as int,
      locktime: 0,
      vin: [
        TxIn(
          prevout: OutPoint.fromTxidHex(v['utxoTxID'] as String, v['utxoVout'] as int),
          sequence: 0xffffffff,
          scriptPubKey: fromHex(v['senderSPKHex'] as String),
          witness: witness,
        ),
      ],
      vout: [
        TxOut(BigInt.from(v['sendAmount'] as int), fromHex(v['recipSPKHex'] as String)),
        TxOut(BigInt.from(v['out1Value'] as int), fromHex(v['senderSPKHex'] as String)),
      ],
    );
  }

  group('Opt3 P1 — consensus serialization (node-pinned)', () {
    test('fixture witness lengths match (2421 / 1313)', () {
      final tx = buildFixtureTx();
      final w = tx.vin[0].witness!;
      expect(w[0].length, v['witness0Len']);
      expect(w[1].length, v['witness1Len']);
    });

    test('full BIP144 serialization is byte-exact (rawTxHex)', () {
      expect(serializeTxHex(buildFixtureTx()), v['rawTxHex']);
    });

    test('txid is byte-exact (non-witness sha256d, display order)', () {
      expect(txid(buildFixtureTx()), v['txid']);
    });
  });

  group('Opt3 P1 — byte-writer + varint primitives', () {
    test('compactSize boundaries', () {
      expect(toHex(compactSize(0x00)), '00');
      expect(toHex(compactSize(0xfc)), 'fc');
      expect(toHex(compactSize(0xfd)), 'fdfd00');
      expect(toHex(compactSize(0xffff)), 'fdffff');
      expect(toHex(compactSize(0x10000)), 'fe00000100');
    });

    test('le64 wraps to uint64 little-endian', () {
      expect(toHex(le64(BigInt.from(0x0102030405060708))), '0807060504030201');
      expect(toHex(le64(BigInt.zero)), '0000000000000000');
    });

    test('le32 handles 0xffffffff (default sequence)', () {
      expect(toHex(le32(0xffffffff)), 'ffffffff');
    });

    test('serTxOut is Phase-4 byte-less: value ‖ compactSize(spk) ‖ spk', () {
      final spk = fromHex(v['recipSPKHex'] as String); // 34 bytes (0x22)
      final out = serTxOut(TxOut(BigInt.from(v['sendAmount'] as int), spk));
      // 8 (value) + 1 (compactSize 0x22) + 34 (spk) = 43; NO extension bytes.
      expect(out.length, 8 + 1 + spk.length);
      expect(out[8], spk.length); // single-byte compactSize, no nAssetType after value
    });
  });
}
