// Copyright (c) 2026 Soqucoin Labs Inc.
// Distributed under the MIT software license.
//
// ctv_test.dart — Opt3 P3: pins the BIP119 CTV template hash to the node vector and asserts
// tamper-sensitivity + the LE32-vs-compactSize length distinction.

import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:soqushield_sdk/src/lightning/eltoo/serialization.dart';
import 'package:soqushield_sdk/src/lightning/eltoo/ctv.dart';
import 'package:test/test.dart';

void main() {
  final v = jsonDecode(
      File('test/fixtures/apo_ctv_vectors.json').readAsStringSync()) as Map<String, dynamic>;

  Tx buildTx({int? vout0Value}) => Tx(
        version: v['version'] as int,
        locktime: v['locktime'] as int,
        vin: [
          TxIn(
            prevout:
                OutPoint(fromHex(v['vin0_prevout_hash'] as String), v['vin0_prevout_n'] as int),
            sequence: v['vin0_sequence'] as int,
            scriptPubKey: Uint8List(0),
          ),
        ],
        vout: [
          TxOut(BigInt.from(vout0Value ?? v['vout0_value'] as int),
              fromHex(v['vout0_scriptpubkey_hex'] as String)),
        ],
      );

  group('Opt3 P3 — CTV template hash (node-pinned)', () {
    test('ctvHash matches node ctv_hash', () {
      expect(toHex(ctvHash(buildTx(), 0)), v['ctv_hash']);
    });

    test('tamper-sensitive: changing an output value moves the hash', () {
      expect(toHex(ctvHash(buildTx(), 0)), isNot(toHex(ctvHash(buildTx(vout0Value: 9999999999), 0))));
    });

    test('serTxOutCtv uses an LE32 length prefix (distinct from consensus compactSize)', () {
      final spk = fromHex(v['vout0_scriptpubkey_hex'] as String); // "51" → 1 byte
      final out = serTxOutCtv(TxOut(BigInt.from(v['vout0_value'] as int), spk));
      // 8 (value) + 4 (LE32 len) + 1 (script) = 13; the length is 4 bytes, not 1.
      expect(out.length, 8 + 4 + spk.length);
      expect(out.sublist(8, 12), [spk.length, 0, 0, 0]); // LE32(1)
    });
  });
}
