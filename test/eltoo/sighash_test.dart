// Copyright (c) 2026 Soqucoin Labs Inc.
// Distributed under the MIT software license.
//
// sighash_test.dart — Opt3 P2: pins APO (0x41/0x42) + BIP143 sighashing to node vectors and
// asserts the eLTOO invariance properties (channel.test.mjs).

import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:soqushield_sdk/src/lightning/eltoo/serialization.dart';
import 'package:soqushield_sdk/src/lightning/eltoo/sighash.dart';
import 'package:test/test.dart';

void main() {
  final v = jsonDecode(
      File('test/fixtures/apo_ctv_vectors.json').readAsStringSync()) as Map<String, dynamic>;
  final oc = jsonDecode(
      File('test/fixtures/onchain_vectors.json').readAsStringSync()) as Map<String, dynamic>;

  // The APO vector tx: version 2, locktime 1, one input (prevout in internal byte order),
  // one output. apoSighash ignores the input's scriptPubKey, so it's empty here.
  Tx buildApoTx({OutPoint? prevout, int? vout0Value}) {
    return Tx(
      version: v['version'] as int,
      locktime: v['locktime'] as int,
      vin: [
        TxIn(
          prevout: prevout ??
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
  }

  final amount = BigInt.from(v['amount_sat'] as int);

  group('Opt3 P2 — APO sighash (node-pinned)', () {
    test('APO 0x42 digest matches node (scriptCode ignored → empty)', () {
      final got = toHex(
          apoSighash(Uint8List(0), buildApoTx(), 0, sighashAnyprevoutAnyscript, amount));
      expect(got, v['digest_apo_0x42']);
    });

    test('APO 0x41 digest matches node (commits scriptCode)', () {
      final got = toHex(apoSighash(
          fromHex(v['scriptcode_hex'] as String), buildApoTx(), 0, sighashAnyprevout, amount));
      expect(got, v['digest_apo_0x41']);
    });

    test('rejects ANYONECANPAY + APO and non-APO hash types', () {
      expect(() => apoSighash(Uint8List(0), buildApoTx(), 0, 0x42 | 0x80, amount),
          throwsArgumentError);
      expect(() => apoSighash(Uint8List(0), buildApoTx(), 0, 0x01, amount), throwsArgumentError);
    });
  });

  group('Opt3 P2 — BIP143 SIGHASH_ALL (node-pinned, onchain_vectors)', () {
    test('digest matches node sighashHex (scriptCode = input scriptPubKey)', () {
      final senderSpk = fromHex(oc['senderSPKHex'] as String);
      final tx = Tx(
        version: oc['txVersion'] as int,
        locktime: 0,
        vin: [
          TxIn(
            prevout: OutPoint.fromTxidHex(oc['utxoTxID'] as String, oc['utxoVout'] as int),
            sequence: 0xffffffff,
            scriptPubKey: senderSpk,
          ),
        ],
        vout: [
          TxOut(BigInt.from(oc['sendAmount'] as int), fromHex(oc['recipSPKHex'] as String)),
          TxOut(BigInt.from(oc['out1Value'] as int), senderSpk),
        ],
      );
      expect(toHex(bip143SighashAll(senderSpk, tx, 0, BigInt.from(oc['utxoValue'] as int))),
          oc['sighashHex']);
    });
  });

  group('Opt3 P2 — eLTOO invariance (channel.test.mjs)', () {
    test('APO 0x42 IGNORES the prevout (rebindable across states)', () {
      final a = apoSighash(Uint8List(0), buildApoTx(), 0, sighashAnyprevoutAnyscript, amount);
      final differentPrevout = OutPoint(Uint8List.fromList(List.filled(32, 0x99)), 7);
      final b = apoSighash(Uint8List(0), buildApoTx(prevout: differentPrevout), 0,
          sighashAnyprevoutAnyscript, amount);
      expect(toHex(a), toHex(b)); // prevout change must NOT move the digest
    });

    test('0x42 (ignores script) and 0x41 (commits script) differ', () {
      final d42 = apoSighash(Uint8List(0), buildApoTx(), 0, sighashAnyprevoutAnyscript, amount);
      final d41 = apoSighash(
          fromHex(v['scriptcode_hex'] as String), buildApoTx(), 0, sighashAnyprevout, amount);
      expect(toHex(d42), isNot(toHex(d41)));
    });

    test('APO 0x42 COMMITS to outputs (amount change moves the digest)', () {
      final a = apoSighash(Uint8List(0), buildApoTx(), 0, sighashAnyprevoutAnyscript, amount);
      final b = apoSighash(Uint8List(0), buildApoTx(vout0Value: 9999999999), 0,
          sighashAnyprevoutAnyscript, amount);
      expect(toHex(a), isNot(toHex(b)));
    });
  });
}
