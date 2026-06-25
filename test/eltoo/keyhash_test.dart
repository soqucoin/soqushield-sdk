// Copyright (c) 2026 Soqucoin Labs Inc.
// Distributed under the MIT software license.
//
// keyhash_test.dart — Opt3 P4: byte-exact construction pins for the key-committed 2-of-2
// funding (OP_CHECKDILITHIUMKEYHASH). The keyhash is SHA256(pubkey), so these layout/ordering
// properties are key-independent and pinned with deterministic pubkey patterns + a deterministic
// MOCK ML-DSA signer (structure, not cryptographic validity).
//
// NOT covered here (separate workstream): the node `committed_sdk_crossvector` byte-match of
// kh_A/kh_B/witnessScript/scriptPubKey/apo42_sighash for keys derived from seeds 0x11×32 / 0x22×32
// — that needs the @noble↔pqcrystals ML-DSA keygen interop (vector_mldsa) and the native
// DilithiumNative FFI (not loadable in a pure `dart test`). Real sig verification rides on that.

import 'dart:typed_data';

import 'package:soqushield_sdk/src/lightning/eltoo/serialization.dart';
import 'package:soqushield_sdk/src/lightning/eltoo/script.dart';
import 'package:soqushield_sdk/src/lightning/eltoo/sighash.dart';
import 'package:soqushield_sdk/src/lightning/eltoo/keyhash.dart';
import 'package:test/test.dart';

void main() {
  // Deterministic 1312-byte pubkey patterns (distinct per party).
  final pubA = Uint8List.fromList(List.generate(1312, (i) => i % 256));
  final pubB = Uint8List.fromList(List.generate(1312, (i) => (i + 7) % 256));
  final pubM = Uint8List.fromList(List.generate(1312, (i) => (i + 13) % 256)); // Mallory
  final skA = Uint8List.fromList(List.filled(32, 0x11));
  final skB = Uint8List.fromList(List.filled(32, 0x22));
  final skM = Uint8List.fromList(List.filled(32, 0x33));

  // Deterministic mock ML-DSA signer: 2420 bytes keyed by (secretKey, message) so a given
  // (sk, msg) always yields identical bytes (required for order-robustness assertions).
  Uint8List mockSign(Uint8List message, Uint8List secretKey) {
    final out = Uint8List(2420);
    for (var i = 0; i < 2420; i++) {
      out[i] = (secretKey[0] + message[i % message.length] + i) & 0xff;
    }
    return out;
  }

  final amount = BigInt.from(100000000);
  Tx updateTx() => Tx(
        version: 2,
        locktime: 101,
        vin: [
          TxIn(
            prevout: OutPoint(Uint8List.fromList(List.filled(32, 0xfd)), 0),
            sequence: 0xfffffffe,
            scriptPubKey: Uint8List(0),
          ),
        ],
        vout: [TxOut(amount, u8(Op.opTrue))],
      );

  group('Opt3 P4 — keyhash + funding construction', () {
    test('dilithiumKeyHash = single SHA256 of the raw 1312-byte key; rejects 1313', () {
      final kh = dilithiumKeyHash(pubA);
      expect(kh.length, 32);
      expect(toHex(kh), toHex(sha256Once(pubA))); // single SHA256, not sha256d
      expect(() => dilithiumKeyHash(dilithiumWitnessPubKey(pubA)), throwsArgumentError); // 1313
    });

    test('funding scriptPubKey is v6 (OP_6 + push32), 34 bytes', () {
      final f = keyhashFunding2of2(pubA, pubB);
      expect(f.scriptPubKey.length, 34);
      expect(f.scriptPubKey[0], Op.witnessV6); // 0x56
      expect(f.scriptPubKey[1], 0x20);
      expect(toHex(f.scriptPubKey), toHex(p2wshV6(f.witnessScript)));
    });

    test('witnessScript commits kh(pubB) FIRST then kh(pubA), ends OP_1 (69 bytes)', () {
      final ws = dilithiumKeyhash2of2Script(pubA, pubB);
      final expected = concatBytes([
        u8(0x20), dilithiumKeyHash(pubB), u8(Op.checkdilithiumkeyhash),
        u8(0x20), dilithiumKeyHash(pubA), u8(Op.checkdilithiumkeyhash),
        u8(Op.opOne),
      ]);
      expect(toHex(ws), toHex(expected));
      expect(ws.length, 1 + 32 + 1 + 1 + 32 + 1 + 1); // 69
    });
  });

  group('Opt3 P4 — 2-of-2 witness layout', () {
    test('signKeyhashFunding2of2 (0x42): [sigA,pubA,sigB,pubB,ws,trailing] with correct shapes', () {
      final f = keyhashFunding2of2(pubA, pubB);
      final w = signKeyhashFunding2of2(
          f, updateTx(), 0, amount, sighashAnyprevoutAnyscript, skA, pubA, skB, pubB, mockSign);
      expect(w.length, 6);
      expect(w[0].length, 2421); // sigA ‖ hashType
      expect(w[0][2420], 0x42);
      expect(w[2][2420], 0x42); // sigB hashType
      expect(toHex(w[1]), toHex(pubA));
      expect(toHex(w[3]), toHex(pubB));
      expect(toHex(w[4]), toHex(f.witnessScript));
      expect(w[5].length, 1313);
      expect(w[5][0], 0x00);
    });

    test('cooperative close (0x01) sets hashType byte 0x01', () {
      final f = keyhashFunding2of2(pubA, pubB);
      final w = signKeyhashFunding2of2(
          f, updateTx(), 0, amount, sighashAll, skA, pubA, skB, pubB, mockSign);
      expect(w[0][2420], 0x01);
    });
  });

  group('Opt3 P4 — order-robust combine + binding rejections', () {
    test('combine is order-invariant: [pa,pb] == [pb,pa] byte-for-byte', () {
      final f = keyhashFunding2of2(pubA, pubB);
      final tx = updateTx();
      final pa = partialSignKeyhash2of2(
          f.witnessScript, tx, 0, sighashAnyprevoutAnyscript, amount, skA, pubA, mockSign);
      final pb = partialSignKeyhash2of2(
          f.witnessScript, tx, 0, sighashAnyprevoutAnyscript, amount, skB, pubB, mockSign);
      final w1 = combineKeyhash2of2Witness(f.witnessScript, [pa, pb]);
      final w2 = combineKeyhash2of2Witness(f.witnessScript, [pb, pa]);
      expect(w1.length, 6);
      for (var i = 0; i < 6; i++) {
        expect(toHex(w1[i]), toHex(w2[i]), reason: 'witness item $i must be order-invariant');
      }
      // eval order [sigA, pubA, sigB, pubB, ...] — B committed first → on top (last pair).
      expect(toHex(w1[1]), toHex(pubA));
      expect(toHex(w1[3]), toHex(pubB));
    });

    test('combine REJECTS a partial matching no committed keyhash (wrong party)', () {
      final f = keyhashFunding2of2(pubA, pubB);
      final tx = updateTx();
      final pa = partialSignKeyhash2of2(
          f.witnessScript, tx, 0, sighashAnyprevoutAnyscript, amount, skA, pubA, mockSign);
      final pm = partialSignKeyhash2of2(
          f.witnessScript, tx, 0, sighashAnyprevoutAnyscript, amount, skM, pubM, mockSign);
      expect(() => combineKeyhash2of2Witness(f.witnessScript, [pa, pm]), throwsArgumentError);
    });

    test('combine REJECTS partials that signed different hashTypes', () {
      final f = keyhashFunding2of2(pubA, pubB);
      final tx = updateTx();
      final pa = partialSignKeyhash2of2(
          f.witnessScript, tx, 0, sighashAnyprevoutAnyscript, amount, skA, pubA, mockSign);
      final pbAll = partialSignKeyhash2of2(
          f.witnessScript, tx, 0, sighashAll, amount, skB, pubB, mockSign);
      expect(() => combineKeyhash2of2Witness(f.witnessScript, [pa, pbAll]), throwsArgumentError);
    });

    test('SUBSTITUTION: Mallory keyhash differs from the committed (Alice) keyhash', () {
      expect(toHex(dilithiumKeyHash(pubM)), isNot(toHex(dilithiumKeyHash(pubA))));
    });
  });
}
