// Copyright (c) 2026 Soqucoin Labs Inc.
// Distributed under the MIT software license.
//
// b1_script_test.dart — pins the B1 eLTOO + HTLC witnessScript bytes to the node.
//
// Ground truth: soqucoin-build src/test/lightning_script_tests.cpp / b1_script_vectors
// (DL-V6-CONTROLFLOW-RESTORE §4). The keyhash = SHA256(pubkey) step is separately pinned (P4),
// so these vectors commit raw 32-byte keyhashes directly and exercise the script FORM byte-exact.

import 'dart:typed_data';

import 'package:soqushield_sdk/eltoo.dart';
import 'package:test/test.dart';

Uint8List fill(int b) => Uint8List(32)..fillRange(0, 32, b);

void main() {
  group('B1 script vectors (node-pinned)', () {
    test('eLTOO update script byte-matches the node vector', () {
      // stateNum=600000, csv=288; update kh A=0x11 B=0x22, settle kh A=0x33 B=0x44.
      final ws = eltooUpdateScriptV6FromKeyhashes(
        600000,
        fill(0x11),
        fill(0x22),
        khAsettle: fill(0x33),
        khBsettle: fill(0x44),
        settlementCsv: 288,
      );
      expect(
        toHex(ws),
        '6303c12709b175202222222222222222222222222222222222222222222222222222222222222222b6201111111111111111111111111111111111111111111111111111111111111111b65167022001b275204444444444444444444444444444444444444444444444444444444444444444b6203333333333333333333333333333333333333333333333333333333333333333b65168',
      );
    });

    test('HTLC script byte-matches the node vector', () {
      // cltv=500; H=0xab, payee kh=0x55, payer kh=0x66.
      final ws = htlcScriptV6FromKeyhashes(fill(0xab), fill(0x55), fill(0x66), 500);
      expect(
        toHex(ws),
        '63a820abababababababababababababababababababababababababababababababab88205555555555555555555555555555555555555555555555555555555555555555b6516702f401b175206666666666666666666666666666666666666666666666666666666666666666b65168',
      );
    });

    test('B1 branch witnesses match the node-accepted satisfaction layout', () {
      final sigA = Uint8List(2421)..fillRange(0, 2421, 0x01);
      final pubA = Uint8List(1312)..fillRange(0, 1312, 0xa1);
      final sigB = Uint8List(2421)..fillRange(0, 2421, 0x02);
      final pubB = Uint8List(1312)..fillRange(0, 1312, 0xb2);
      final script = Uint8List.fromList([0x63, 0x68]); // any witnessScript stand-in
      final trailing = dilithiumWitnessPubKey(pubA); // 0x00 ‖ pubA

      // UPDATE branch: [sigA, pubA, sigB, pubB, 0x01, script, trailing]
      final up = eltooUpdateBranchWitness(script, sigA, pubA, sigB, pubB, trailing);
      expect(up.length, 7);
      expect(up[0], sigA);
      expect(up[1], pubA);
      expect(up[2], sigB);
      expect(up[3], pubB);
      expect(up[4], Uint8List.fromList([0x01])); // truthy IF selector
      expect(up[5], script);
      expect(up[6][0], 0x00); // trailing v6 pubkey is 0x00-prefixed

      // SETTLEMENT branch: same but FALSE (empty) selector
      final set = eltooSettlementBranchWitness(script, sigA, pubA, sigB, pubB, trailing);
      expect(set.length, 7);
      expect(set[4].isEmpty, isTrue); // empty → ELSE branch

      // HTLC success: [sigPayee, pubPayee, preimage, 0x01, script, trailing]
      final preimage = Uint8List(32)..fillRange(0, 32, 0x07);
      final ok = htlcSuccessWitness(script, sigA, pubA, preimage, trailing);
      expect(ok.length, 6);
      expect(ok[2], preimage);
      expect(ok[3], Uint8List.fromList([0x01]));

      // HTLC timeout: [sigPayer, pubPayer, empty, script, trailing]
      final to = htlcTimeoutWitness(script, sigA, pubA, trailing);
      expect(to.length, 5);
      expect(to[2].isEmpty, isTrue);
    });

    test('pubkey wrappers agree with the from-keyhash form', () {
      final pubA = Uint8List(1312)..fillRange(0, 1312, 0xa1);
      final pubB = Uint8List(1312)..fillRange(0, 1312, 0xb2);
      final viaPub = eltooUpdateScriptV6(7, pubA, pubB, settlementCsv: 144);
      final viaKh = eltooUpdateScriptV6FromKeyhashes(
        7, dilithiumKeyHash(pubA), dilithiumKeyHash(pubB), settlementCsv: 144);
      expect(toHex(viaPub), toHex(viaKh));

      final h = Uint8List(32)..fillRange(0, 32, 0x07);
      final htlcViaPub = htlcScriptV6(h, pubA, pubB, 1000);
      final htlcViaKh = htlcScriptV6FromKeyhashes(h, dilithiumKeyHash(pubA), dilithiumKeyHash(pubB), 1000);
      expect(toHex(htlcViaPub), toHex(htlcViaKh));
    });
  });
}
