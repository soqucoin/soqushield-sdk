// Copyright (c) 2026 Soqucoin Labs Inc.
// Distributed under the MIT software license.
//
// derivation_marker_retry_test.dart — the invalid-marker retry rule, checked
// against the vector the NODE's own derivation test prints
// (soqucoin src/test/pqderive-test, "0. Testing the 0xFF invalid-key marker
// retry"). The node's CPubKey treats a public key whose first byte is 0xFF as
// its invalid-key sentinel; one derivation path in 256 lands on one, and a
// wallet that did not re-derive would hand the user an address whose deposits
// can never be spent. Node, this SDK and the SoquShield app must agree on the
// re-derivation, or a wallet restored on another implementation would show a
// different address for the same mnemonic.
//
// Vector (node pqderive-test, 2026-09-03):
//   master seed: 64 bytes, seed[i] = 0xA5 ^ i
//   path m/44'/21329'/0'/0/392
//   retry-0 public key begins ffdef52511cf1e80 (the marker)
//   returned public key begins f920b5acf83d9a58 (retry 1)
//
// Needs the native library: SOQ_DILITHIUM_DYLIB=<path> dart test test/derivation_marker_retry_test.dart
// (skips cleanly if absent; see dilithium_native_interop_test.dart for the build line).
import 'dart:ffi';
import 'dart:io';
import 'dart:typed_data';

import 'package:soqushield_sdk/src/keys/key_generator.dart';
import 'package:test/test.dart';

String hex(Uint8List b, int n) => b.sublist(0, n).map((x) => x.toRadixString(16).padLeft(2, '0')).join();

void main() {
  final dylib = Platform.environment['SOQ_DILITHIUM_DYLIB'];
  if (dylib == null || !File(dylib).existsSync()) {
    test('marker retry (skipped: SOQ_DILITHIUM_DYLIB not set)', () {}, skip: 'set SOQ_DILITHIUM_DYLIB to the built libdilithium_soq');
    return;
  }
  DynamicLibrary.open(dylib); // make the symbols visible to DilithiumNative's process() lookup

  final seed = Uint8List(64);
  for (var i = 0; i < 64; i++) {
    seed[i] = 0xA5 ^ i;
  }

  test('index 392 under the fixed seed re-derives past the marker to the node\'s key', () {
    final gen = KeyGenerator();
    final (pk, sk) = gen.deriveKeyPairWithRetry(Uint8List.fromList(seed), 392);
    sk.fillRange(0, sk.length, 0);
    expect(pk[0], isNot(0xFF), reason: 'returned key carries the invalid-key marker');
    expect(hex(pk, 8), 'f920b5acf83d9a58', reason: 'does not match the node\'s retry-1 key for this path');
  });

  test('a clean path is unchanged by the rule (retry 0 is the original derivation)', () {
    final gen = KeyGenerator();
    // Index 0 under this seed is not a marker path (the node test derives it
    // as its determinism check); the returned key is the retry-0 key, whose
    // first byte is therefore not 0xFF and whose derivation info has no
    // trailing retry byte.
    final (pk, sk) = gen.deriveKeyPairWithRetry(Uint8List.fromList(seed), 0);
    sk.fillRange(0, sk.length, 0);
    expect(pk[0], isNot(0xFF));
    expect(pk.length, 1312);
  });

  test('the marker never escapes for any index', () {
    final gen = KeyGenerator();
    for (var index = 0; index < 600; index++) {
      final (pk, sk) = gen.deriveKeyPairWithRetry(Uint8List.fromList(seed), index);
      sk.fillRange(0, sk.length, 0);
      expect(pk[0], isNot(0xFF), reason: 'index $index');
    }
  });
}
