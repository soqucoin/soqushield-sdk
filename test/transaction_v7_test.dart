// Copyright (c) 2026 Soqucoin Labs Inc.
// Distributed under the MIT software license.
//
// transaction_v7_test.dart — v7 USDSOQ holding classification (CTxOut migration Phase 3).
// USDSOQ is recognised by the witness VERSION (OP_7), not just the nAssetType byte / the
// byte-derived RPC `assetType` field — so a v7 holding stays USDSOQ post-Phase-4.

import 'package:soqushield_sdk/src/models/transaction.dart';
import 'package:test/test.dart';

TxOutput out(String spk, int asset) =>
    TxOutput(value: 1, valueSat: 1, n: 0, scriptPubKey: spk, assetType: asset);

void main() {
  final v7 = '5720${'aa' * 32}'; // OP_7 <32>
  final v1 = '5120${'cd' * 32}'; // OP_1 <32>

  group('v7 USDSOQ holding classification', () {
    test('v7 holding is USDSOQ by version even with the byte clear', () {
      expect(out(v7, 0).isUsdsoq, isTrue);
      expect(out(v7, 0).isV7UsdsoqHolding, isTrue);
    });

    test('v1 output with byte clear is native SOQ', () {
      expect(out(v1, 0).isUsdsoq, isFalse);
      expect(out(v1, 0).isV7UsdsoqHolding, isFalse);
    });

    test('legacy v1 + byte set is still USDSOQ (transition dual-recognition)', () {
      expect(out(v1, 1).isUsdsoq, isTrue);
    });

    test('static script classifier matches', () {
      expect(TxOutput.isV7UsdsoqHoldingScript(v7), isTrue);
      expect(TxOutput.isV7UsdsoqHoldingScript(v1), isFalse);
      expect(TxOutput.isV7UsdsoqHoldingScript('5720aa'), isFalse); // wrong length
      expect(TxOutput.isV7UsdsoqHoldingScript('1720${'aa' * 32}'), isFalse); // wrong version
    });
  });
}
