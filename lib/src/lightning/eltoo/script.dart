// Copyright (c) 2026 Soqucoin Labs Inc.
// Distributed under the MIT software license.
//
// script.dart — Opt3 script primitives (port of channel.ts:52-142).
//
// Opcodes, CScript data pushes, CScriptNum encoding, and the Soqucoin witness-v6 wrappers
// (p2wshV6, the trailing Dilithium pubkey, and the v6 witness-stack assembler). Byte-exact
// with the consensus interpreter; pinned via the keyhash/eltoo vectors that consume them.

import 'dart:typed_data';

import 'serialization.dart';

/// Script opcodes (channel.ts:52-58).
class Op {
  static const int op0 = 0x00;
  static const int opFalse = 0x00;
  static const int op1 = 0x51;
  static const int opTrue = 0x51;
  static const int opOne = 0x51;
  static const int witnessV6 = 0x56;
  static const int opIf = 0x63;
  static const int opElse = 0x67;
  static const int opEndif = 0x68;
  static const int opDrop = 0x75;
  static const int equalverify = 0x88;
  static const int opSha256 = 0xa8;
  static const int checksig = 0xac;
  static const int checksigverify = 0xad;
  static const int cltv = 0xb1;
  static const int csv = 0xb2;
  static const int nop4Ctv = 0xb3;
  static const int nop5Csfs = 0xb4;
  // 0xb5 (OP_NOP6) RESERVED for OP_TXHASH / BIP 346 — do not repurpose.
  static const int checkdilithiumkeyhash = 0xb6; // OP_NOP7 (SOQ-COV-013)
}

/// CScript data push: length-opcode selection (channel.ts:69-76).
Uint8List pushData(Uint8List data) {
  final n = data.length;
  if (n < 0x4c) return concatBytes([u8(n), data]);
  if (n <= 0xff) return concatBytes([u8(0x4c), u8(n), data]);
  if (n <= 0xffff) return concatBytes([u8(0x4d), le16(n), data]);
  return concatBytes([u8(0x4e), le32(n), data]);
}

/// CScriptNum minimal encoding, then pushed as data (channel.ts:78-89).
Uint8List scriptNum(int value) {
  if (value == 0) return u8(0x00); // CScriptNum(0) → empty push → OP_0
  final neg = value < 0;
  var abs = neg ? -value : value;
  final bytes = <int>[];
  while (abs > 0) {
    bytes.add(abs & 0xff);
    abs >>= 8;
  }
  if (bytes.last & 0x80 != 0) {
    bytes.add(neg ? 0x80 : 0x00);
  } else if (neg) {
    bytes[bytes.length - 1] |= 0x80;
  }
  return pushData(Uint8List.fromList(bytes));
}

/// BIP141 v0 P2WSH scriptPubKey: OP_0 ‖ push(sha256(script)). Kept for interop; Soqucoin
/// channels use v6 (see [p2wshV6]).
Uint8List p2wsh(Uint8List witnessScript) =>
    concatBytes([u8(Op.opFalse), pushData(sha256Once(witnessScript))]);

/// Soqucoin P2WSH-Dilithium scriptPubKey (witness v6): OP_6 ‖ push(sha256(script)).
Uint8List p2wshV6(Uint8List witnessScript) =>
    concatBytes([u8(Op.witnessV6), pushData(sha256Once(witnessScript))]);

/// The trailing v6 witness item: the ML-DSA-44 pubkey 0x00-prefixed (1313 bytes). Consumed by
/// the HasDilithiumSignatures standardness check; not on the eval stack.
Uint8List dilithiumWitnessPubKey(Uint8List mldsaPubKey) =>
    concatBytes([u8(0x00), mldsaPubKey]);

/// Assemble a v6 witness stack: [...satisfaction, witnessScript, trailingPubKey].
/// [trailingPubKey] must already be 0x00-prefixed (use [dilithiumWitnessPubKey]).
List<Uint8List> p2wshV6Witness(
  List<Uint8List> satisfaction,
  Uint8List witnessScript,
  Uint8List trailingPubKey,
) {
  if (trailingPubKey.isEmpty || trailingPubKey[0] != 0x00) {
    throw ArgumentError('trailing witness pubkey must be 0x00-prefixed (HasDilithiumSignatures)');
  }
  return [...satisfaction, witnessScript, trailingPubKey];
}
