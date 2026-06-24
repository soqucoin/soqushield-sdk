// Copyright (c) 2026 Soqucoin Labs Inc.
// Distributed under the MIT software license.
//
// sighash.dart — Opt3 P2: BIP118 APO + BIP143 sighashing.
//
// Byte-for-byte port of soq-lightning-sdk/src/channel.ts (apoSighash, sighashAll) — the eLTOO
// core. The APO-0x42 digest is what the update TX is signed over; getting the preimage
// field-exact is the difference between a channel that disputes correctly and one that doesn't.
//
// Pinned to node vectors in test/eltoo/sighash_test.dart:
//   • APO 0x42 / 0x41 digests  ← apo_ctv_vectors.json (b1_dump_vectors, Phase-4 byte-less)
//   • BIP143 SIGHASH_ALL digest ← onchain_vectors.json (sighashHex)

import 'dart:typed_data';

import 'serialization.dart';

/// BIP118 hash-type bytes.
const int sighashAnyprevout = 0x41; // ANYPREVOUT — commits scriptCode
const int sighashAnyprevoutAnyscript = 0x42; // ANYPREVOUTANYSCRIPT — ignores scriptCode
const int sighashAll = 0x01; // standard BIP143

/// COutPoint::SetNull → 32 zero bytes ‖ n = 0xFFFFFFFF (channel.ts:220).
final Uint8List _emptyOutpoint =
    concatBytes([Uint8List(32), Uint8List.fromList([0xff, 0xff, 0xff, 0xff])]);

/// Signs a 32-byte message with ML-DSA-44 and returns the 2420-byte signature.
/// (Inject `DilithiumNative.instance.sign` here; kept abstract so this layer stays pure.)
typedef MlDsaSign = Uint8List Function(Uint8List message, Uint8List secretKey);

/// BIP118 APO sighash (channel.ts:241-267). For 0x42 the scriptCode is serialized EMPTY (the
/// signature rebinds across states/scripts); for 0x41 the real [scriptCode] is committed.
/// hashPrevouts / hashSequence / the outpoint / nSequence are all zeroed (rebindable). Returns
/// the 32-byte SHA256d digest ML-DSA signs.
Uint8List apoSighash(
  Uint8List scriptCode,
  Tx tx,
  int nIn,
  int hashType,
  BigInt amountSat,
) {
  final base = hashType & 0x7f;
  if (base != sighashAnyprevout && base != sighashAnyprevoutAnyscript) {
    throw ArgumentError('apoSighash: hashType must be 0x41 or 0x42');
  }
  if (hashType & 0x80 != 0) {
    throw ArgumentError('ANYONECANPAY + APO is invalid (SOQ-COV-003)');
  }

  final zero32 = Uint8List(32);
  final hashOutputs = sha256d(concatBytes(tx.vout.map(serTxOut).toList()));
  // ANYPREVOUT commits scriptCode; ANYPREVOUTANYSCRIPT serializes an empty script.
  final scriptField = base == sighashAnyprevout
      ? concatBytes([compactSize(scriptCode.length), scriptCode])
      : u8(0x00); // empty script → compactSize(0)

  final preimage = concatBytes([
    le32(tx.version),
    zero32, // hashPrevouts = 0
    zero32, // hashSequence = 0
    _emptyOutpoint, // outpoint zeroed
    scriptField,
    le64(amountSat),
    le32(0), // nSequence = 0
    hashOutputs,
    le32(tx.locktime),
    le32(hashType), // nHashType as a 4-byte int
  ]);
  return sha256d(preimage);
}

/// Witness signature element for an APO spend: ML-DSA-44 sig (2420) ‖ hashType byte (channel.ts:271).
Uint8List signApoWitness(
  Uint8List scriptCode,
  Tx tx,
  int nIn,
  int hashType,
  BigInt amountSat,
  Uint8List secretKey,
  MlDsaSign sign,
) {
  final digest = apoSighash(scriptCode, tx, nIn, hashType, amountSat);
  final sig = sign(digest, secretKey);
  if (sig.length != 2420) {
    throw StateError('expected 2420-byte ML-DSA sig, got ${sig.length}');
  }
  return concatBytes([sig, u8(hashType)]);
}

/// BIP143 witness-v0 sighash for SIGHASH_ALL (channel.ts:288-306). Unlike the eLTOO update this
/// commits to the real prevout/sequence (a fixed-output spend, no rebinding) — used by HTLC
/// SUCCESS/TIMEOUT claims and the simple-send path. [scriptCode] is the input's scriptPubKey.
Uint8List bip143SighashAll(Uint8List scriptCode, Tx tx, int nIn, BigInt amountSat) {
  final hashPrevouts = sha256d(concatBytes(tx.vin.map(serOutpoint).toList()));
  final hashSequence = sha256d(concatBytes(tx.vin.map((i) => le32(i.sequence)).toList()));
  final hashOutputs = sha256d(concatBytes(tx.vout.map(serTxOut).toList()));
  final preimage = concatBytes([
    le32(tx.version),
    hashPrevouts,
    hashSequence,
    serOutpoint(tx.vin[nIn]),
    compactSize(scriptCode.length), scriptCode,
    le64(amountSat),
    le32(tx.vin[nIn].sequence),
    hashOutputs,
    le32(tx.locktime),
    le32(sighashAll),
  ]);
  return sha256d(preimage);
}

/// Witness signature element for a SIGHASH_ALL claim: ML-DSA-44 sig (2420) ‖ 0x01.
Uint8List signAllWitness(
  Uint8List scriptCode,
  Tx tx,
  int nIn,
  BigInt amountSat,
  Uint8List secretKey,
  MlDsaSign sign,
) {
  final sig = sign(bip143SighashAll(scriptCode, tx, nIn, amountSat), secretKey);
  if (sig.length != 2420) {
    throw StateError('expected 2420-byte ML-DSA sig, got ${sig.length}');
  }
  return concatBytes([sig, u8(sighashAll)]);
}
