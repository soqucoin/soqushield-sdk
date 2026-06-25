// Copyright (c) 2026 Soqucoin Labs Inc.
// Distributed under the MIT software license.
//
// keyhash.dart — Opt3 P4: OP_CHECKDILITHIUMKEYHASH (SOQ-COV-013) key-committed 2-of-2 funding.
//
// Byte-for-byte port of channel.ts:349-504. This is the REAL key-binding primitive for eLTOO
// funding: the funding output commits SHA256(pubkey) for BOTH parties as script literals, so
// each party must co-sign with their SPECIFIC Dilithium key (CSFS authorizes a witness-supplied
// key and does not bind — a thief could substitute their own). Node-pinned against
// dilithium_keyhash_committed_tests.cpp (committed_sdk_crossvector).
//
// Pinned in test/eltoo/keyhash_test.dart: the keyhash (single SHA256), the 69-byte witnessScript
// layout + offsets, the v6 funding scriptPubKey, the 2-of-2 witness ordering (B checked first),
// order-robust combine, substitution + mixed-hashType rejection. (Real ML-DSA verification of
// the sigs is the separately-gated @noble↔pqcrystals interop workstream — see vector_mldsa.)

import 'dart:typed_data';

import 'script.dart';
import 'serialization.dart';
import 'sighash.dart';

/// SHA256(rawPubKey) — the 32-byte committed keyhash. SINGLE SHA256 (matches the handler's
/// CSHA256), NOT sha256d. [rawPubKey] is the 1312-byte ML-DSA-44 key with NO 0x00 prefix.
Uint8List dilithiumKeyHash(Uint8List rawPubKey) {
  if (rawPubKey.length != 1312) {
    throw ArgumentError('expected 1312-byte ML-DSA pubkey, got ${rawPubKey.length}');
  }
  return sha256Once(rawPubKey);
}

/// Single-key committed script: `<kh(pub)> OP_CHECKDILITHIUMKEYHASH OP_1`.
Uint8List dilithiumKeyhashScript(Uint8List rawPubKey) => concatBytes([
      pushData(dilithiumKeyHash(rawPubKey)),
      u8(Op.checkdilithiumkeyhash),
      u8(Op.opOne),
    ]);

/// Key-committed 2-of-2 script: `<kh(pubB)> OP_CDKH <kh(pubA)> OP_CDKH OP_1`. pubB is committed
/// FIRST because the first opcode checks the TOP eval item, and the witness puts pubB on top.
Uint8List dilithiumKeyhash2of2Script(Uint8List pubA, Uint8List pubB) => concatBytes([
      pushData(dilithiumKeyHash(pubB)), u8(Op.checkdilithiumkeyhash),
      pushData(dilithiumKeyHash(pubA)), u8(Op.checkdilithiumkeyhash),
      u8(Op.opOne),
    ]);

/// v6 witness for a single-key committed spend. Eval items: [sig, pub] (pub on top).
List<Uint8List> dilithiumKeyhashWitness(
  Uint8List sig,
  Uint8List rawPubKey,
  Uint8List trailingPubKey, {
  Uint8List? witnessScript,
}) =>
    p2wshV6Witness(
        [sig, rawPubKey], witnessScript ?? dilithiumKeyhashScript(rawPubKey), trailingPubKey);

/// v6 witness for the key-committed 2-of-2. Eval order: the first OP_CDKH consumes the TOP
/// triple, so satisfaction = [sigA, pubA, sigB, pubB] (B checked first, A second).
List<Uint8List> dilithiumKeyhash2of2Witness(
  Uint8List sigA,
  Uint8List pubA,
  Uint8List sigB,
  Uint8List pubB,
  Uint8List trailingPubKey, {
  Uint8List? witnessScript,
}) =>
    p2wshV6Witness([sigA, pubA, sigB, pubB],
        witnessScript ?? dilithiumKeyhash2of2Script(pubA, pubB), trailingPubKey);

/// Sign an OP_CHECKDILITHIUMKEYHASH input. The opcode delegates to CheckSig, which signs the
/// sighash DIRECTLY (reads the trailing hashType byte). scriptCode = the FULL witnessScript.
/// hashType: 0x01 (close) or 0x41/0x42 (eLTOO update rebinding).
Uint8List signForKeyhash(
  Uint8List witnessScript,
  Tx tx,
  int nIn,
  int hashType,
  BigInt amountSat,
  Uint8List secretKey,
  MlDsaSign sign,
) {
  if (hashType == sighashAll) {
    return signAllWitness(witnessScript, tx, nIn, amountSat, secretKey, sign);
  }
  if (hashType == sighashAnyprevout || hashType == sighashAnyprevoutAnyscript) {
    return signApoWitness(witnessScript, tx, nIn, hashType, amountSat, secretKey, sign);
  }
  throw ArgumentError('signForKeyhash: unsupported hashType 0x${hashType.toRadixString(16)}');
}

// ── funding helper ──

/// A key-committed eLTOO funding output: the 2-of-2 both parties must co-sign with their
/// specific Dilithium keys. [pubA]/[pubB] are raw 1312-byte ML-DSA-44 keys.
class KeyhashFunding {
  final Uint8List witnessScript; // <kh(pubB)> OP_CDKH <kh(pubA)> OP_CDKH OP_1
  final Uint8List scriptPubKey; // p2wshV6(witnessScript)
  const KeyhashFunding(this.witnessScript, this.scriptPubKey);
}

KeyhashFunding keyhashFunding2of2(Uint8List pubA, Uint8List pubB) {
  final ws = dilithiumKeyhash2of2Script(pubA, pubB);
  return KeyhashFunding(ws, p2wshV6(ws));
}

bool _bytesEqual(Uint8List a, Uint8List b) {
  if (a.length != b.length) return false;
  for (var i = 0; i < a.length; i++) {
    if (a[i] != b[i]) return false;
  }
  return true;
}

/// Validate + extract the two committed keyhashes from a keyhash-2-of-2 witnessScript.
/// Shape: 0x20 <khFirst(32)> 0xb6 0x20 <khSecond(32)> 0xb6 0x51 (69 bytes). khFirst is checked
/// FIRST by the script (so its key must end up on TOP of the eval stack).
({Uint8List khFirst, Uint8List khSecond}) _parseKeyhash2of2Script(Uint8List ws) {
  if (ws.length != 69 ||
      ws[0] != 0x20 ||
      ws[33] != Op.checkdilithiumkeyhash ||
      ws[34] != 0x20 ||
      ws[67] != Op.checkdilithiumkeyhash ||
      ws[68] != Op.opOne) {
    throw ArgumentError('not a keyhash-2-of-2 witnessScript');
  }
  return (khFirst: ws.sublist(1, 33), khSecond: ws.sublist(35, 67));
}

/// One party's contribution to a keyhash-2-of-2 spend: their pubkey + their 2421-byte signature.
class KeyhashPartial {
  final Uint8List pubKey;
  final Uint8List sig; // 2420-byte ML-DSA sig ‖ hashType
  const KeyhashPartial(this.pubKey, this.sig);
}

/// Produce ONE party's partial signature. The party needs only their own secret key.
/// [hashType] = 0x42 (eLTOO update) or 0x01 (close); both signers must use the same one.
KeyhashPartial partialSignKeyhash2of2(
  Uint8List witnessScript,
  Tx tx,
  int nIn,
  int hashType,
  BigInt amountSat,
  Uint8List secretKey,
  Uint8List pubKey,
  MlDsaSign sign,
) {
  if (pubKey.length != 1312) {
    throw ArgumentError('expected 1312-byte pubkey, got ${pubKey.length}');
  }
  return KeyhashPartial(
      pubKey, signForKeyhash(witnessScript, tx, nIn, hashType, amountSat, secretKey, sign));
}

/// Assemble the v6 witness from two independently-produced partials. ORDER-ROBUST: each partial
/// is matched to its committed keyhash slot, so [pa,pb] and [pb,pa] yield the identical witness.
/// Throws on a partial matching no slot (wrong key), both mapping to one slot, or mixed hashTypes.
List<Uint8List> combineKeyhash2of2Witness(
  Uint8List witnessScript,
  List<KeyhashPartial> partials, {
  Uint8List? trailingPubKey,
}) {
  if (partials.length != 2) throw ArgumentError('exactly two partials required');
  final parsed = _parseKeyhash2of2Script(witnessScript);

  KeyhashPartial match(Uint8List target) {
    final found =
        partials.where((p) => _bytesEqual(dilithiumKeyHash(p.pubKey), target)).toList();
    if (found.length != 1) {
      throw ArgumentError(
          'combineKeyhash2of2Witness: exactly one partial must match each committed keyhash');
    }
    return found.first;
  }

  final pFirst = match(parsed.khFirst); // committed first → checked first → TOP of eval stack
  final pSecond = match(parsed.khSecond);
  if (identical(pFirst, pSecond)) {
    throw ArgumentError('both partials map to the same committed key');
  }
  for (final p in [pFirst, pSecond]) {
    if (p.sig.length != 2421) {
      throw ArgumentError('partial sig must be 2421 bytes (2420 + hashType), got ${p.sig.length}');
    }
  }
  if (pFirst.sig[2420] != pSecond.sig[2420]) {
    throw ArgumentError('partials signed different hashTypes');
  }
  // Trailing pubkey derived from the SCRIPT-matched ordering (pFirst), NOT caller arg order,
  // so the assembled witness is identical for [pa,pb] and [pb,pa].
  final trailing = trailingPubKey ?? dilithiumWitnessPubKey(pFirst.pubKey);
  // eval items bottom→top: [sigSecond, pubSecond, sigFirst, pubFirst] (First on top)
  return p2wshV6Witness(
      [pSecond.sig, pSecond.pubKey, pFirst.sig, pFirst.pubKey], witnessScript, trailing);
}

/// Single-operator convenience: sign both sides locally, then combine. Same code path as two
/// parties signing independently and combining.
List<Uint8List> signKeyhashFunding2of2(
  KeyhashFunding funding,
  Tx tx,
  int nIn,
  BigInt amountSat,
  int hashType,
  Uint8List skA,
  Uint8List pubA,
  Uint8List skB,
  Uint8List pubB,
  MlDsaSign sign,
) {
  final pa =
      partialSignKeyhash2of2(funding.witnessScript, tx, nIn, hashType, amountSat, skA, pubA, sign);
  final pb =
      partialSignKeyhash2of2(funding.witnessScript, tx, nIn, hashType, amountSat, skB, pubB, sign);
  return combineKeyhash2of2Witness(funding.witnessScript, [pa, pb],
      trailingPubKey: dilithiumWitnessPubKey(pubA));
}
