// Copyright (c) 2026 Soqucoin Labs Inc.
// Distributed under the MIT software license.
//
// ctv.dart — Opt3 P3: BIP119 CheckTemplateVerify template hash.
//
// Byte-for-byte port of channel.ts ctvHash / serTxOutCtv. The eLTOO settlement TX is committed
// by this hash, so it must agree with the node's byte-less C++ CTV hashing exactly.
//
// Two easy-to-conflate subtleties, both pinned to node vectors (test/eltoo/ctv_test.dart):
//   • serTxOutCtv uses an **LE32** script-length prefix — NOT the consensus compactSize.
//   • ctvHash is a **single** SHA256 — NOT sha256d.
//   • scriptSigsHash is included ONLY if some input has a non-empty scriptSig; segwit eLTOO
//     spends have empty scriptSigs (our TxIn carries none), so it is omitted.

import 'dart:typed_data';

import 'serialization.dart';

/// CTV output serializer (Phase-4 byte-less): value(LE64) ‖ scriptlen(LE32) ‖ script.
/// Distinct from [serTxOut] (consensus), which uses compactSize for the length.
Uint8List serTxOutCtv(TxOut o) =>
    concatBytes([le64(o.value), le32(o.scriptPubKey.length), o.scriptPubKey]);

/// BIP119 DefaultCheckTemplateVerifyHash (single SHA256). [nIn] is the input index this
/// template is bound to. scriptSigsHash is omitted (segwit spends have empty scriptSigs).
Uint8List ctvHash(Tx tx, int nIn) {
  final parts = <Uint8List>[le32(tx.version), le32(tx.locktime)];

  // scriptSig is always empty for segwit eLTOO spends → scriptSigsHash branch omitted.
  parts.add(le32(tx.vin.length));
  parts.add(sha256Once(concatBytes(tx.vin.map((i) => le32(i.sequence)).toList())));
  parts.add(le32(tx.vout.length));
  parts.add(sha256Once(concatBytes(tx.vout.map(serTxOutCtv).toList())));
  parts.add(le32(nIn));

  return sha256Once(concatBytes(parts)); // single SHA256, NOT double
}
