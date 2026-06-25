// Copyright (c) 2026 Soqucoin Labs Inc.
// Distributed under the MIT software license.
//
// serialization.dart — Opt3 consensus transaction serialization (P1).
//
// Byte-for-byte port of the node-proven TypeScript SDK (soq-lightning-sdk/src/onchain.ts +
// the shared serializers in channel.ts). This is the foundation the whole eLTOO builder
// stands on — every sighash, txid, and CTV hash is computed over these bytes, so a single
// wrong byte here breaks everything above it.
//
// 🔴 PHASE-4 CTxOut (the #1 recurring root cause): the consensus output serialization is
//    value(LE64) ‖ compactSize(spk) ‖ spk — with NO nVisibility/nAssetType extension bytes.
//    The stale public Go SDK still emits those bytes; we MUST NOT. Pinned to node vectors in
//    test/serialization_test.dart (onchain_vectors.json: rawTxHex + txid byte-equal).
//
// SOURCE OF TRUTH: soqucoind C++ consensus (primitives/transaction.h, interpreter.cpp) via
// the node-pinned TS vectors. Witness-v1 send format verified byte-exact in the TS suite.

import 'dart:typed_data';
import 'package:crypto/crypto.dart' as crypto;

// ── byte writers (mirror onchain.ts:36-58) ──

/// Single byte (n & 0xff).
Uint8List u8(int n) => Uint8List.fromList([n & 0xff]);

/// 2-byte little-endian.
Uint8List le16(int n) => Uint8List.fromList([n & 0xff, (n >> 8) & 0xff]);

/// 4-byte little-endian (unsigned 32-bit; handles 0xffffffff).
Uint8List le32(int n) => Uint8List.fromList([
      n & 0xff,
      (n >> 8) & 0xff,
      (n >> 16) & 0xff,
      (n >> 24) & 0xff,
    ]);

/// 8-byte little-endian from a BigInt (wraps to uint64).
Uint8List le64(BigInt v) {
  final out = Uint8List(8);
  var x = v.toUnsigned(64);
  final mask = BigInt.from(0xff);
  for (var i = 0; i < 8; i++) {
    out[i] = (x & mask).toInt();
    x = x >> 8;
  }
  return out;
}

/// Concatenate byte arrays.
Uint8List concatBytes(List<Uint8List> parts) {
  var n = 0;
  for (final p in parts) {
    n += p.length;
  }
  final out = Uint8List(n);
  var o = 0;
  for (final p in parts) {
    out.setAll(o, p);
    o += p.length;
  }
  return out;
}

/// Bitcoin CompactSize varint: <0xfd → 1 byte; ≤0xffff → 0xfd+le16; ≤0xffffffff → 0xfe+le32.
Uint8List compactSize(int n) {
  if (n < 0xfd) return u8(n);
  if (n <= 0xffff) return concatBytes([u8(0xfd), le16(n)]);
  if (n <= 0xffffffff) return concatBytes([u8(0xfe), le32(n)]);
  throw ArgumentError('compactSize too large: $n');
}

/// SHA256d — double SHA256.
Uint8List sha256d(Uint8List b) =>
    Uint8List.fromList(crypto.sha256.convert(crypto.sha256.convert(b).bytes).bytes);

/// Single SHA256.
Uint8List sha256Once(Uint8List b) => Uint8List.fromList(crypto.sha256.convert(b).bytes);

// ── hex helpers ──

const _hexDigits = '0123456789abcdef';

String toHex(Uint8List b) {
  final sb = StringBuffer();
  for (final x in b) {
    sb.write(_hexDigits[(x >> 4) & 0xf]);
    sb.write(_hexDigits[x & 0xf]);
  }
  return sb.toString();
}

Uint8List fromHex(String h) {
  if (h.length.isOdd) throw ArgumentError('hex length must be even');
  final out = Uint8List(h.length ~/ 2);
  for (var i = 0; i < out.length; i++) {
    out[i] = int.parse(h.substring(i * 2, i * 2 + 2), radix: 16);
  }
  return out;
}

Uint8List reversed(Uint8List b) => Uint8List.fromList(b.reversed.toList());

// ── transaction model (mirror onchain.ts:104-108 / channel.ts OutPoint) ──

/// A transaction outpoint. [txid] is the 32-byte INTERNAL byte order (not display-reversed).
class OutPoint {
  final Uint8List txid;
  final int n;
  const OutPoint(this.txid, this.n);

  /// Build from a display-order txid hex (reverses to internal order).
  factory OutPoint.fromTxidHex(String txidHex, int n) {
    final b = fromHex(txidHex);
    if (b.length != 32) throw ArgumentError('txid must be 32 bytes, got ${b.length}');
    return OutPoint(reversed(b), n);
  }
}

/// A transaction input. [scriptPubKey] is the input's scriptPubKey (the BIP143 scriptCode).
/// For segwit broadcast ([serializeTx]) the on-wire scriptSig is always empty and [witness]
/// carries the data. [scriptSig] is used only by the legacy/opaque transport serializer
/// ([serializeTxLegacy]) — the eLTOO builder stuffs its signature there for the LSP's opaque
/// update_tx_hex (real broadcast uses the witness).
class TxIn {
  final OutPoint prevout;
  final int sequence;
  final Uint8List scriptPubKey;
  final List<Uint8List>? witness;
  final Uint8List? scriptSig;
  const TxIn({
    required this.prevout,
    required this.sequence,
    required this.scriptPubKey,
    this.witness,
    this.scriptSig,
  });
}

/// A transaction output. Phase-4 byte-less: only value + scriptPubKey are serialized.
class TxOut {
  final BigInt value; // satoshis
  final Uint8List scriptPubKey;
  const TxOut(this.value, this.scriptPubKey);
}

/// A transaction.
class Tx {
  final int version;
  final int locktime;
  final List<TxIn> vin;
  final List<TxOut> vout;
  const Tx({
    required this.version,
    required this.locktime,
    required this.vin,
    required this.vout,
  });
}

// ── consensus serializers (mirror onchain.ts:110-219) ──

/// CTxOut consensus serializer — Phase-4 byte-less: value(LE64) ‖ compactSize(spk) ‖ spk.
/// 🔴 NO nVisibility/nAssetType bytes.
Uint8List serTxOut(TxOut o) =>
    concatBytes([le64(o.value), compactSize(o.scriptPubKey.length), o.scriptPubKey]);

/// Outpoint serialization: txid(32) ‖ le32(n).
Uint8List serOutpoint(TxIn i) => concatBytes([i.prevout.txid, le32(i.prevout.n)]);

/// Full transaction serialization (BIP144 witness). Marker/flag + witness stacks are emitted
/// only when at least one input carries a witness; scriptSig is always empty (compactSize(0)).
Uint8List serializeTx(Tx tx) {
  final hasWitness = tx.vin.any((i) => (i.witness?.isNotEmpty ?? false));
  final parts = <Uint8List>[le32(tx.version)];
  if (hasWitness) {
    parts.add(u8(0x00)); // marker
    parts.add(u8(0x01)); // flag
  }
  parts.add(compactSize(tx.vin.length));
  for (final i in tx.vin) {
    parts.add(serOutpoint(i));
    parts.add(compactSize(0)); // empty scriptSig
    parts.add(le32(i.sequence));
  }
  parts.add(compactSize(tx.vout.length));
  for (final o in tx.vout) {
    parts.add(serTxOut(o));
  }
  if (hasWitness) {
    for (final i in tx.vin) {
      final w = i.witness ?? const [];
      parts.add(compactSize(w.length));
      for (final item in w) {
        parts.add(compactSize(item.length));
        parts.add(item);
      }
    }
  }
  parts.add(le32(tx.locktime));
  return concatBytes(parts);
}

String serializeTxHex(Tx tx) => toHex(serializeTx(tx));

/// txid: SHA256d of the NON-witness serialization, reversed to display order.
String txid(Tx tx) => toHex(reversed(_txidInternal(tx)));

/// txid in INTERNAL byte order (not display-reversed) — what an [OutPoint] consumes as the
/// prevout of a spending tx (e.g. the eLTOO settlement spending the update). scriptSig is
/// cleared (the txid commits to the unsigned form).
Uint8List txidInternal(Tx tx) => _txidInternal(tx);

Uint8List _txidInternal(Tx tx) {
  final parts = <Uint8List>[le32(tx.version), compactSize(tx.vin.length)];
  for (final i in tx.vin) {
    parts.add(serOutpoint(i));
    parts.add(compactSize(0)); // empty scriptSig
    parts.add(le32(i.sequence));
  }
  parts.add(compactSize(tx.vout.length));
  for (final o in tx.vout) {
    parts.add(serTxOut(o));
  }
  parts.add(le32(tx.locktime));
  return sha256d(concatBytes(parts));
}

/// Legacy (non-witness) serialization that INCLUDES each input's [TxIn.scriptSig] (channel.ts
/// serializeTx). Used for the LSP's opaque update/settlement transport hex, where the eLTOO
/// builder stuffs the 0x42 signature into scriptSig. Real broadcast uses [serializeTx] (witness).
Uint8List serializeTxLegacy(Tx tx) {
  final parts = <Uint8List>[le32(tx.version), compactSize(tx.vin.length)];
  for (final i in tx.vin) {
    final ss = i.scriptSig ?? Uint8List(0);
    parts.add(serOutpoint(i));
    parts.add(compactSize(ss.length));
    parts.add(ss);
    parts.add(le32(i.sequence));
  }
  parts.add(compactSize(tx.vout.length));
  for (final o in tx.vout) {
    parts.add(serTxOut(o));
  }
  parts.add(le32(tx.locktime));
  return concatBytes(parts);
}
