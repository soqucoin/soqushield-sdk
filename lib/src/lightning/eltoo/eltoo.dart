// Copyright (c) 2026 Soqucoin Labs Inc.
// Distributed under the MIT software license.
//
// eltoo.dart — barrel for the Opt3 self-custodial eLTOO crypto layer.
//
// The real `DilithiumEltooBuilder` (and the primitives it composes) that swaps into the
// SoqLightning facade via the UpdateTxBuilder seam to make payments self-custodial. The crypto
// primitives (serialization, APO/BIP143 sighash, CTV, keyhash funding) are individually
// node-pinned (P1–P4); the builder's tx-graph assembly is pending stagenet validation (P6).
library;

export 'serialization.dart';
export 'script.dart';
export 'sighash.dart';
export 'ctv.dart';
export 'keyhash.dart';
export 'eltoo_builder.dart';
