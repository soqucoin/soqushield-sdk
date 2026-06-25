// Copyright (c) 2026 Soqucoin Labs Inc.
// Distributed under the MIT software license.
//
// eltoo.dart — public entrypoint for the Opt3 self-custodial eLTOO crypto layer.
//
// Import alongside `package:soqushield_sdk/lightning.dart` to activate Opt3:
//
//   import 'package:soqushield_sdk/lightning.dart';
//   import 'package:soqushield_sdk/eltoo.dart';
//
//   final ln = SoqLightning(
//     baseUrl: 'https://lsp.soqu.org',
//     txBuilder: DilithiumEltooBuilder(EltooBuilderOpts(...)),  // self-custodial — same facade
//   );
//
// Kept separate from lightning.dart so the Opt2 facade namespace stays free of the low-level
// consensus types (Tx/serializeTx/toHex/…). The builder implements the same UpdateTxBuilder
// seam, so the two entrypoints compose without change.
library;

export 'src/lightning/eltoo/eltoo.dart';
