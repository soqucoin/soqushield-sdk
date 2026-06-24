// Copyright (c) 2026 Soqucoin Labs Inc.
// Distributed under the MIT software license.
//
// lightning.dart — focused public entrypoint for the Soqucoin Lightning (eLTOO) layer.
//
// Import this (instead of the full `soqushield_sdk.dart` barrel) when you only need the
// Lightning SDK and want to avoid pulling the package's Dilithium FFI / wallet / RPC
// surface. The Lightning layer is pure Dart over `dio` — no native dependencies.
//
//   import 'package:soqushield_sdk/lightning.dart';
//   final ln = SoqLightning(baseUrl: 'https://lsp.soqu.org');
library;

export 'src/lightning/lightning.dart';
