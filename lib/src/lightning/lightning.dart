// Copyright (c) 2026 Soqucoin Labs Inc.
// Distributed under the MIT software license.
//
// lightning.dart — barrel for the Soqucoin Lightning (eLTOO) layer of the SoquShield SDK.
//
// Quantum-safe (ML-DSA-44) eLTOO Lightning, ported from the node-proven TypeScript SDK.
// Layers:
//   lsp_models        — request/response types for the LSP REST API
//   lsp_client        — LspClient REST transport for the live LSP (https://lsp.soqu.org)
//   update_tx_builder — the SWAPPABLE eLTOO TX-construction seam (Opt2 placeholder → Opt3 real)
//   soq_lightning     — high-level SoqLightning facade (open/pay/close + tower liveness)
library;

export 'lsp_models.dart';
export 'lsp_client.dart';
export 'update_tx_builder.dart';
export 'soq_lightning.dart';
