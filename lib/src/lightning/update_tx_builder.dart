// Copyright (c) 2026 Soqucoin Labs Inc.
// Distributed under the MIT software license.
//
// update_tx_builder.dart — the swappable eLTOO transaction-construction seam.
//
// This is the single architectural seam that lets Opt2 and Opt3 be the SAME code path
// (Casey, 2026-06-24): the [SoqLightning] facade and the whole wallet UI talk only to the
// [UpdateTxBuilder] interface, never to a concrete signer.
//
//   • Opt2 (ship sooner): [PlaceholderTxBuilder] — the LSP is accept-and-store on the happy
//     path, so the spoke hands it opaque placeholders. Custody is LSP-trusted, honestly
//     labelled. NO real on-chain dispute path.
//   • Opt3 (flagship): a `DilithiumEltooBuilder` that ports the node-proven TS `channel.ts`
//     (SIGHASH_ANYPREVOUTANYSCRIPT 0x42, CTV templates, CSFS 2-of-2, p2wsh v6) and signs
//     with the existing `DilithiumNative.instance.sign(...)`. Swapping it in is the WHOLE
//     change — zero edits to the facade or UI.
//
// ⚠️ Do NOT fake a real builder by returning plausible-looking hex from the placeholder.
// The honest boundary is the contract: placeholders are visibly placeholders so nothing
// downstream mistakes Opt2 for self-custody. The old in-app crypto (OP_CHECKMULTISIG +
// UTF-8 "state digest") that this replaces was a fund-loss trap precisely because it LOOKED
// real but signed nothing binding.

import 'lsp_models.dart';

/// Everything a builder needs to construct the TXs for one state transition.
class UpdateContext {
  /// Current on-LSP channel state (pre-update).
  final LnChannel channel;
  final int nextStateIndex;
  final int nextInitiatorBalanceSat;
  final int nextPeerBalanceSat;

  const UpdateContext({
    required this.channel,
    required this.nextStateIndex,
    required this.nextInitiatorBalanceSat,
    required this.nextPeerBalanceSat,
  });
}

/// The eLTOO update + settlement TX hex (plus CTV hash) for one state transition.
class UpdateTx {
  final String updateTxHex;
  final String settlementTxHex;
  final String ctvHash;

  const UpdateTx({
    required this.updateTxHex,
    required this.settlementTxHex,
    required this.ctvHash,
  });
}

/// Produces the eLTOO update/settlement TX hex for a state transition.
///
/// Opt3's `DilithiumEltooBuilder` will implement this with real 0x42-signed transactions;
/// today [PlaceholderTxBuilder] is the default. The facade is agnostic to which is wired.
abstract class UpdateTxBuilder {
  Future<UpdateTx> build(UpdateContext ctx);
}

/// Default builder for the LSP-trusted (Opt2) happy path — opaque placeholders accepted by
/// the accept-and-store peer. Carries NO dispute guarantees; swap in the real signer (Opt3)
/// before relying on the unilateral close path.
class PlaceholderTxBuilder implements UpdateTxBuilder {
  const PlaceholderTxBuilder();

  @override
  Future<UpdateTx> build(UpdateContext ctx) async => const UpdateTx(
        updateTxHex: 'placeholder',
        settlementTxHex: 'placeholder',
        ctvHash: 'placeholder',
      );
}
