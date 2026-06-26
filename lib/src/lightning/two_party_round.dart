// Copyright (c) 2026 Soqucoin Labs Inc.
// Distributed under the MIT software license.
//
// two_party_round.dart — the F1 self-custody stitch: consume the LSP's two response partials.
//
// Dart mirror of soq-lightning-sdk/src/two-party-broadcast.ts (combineLspRound, lspUpdateRound).
// After the user signs its own partials and the LSP returns BOTH partials (peer_signature_hex =
// update, settlement_signature_hex = settlement), this combines them into a fully-signed,
// broadcastable (Tu, Ts) the user persists — so it can unilaterally close WITHOUT the LSP (§E).
// Proven live on stagenet via the TS equivalent (self-custody-canary).

import 'dart:typed_data';

import 'eltoo/broadcaster.dart';
import 'eltoo/ctv.dart';
import 'eltoo/keyhash.dart';
import 'eltoo/serialization.dart';
import 'eltoo/sighash.dart';
import 'lsp_models.dart';

/// The LSP round-trip a live pay() performs (in production: `LspClient.updateState`). Injectable
/// so the round is testable with a mock LSP. The response MUST carry BOTH partials.
typedef LspUpdateStateFn = Future<UpdateStateResp> Function(UpdateStateReq req);

/// Parse one LSP response signature (hex) into a [KeyhashPartial] under the LSP's pubkey. The LSP
/// returns a 2421-byte element (2420 ML-DSA ‖ 0x42). A short/garbage value (the legacy
/// "countersigned" stub, or a missing field) is rejected here with a clear message — exactly the
/// F1 failure the round must not silently accept.
KeyhashPartial _lspPartial(Uint8List lspPub, String sigHex) {
  Uint8List sig;
  try {
    sig = fromHex(sigHex);
  } catch (_) {
    // The legacy stub is the literal string "countersigned" (not hex) — give the operator the
    // real reason rather than a cryptic hex-parse error.
    throw StateError(
        'LSP partial is not valid hex — is the LSP returning a real ML-DSA sig (WS2b deployed) '
        'rather than the "countersigned" stub?');
  }
  if (sig.length != 2421) {
    throw StateError(
        'LSP partial must be 2421 bytes (2420 ‖ hashType), got ${sig.length} — is the LSP '
        'returning a real ML-DSA sig (WS2b deployed) rather than the "countersigned" stub?');
  }
  if (sig[2420] != sighashAnyprevoutAnyscript) {
    throw StateError('LSP partial hashType must be 0x42, got 0x${sig[2420].toRadixString(16)}');
  }
  return KeyhashPartial(lspPub, sig);
}

/// F1 stitch: combine the LSP's two response partials with the user's into a fully-signed,
/// broadcastable (Tu, Ts) the user persists (spec §E). [lspUpdateSigHex] = `peer_signature_hex`,
/// [lspSettleSigHex] = `settlement_signature_hex`. Throws if either sig is the stub/wrong-length,
/// or the combine can't match the committed keys.
({SignedTx update, SignedTx settlement}) combineLspRound(
  EltooBroadcaster bc, {
  required Tx updateTx,
  required Tx settlementTx,
  required int prevState,
  required KeyhashPartial userUpdate,
  required KeyhashPartial userSettle,
  required Uint8List lspPub,
  required String lspUpdateSigHex,
  required String lspSettleSigHex,
}) {
  final update =
      bc.assembleFundingSpend(updateTx, [userUpdate, _lspPartial(lspPub, lspUpdateSigHex)]);
  final settlement = bc.assembleSettlement(
      settlementTx, prevState, [userSettle, _lspPartial(lspPub, lspSettleSigHex)]);
  return (update: update, settlement: settlement);
}

/// One F1-complete update round against the LSP — the real pay() path. The user builds the
/// update + settlement, signs ITS partials locally, sends the txs, and the LSP returns its two
/// partials; [combineLspRound] stitches them into the fully-signed (Tu, Ts) the user persists.
/// The user ends the round able to unilaterally close (spec §E).
///
/// [initiatorBalanceSat]/[peerBalanceSat] are the SETTLEMENT-tx outputs (fee-deducted, sum =
/// capacity − 2·fee). [reqBalances] are the LOGICAL balances reported to the LSP (sum == capacity,
/// `manager.go:271`); defaults to the settlement balances (correct only when fee == 0).
///
/// Throws if the LSP rejects, or omits `settlement_signature_hex` (F1 not deployed on the LSP).
Future<({SignedTx update, SignedTx settlement})> lspUpdateRound(
  EltooBroadcaster bc,
  LspUpdateStateFn updateState, {
  required int stateNum,
  required BigInt initiatorBalanceSat,
  required BigInt peerBalanceSat,
  ({int initiatorSat, int peerSat})? reqBalances,
  required Uint8List userSecretKey,
  required Uint8List userPub,
  required Uint8List lspPub,
  required MlDsaSign mldsa,
}) async {
  final updateTx = bc.buildFundingUpdateTx(stateNum);
  final updateValueSat = updateTx.vout[0].value;
  final settlementTx = bc.buildSettlementTx(
    updateOutpoint: OutPoint(txidInternal(updateTx), 0),
    updateValueSat: updateValueSat,
    initiatorBalanceSat: initiatorBalanceSat,
    peerBalanceSat: peerBalanceSat,
  );

  // The user signs its own partials (own key only) BEFORE handing the txs to the LSP.
  final userUpdate = bc.signFundingPartial(updateTx, userSecretKey, userPub, mldsa);
  final userSettle = bc.signEltooPartial(settlementTx, updateValueSat, userSecretKey, userPub, mldsa);

  final resp = await updateState(UpdateStateReq(
    stateIndex: stateNum,
    initiatorBalanceSat: reqBalances?.initiatorSat ?? initiatorBalanceSat.toInt(),
    peerBalanceSat: reqBalances?.peerSat ?? peerBalanceSat.toInt(),
    updateTxHex: serializeTxHex(updateTx),
    settlementTxHex: serializeTxHex(settlementTx),
    ctvHash: toHex(ctvHash(settlementTx, 0)),
  ));
  if (!resp.accepted) {
    throw StateError('LSP rejected update: ${resp.rejectReason ?? "unknown"}');
  }
  if (resp.peerSignatureHex == null || resp.settlementSignatureHex == null) {
    throw StateError(
        'LSP did not return BOTH partials — settlement_signature_hex missing. The user cannot '
        'self-custodially close without it (F1 not deployed on the LSP?).');
  }

  return combineLspRound(
    bc,
    updateTx: updateTx,
    settlementTx: settlementTx,
    prevState: stateNum,
    userUpdate: userUpdate,
    userSettle: userSettle,
    lspPub: lspPub,
    lspUpdateSigHex: resp.peerSignatureHex!,
    lspSettleSigHex: resp.settlementSignatureHex!,
  );
}
