// Copyright (c) 2026 Soqucoin Labs Inc.
// Distributed under the MIT software license.
//
// soq_lightning.dart — high-level developer/wallet facade for Soqucoin Lightning.
//
// Ported 1:1 from the node-proven TypeScript SDK (soq-lightning-sdk/src/sdk.ts). One
// ergonomic surface over the REST [LspClient]; the eLTOO TX construction is abstracted
// behind the swappable [UpdateTxBuilder] (PlaceholderTxBuilder today = Opt2, the real
// DilithiumEltooBuilder later = Opt3, with NO change to this API or the wallet UI).
//
//   final ln = SoqLightning(baseUrl: 'https://lsp.soqu.org');
//   final ch = await ln.openChannel(OpenChannelParams(
//       pubKeyHex: pk, address: addr, capacitySat: 100000000));
//   await ln.pay(ch.channelId, 20000000); // move 0.2 SOQ to the peer
//   await ln.close(ch.channelId);
//
// The invariants enforced here (balance conservation, monotonic state advance, faucet-cap
// clamp, dropped-close resilience) are the ones VERIFIED LIVE against the stagenet LSP on
// 2026-06-24 — keep them.

import 'dart:typed_data';

import 'package:dio/dio.dart';

import 'eltoo/broadcaster.dart';
import 'eltoo/ctv.dart';
import 'eltoo/serialization.dart';
import 'eltoo/sighash.dart';
import 'lsp_client.dart';
import 'lsp_models.dart';
import 'two_party_round.dart';
import 'update_tx_builder.dart';

/// Everything the SDK needs to co-sign + self-custody a channel that the LSP-side facade does
/// NOT hold: the user's key, the funding outpoint (tracked at open), the on-chain payout scripts,
/// the fee, and the ML-DSA signer. Supplied per call so the demo [SoqLightning.pay] path stays
/// key-free.
class SelfCustodyContext {
  final Uint8List userSecretKey;
  final Uint8List userPub; // MUST equal fromHex(channel.initiatorPubKeyHex)
  final OutPoint funding; // the channel's funding outpoint (internal byte order)
  final Uint8List initiatorScriptPubKey; // the user's on-chain settlement payout
  final Uint8List peerScriptPubKey; // the LSP's on-chain settlement payout
  final BigInt feeSat; // fixed per-tx fee (v1, spec §H)
  final MlDsaSign sign; // ML-DSA-44 signer (e.g. DilithiumNative.instance.sign)

  const SelfCustodyContext({
    required this.userSecretKey,
    required this.userPub,
    required this.funding,
    required this.initiatorScriptPubKey,
    required this.peerScriptPubKey,
    required this.feeSat,
    required this.sign,
  });
}

/// Optional watchtower arming hook (spec §1.6 persist→arm→ack). On stagenet the LSP arms the
/// firewalled dual towers on the spoke's behalf, so this is unused by default; it exists so
/// the Opt3 self-custodial path can arm a tower with state i+1 BEFORE [SoqLightning.pay]
/// returns success.
abstract class WatchtowerArming {
  /// The funding outpoint the tower monitors for [channelId].
  Future<({String fundingTxid, int fundingVout})> fundingFor(String channelId);

  /// Register/arm the tower with the freshly-built state i+1.
  Future<void> arm({
    required String channelId,
    required String fundingTxid,
    required int fundingVout,
    required int stateIndex,
    required UpdateTx tx,
  });
}

/// Parameters for opening a channel.
class OpenChannelParams {
  final String pubKeyHex; // ML-DSA-44 public key (hex)
  final String address; // L1 settlement address
  final int capacitySat;
  final String? name;
  final int? csvDelay; // settlement_csv tier (default 288, transparent — spec §6.2.1)

  const OpenChannelParams({
    required this.pubKeyHex,
    required this.address,
    required this.capacitySat,
    this.name,
    this.csvDelay,
  });
}

class SoqLightning {
  final LspClient client;
  final UpdateTxBuilder _builder;
  final WatchtowerArming? _watchtower;

  /// [baseUrl] is the LSP gateway (e.g. https://lsp.soqu.org). [txBuilder] defaults to the
  /// LSP-trusted [PlaceholderTxBuilder] (Opt2); pass a real builder for Opt3. [dio] is
  /// injectable for tests.
  SoqLightning({
    required String baseUrl,
    UpdateTxBuilder txBuilder = const PlaceholderTxBuilder(),
    WatchtowerArming? watchtower,
    Dio? dio,
  })  : client = LspClient(baseUrl: baseUrl, dio: dio),
        _builder = txBuilder,
        _watchtower = watchtower;

  /// Construct over an existing [LspClient] (e.g. a shared/pre-configured transport).
  SoqLightning.withClient(
    this.client, {
    UpdateTxBuilder txBuilder = const PlaceholderTxBuilder(),
    WatchtowerArming? watchtower,
  })  : _builder = txBuilder,
        _watchtower = watchtower;

  /// Fund via faucet + auto-open a channel (stagenet path). Returns the opened channel.
  ///
  /// The LSP caps channel capacity at `max_channel_sat`; the faucet drips the requested
  /// funds but SILENTLY declines to open a channel if asked for more (success + txid, no
  /// channel_id — verified live 2026-06-24). We clamp the request to the advertised cap so
  /// the open actually happens; the returned [LnChannel] reflects the real capacity.
  Future<LnChannel> fundAndOpen(OpenChannelParams p) async {
    Map<String, dynamic> info;
    try {
      info = await client.info();
    } catch (_) {
      info = const {};
    }
    final maxCap = (info['max_channel_sat'] as num?)?.toInt() ?? p.capacitySat;
    final capacitySat = p.capacitySat < maxCap ? p.capacitySat : maxCap;

    final r = await client.faucetDrip(FaucetReq(
      address: p.address,
      pubKeyHex: p.pubKeyHex,
      openChannel: true,
      amountSat: capacitySat,
      name: p.name ?? 'sdk',
    ));
    if (!r.success) {
      throw StateError('faucet failed: ${r.error ?? "unknown"}');
    }
    if (r.channelId == null) {
      throw StateError(
        'faucet dripped ${r.amountSat ?? capacitySat} sat (txid ${r.txid ?? "?"}) but did '
        'not open a channel — requested capacity may exceed the LSP max_channel_sat ($maxCap)',
      );
    }
    return client.getChannel(r.channelId!);
  }

  /// Open a channel directly (when you already hold funds — no faucet).
  Future<LnChannel> openChannel(OpenChannelParams p) async {
    final r = await client.openChannel(OpenChannelReq(
      initiatorPubKeyHex: p.pubKeyHex,
      capacitySat: p.capacitySat,
      initiatorName: p.name ?? 'sdk',
      csvDelay: p.csvDelay ?? 288,
      initiatorAddress: p.address,
    ));
    if (!r.accepted || r.channelId == null) {
      throw StateError('open rejected: ${r.rejectReason ?? "unknown"}');
    }
    return client.getChannel(r.channelId!);
  }

  /// Move [amountSat] from the initiator (us) to the peer — one eLTOO state bump.
  ///
  /// Proposes the transition, then re-reads: the LSP is the source of truth for the
  /// committed balances/index (a countersigning peer may meet-in-the-middle or bump the
  /// index), so we never assume our proposal was stored verbatim. Returns the channel AS
  /// COMMITTED by the peer.
  Future<LnChannel> pay(String channelId, int amountSat) async {
    if (amountSat <= 0) throw ArgumentError('amount must be positive');
    final ch = await client.getChannel(channelId);
    if (ch.state != 'open') throw StateError('channel not open (state=${ch.state})');
    if (amountSat > ch.initiatorBalanceSat) {
      throw StateError('insufficient initiator balance');
    }

    final next = UpdateContext(
      channel: ch,
      nextStateIndex: ch.stateIndex + 1,
      nextInitiatorBalanceSat: ch.initiatorBalanceSat - amountSat,
      nextPeerBalanceSat: ch.peerBalanceSat + amountSat,
    );
    final tx = await _builder.build(next);
    final resp = await client.updateState(
      channelId,
      UpdateStateReq(
        stateIndex: next.nextStateIndex,
        initiatorBalanceSat: next.nextInitiatorBalanceSat,
        peerBalanceSat: next.nextPeerBalanceSat,
        updateTxHex: tx.updateTxHex,
        settlementTxHex: tx.settlementTxHex,
        ctvHash: tx.ctvHash,
      ),
    );
    if (!resp.accepted) {
      throw StateError('update rejected: ${resp.rejectReason ?? "unknown"}');
    }

    // §1.6 persist→arm→ack: the LSP has now persisted+countersigned state i+1. Arm the
    // watchtower with i+1 BEFORE we return success. If arming fails we throw — the payment
    // is NOT safely locked, and surfacing that beats a silent theft window.
    final wt = _watchtower;
    if (wt != null) {
      final f = await wt.fundingFor(channelId);
      await wt.arm(
        channelId: channelId,
        fundingTxid: f.fundingTxid,
        fundingVout: f.fundingVout,
        stateIndex: next.nextStateIndex,
        tx: tx,
      );
    }

    final after = await client.getChannel(channelId);
    // invariant true in BOTH echo_mode and accept-and-store: state advanced + funds conserved
    if (after.stateIndex <= ch.stateIndex) {
      throw StateError('state did not advance: ${ch.stateIndex} -> ${after.stateIndex}');
    }
    if (after.initiatorBalanceSat + after.peerBalanceSat != after.capacitySat) {
      throw StateError('balance not conserved after update');
    }
    return after;
  }

  /// Self-custodial pay — one F1-complete LSP round (spec §D + §E). Moves [amountSat] to the peer
  /// and returns the fully-signed (Tu, Ts) the caller MUST persist: with them the user can
  /// unilaterally close WITHOUT the LSP. Unlike [pay] (the demo/opaque path) this does real
  /// 2-of-2 co-signing — the user signs locally; the LSP returns BOTH partials; they're combined.
  ///
  /// Balance/fee model: the LSP accounts LOGICAL balances (sum == capacity, `manager.go:271`), but
  /// the on-chain settlement can only pay capacity − 2·fee (one fee for the update tx, one for the
  /// settlement). ⚠️ v1 policy (§H — FLAG): the INITIATOR pays both on-chain force-close fees (the
  /// LN default), so its settlement output = logical balance − 2·fee. Revisit when fee policy lands.
  ///
  /// ⚠️ TRUST GAP (WS2b Task 7): the LSP co-signs the settlement WITHOUT validating its outputs
  /// match the recorded balances — a malicious spoke could over-pay itself. Safe only until the
  /// LSP enforces settlement-output validation.
  Future<({LnChannel channel, SignedTx update, SignedTx settlement})> selfCustodialPay(
      String channelId, int amountSat, SelfCustodyContext ctx) async {
    if (amountSat <= 0) throw ArgumentError('amount must be positive');
    final ch = await client.getChannel(channelId);
    if (ch.state != 'open') throw StateError('channel not open (state=${ch.state})');
    if (amountSat > ch.initiatorBalanceSat) throw StateError('insufficient initiator balance');

    final lspPub = fromHex(ch.peerPubKeyHex);
    final bc = EltooBroadcaster(ChannelParams(
      funding: ctx.funding,
      capacitySat: BigInt.from(ch.capacitySat),
      initiatorPub: ctx.userPub,
      peerPub: lspPub,
      initiatorScriptPubKey: ctx.initiatorScriptPubKey,
      peerScriptPubKey: ctx.peerScriptPubKey,
      settlementCsv: ch.csvDelay,
      feeSat: ctx.feeSat,
    ));

    // Logical balances after the payment (sum == capacity, for the LSP), then the on-chain
    // settlement split: the initiator absorbs the 2·fee force-close cost.
    final logicalInitiator = ch.initiatorBalanceSat - amountSat;
    final logicalPeer = ch.peerBalanceSat + amountSat;
    final settlementInitiator = BigInt.from(logicalInitiator) - BigInt.two * ctx.feeSat;
    if (settlementInitiator < BigInt.zero) {
      throw StateError(
          'initiator balance $logicalInitiator cannot cover ${BigInt.two * ctx.feeSat} on-chain fees');
    }

    final round = await lspUpdateRound(
      bc,
      (req) => client.updateState(channelId, req),
      stateNum: ch.stateIndex + 1,
      initiatorBalanceSat: settlementInitiator,
      peerBalanceSat: BigInt.from(logicalPeer),
      reqBalances: (initiatorSat: logicalInitiator, peerSat: logicalPeer),
      userSecretKey: ctx.userSecretKey,
      userPub: ctx.userPub,
      lspPub: lspPub,
      mldsa: ctx.sign,
    );

    // §1.6 persist→arm→ack: arm the watchtower with the FULLY-SIGNED txs that will broadcast.
    final wt = _watchtower;
    if (wt != null) {
      await wt.arm(
        channelId: channelId,
        fundingTxid: toHex(reversed(ctx.funding.txid)),
        fundingVout: ctx.funding.n,
        stateIndex: ch.stateIndex + 1,
        tx: UpdateTx(
          updateTxHex: round.update.hex,
          settlementTxHex: round.settlement.hex,
          ctvHash: toHex(ctvHash(round.settlement.tx, 0)),
        ),
      );
    }

    final after = await client.getChannel(channelId);
    return (channel: after, update: round.update, settlement: round.settlement);
  }

  /// Cooperative close → L1 settlement enqueued via the LSP.
  ///
  /// Resilient to the deployed binary's bug where a SUCCESSFUL close mutates state to
  /// "closed" but drops the HTTP response: on a transport error we re-read the channel and
  /// treat closed/closing as success.
  Future<CloseResp> close(String channelId) async {
    try {
      final r = await client.closeChannel(channelId);
      if (!r.accepted) throw StateError('close rejected: ${r.rejectReason ?? "unknown"}');
      return r;
    } catch (e) {
      LnChannel? ch;
      try {
        ch = await client.getChannel(channelId);
      } catch (_) {
        ch = null;
      }
      if (ch != null && ch.isClosed) {
        return const CloseResp(
            accepted: true, rejectReason: '(response dropped; state confirms closed)');
      }
      rethrow;
    }
  }

  /// LSP liveness — `{ status: "ok", ... }` when the peer + its node backend are healthy.
  Future<Map<String, dynamic>> health() => client.health();

  /// LSP identity/capabilities — peer name, version, network, fee policy, etc.
  Future<Map<String, dynamic>> info() => client.info();

  Future<LnChannel> channel(String id) => client.getChannel(id);
  Future<List<LnChannel>> channels() => client.listChannels();

  /// Watchtower health, proxied through the LSP. On stagenet the LSP arms the (firewalled,
  /// dual) towers on the spoke's behalf, so the spoke verifies LIVENESS here — "a tower is
  /// watching" — not per-state arming (that's mainnet Phase-1 signed receipts).
  Future<TowerProxyStatus> towerStatus() => client.towerStatus();

  /// Throws unless at least [minTowers] watchtowers are reachable — call before relying on
  /// offline safety. Default 2 reflects the dual-tower defense-in-depth deployment.
  Future<void> assertTowersHealthy([int minTowers = 2]) async {
    final s = await client.towerStatus();
    final up = s.reachable;
    if (!s.available || up < minTowers) {
      throw StateError(
          'watchtower coverage degraded: $up/${s.towerCount} reachable (need $minTowers)');
    }
  }
}
