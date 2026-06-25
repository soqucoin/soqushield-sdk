// Copyright (c) 2026 Soqucoin Labs Inc.
// Distributed under the MIT software license.
//
// lsp_models.dart — request/response types for the Soqucoin Lightning LSP REST API.
//
// Ported from the node-proven TypeScript SDK (soq-lightning-sdk/src/client.ts), which is
// in turn grounded in soq-lightning-peer/internal/server/rest.go (the live endpoints on the
// Services VPS, fronted at https://lsp.soqu.org). Field names mirror the Go/TS structs
// verbatim over the wire (snake_case); Dart accessors are camelCase.

/// One eLTOO payment channel as committed on the LSP (channelToMap, rest.go:304-317).
class LnChannel {
  final String channelId;
  final String initiatorPubKeyHex;
  final String peerPubKeyHex;
  final int capacitySat;
  final int initiatorBalanceSat;
  final int peerBalanceSat;
  final int stateIndex;
  final String state; // "open" | "closing" | "closed" | ...
  final int csvDelay;
  final int createdAtUnix;

  const LnChannel({
    required this.channelId,
    required this.initiatorPubKeyHex,
    required this.peerPubKeyHex,
    required this.capacitySat,
    required this.initiatorBalanceSat,
    required this.peerBalanceSat,
    required this.stateIndex,
    required this.state,
    required this.csvDelay,
    required this.createdAtUnix,
  });

  bool get isOpen => state == 'open';
  bool get isClosed => state == 'closed' || state == 'closing';

  factory LnChannel.fromJson(Map<String, dynamic> json) => LnChannel(
        channelId: json['channel_id'] as String,
        initiatorPubKeyHex: json['initiator_pub_key_hex'] as String? ?? '',
        peerPubKeyHex: json['peer_pub_key_hex'] as String? ?? '',
        capacitySat: (json['capacity_sat'] as num).toInt(),
        initiatorBalanceSat: (json['initiator_balance_sat'] as num).toInt(),
        peerBalanceSat: (json['peer_balance_sat'] as num).toInt(),
        stateIndex: (json['state_index'] as num?)?.toInt() ?? 0,
        state: json['state'] as String? ?? 'unknown',
        csvDelay: (json['csv_delay'] as num?)?.toInt() ?? 0,
        createdAtUnix: (json['created_at_unix'] as num?)?.toInt() ?? 0,
      );
}

/// Request: open a channel directly when you already hold funds (rest.go POST /v1/channels).
class OpenChannelReq {
  final String initiatorPubKeyHex;
  final int capacitySat;
  final String initiatorName;
  final int csvDelay; // settlement_csv tier (spec §6.2.1: 288 transparent)
  final String initiatorAddress;

  const OpenChannelReq({
    required this.initiatorPubKeyHex,
    required this.capacitySat,
    required this.initiatorName,
    required this.csvDelay,
    required this.initiatorAddress,
  });

  Map<String, dynamic> toJson() => {
        'initiator_pub_key_hex': initiatorPubKeyHex,
        'capacity_sat': capacitySat,
        'initiator_name': initiatorName,
        'csv_delay': csvDelay,
        'initiator_address': initiatorAddress,
      };
}

/// Response to an open request (rest.go:161-176).
class OpenChannelResp {
  final bool accepted;
  final String? rejectReason;
  final String? peerPubKeyHex;
  final String? channelId;
  final String? peerAddress;

  const OpenChannelResp({
    required this.accepted,
    this.rejectReason,
    this.peerPubKeyHex,
    this.channelId,
    this.peerAddress,
  });

  factory OpenChannelResp.fromJson(Map<String, dynamic> json) => OpenChannelResp(
        accepted: json['accepted'] as bool? ?? false,
        rejectReason: json['reject_reason'] as String?,
        peerPubKeyHex: json['peer_pub_key_hex'] as String?,
        channelId: json['channel_id'] as String?,
        peerAddress: json['peer_address'] as String?,
      );
}

/// Request: drip stagenet SOQ and (default) auto-open a channel (faucet.go:78-96).
class FaucetReq {
  final String address;
  final int? amountSat; // default 500M, clamped [100M, 1B] server-side
  final bool? openChannel; // default true
  final String? pubKeyHex; // required when openChannel
  final String? name; // default "faucet-user"

  const FaucetReq({
    required this.address,
    this.amountSat,
    this.openChannel,
    this.pubKeyHex,
    this.name,
  });

  Map<String, dynamic> toJson() => {
        'address': address,
        if (amountSat != null) 'amount_sat': amountSat,
        if (openChannel != null) 'open_channel': openChannel,
        if (pubKeyHex != null) 'pub_key_hex': pubKeyHex,
        if (name != null) 'name': name,
      };
}

/// Response from the faucet (faucet.go:258-264).
class FaucetResp {
  final bool success;
  final String? txid;
  final int? amountSat;
  final String? amountSoq;
  final String? channelId;
  final String? error;
  final String? retryAfter;

  const FaucetResp({
    required this.success,
    this.txid,
    this.amountSat,
    this.amountSoq,
    this.channelId,
    this.error,
    this.retryAfter,
  });

  factory FaucetResp.fromJson(Map<String, dynamic> json) => FaucetResp(
        success: json['success'] as bool? ?? false,
        txid: json['txid'] as String?,
        amountSat: (json['amount_sat'] as num?)?.toInt(),
        amountSoq: json['amount_soq']?.toString(),
        channelId: json['channel_id'] as String?,
        error: json['error'] as String?,
        retryAfter: json['retry_after'] as String?,
      );
}

/// Request: propose one eLTOO state transition (rest.go POST /v1/channels/{id}/update).
///
/// [updateTxHex]/[settlementTxHex]/[ctvHash] come from the swappable [UpdateTxBuilder]:
/// placeholder strings on the Opt2 LSP-trusted path, real 0x42-signed TX hex on Opt3.
class UpdateStateReq {
  final int stateIndex;
  final int initiatorBalanceSat;
  final int peerBalanceSat;
  final String updateTxHex;
  final String settlementTxHex;
  final String ctvHash;

  const UpdateStateReq({
    required this.stateIndex,
    required this.initiatorBalanceSat,
    required this.peerBalanceSat,
    required this.updateTxHex,
    required this.settlementTxHex,
    required this.ctvHash,
  });

  Map<String, dynamic> toJson() => {
        'state_index': stateIndex,
        'initiator_balance_sat': initiatorBalanceSat,
        'peer_balance_sat': peerBalanceSat,
        'update_tx_hex': updateTxHex,
        'settlement_tx_hex': settlementTxHex,
        'ctv_hash': ctvHash,
      };
}

/// Response to a state update (rest.go updateState).
class UpdateStateResp {
  final bool accepted;
  final String? rejectReason;
  final String? peerSignatureHex; // "countersigned" on success
  final UpdateStateEcho? echo;

  const UpdateStateResp({
    required this.accepted,
    this.rejectReason,
    this.peerSignatureHex,
    this.echo,
  });

  factory UpdateStateResp.fromJson(Map<String, dynamic> json) => UpdateStateResp(
        accepted: json['accepted'] as bool? ?? false,
        rejectReason: json['reject_reason'] as String?,
        peerSignatureHex: json['peer_signature_hex'] as String?,
        echo: json['echo'] is Map<String, dynamic>
            ? UpdateStateEcho.fromJson(json['echo'] as Map<String, dynamic>)
            : null,
      );
}

/// The peer's echoed view of the committed state (present in echo_mode).
class UpdateStateEcho {
  final int stateIndex;
  final int initiatorBalanceSat;
  final int peerBalanceSat;

  const UpdateStateEcho({
    required this.stateIndex,
    required this.initiatorBalanceSat,
    required this.peerBalanceSat,
  });

  factory UpdateStateEcho.fromJson(Map<String, dynamic> json) => UpdateStateEcho(
        stateIndex: (json['state_index'] as num?)?.toInt() ?? 0,
        initiatorBalanceSat: (json['initiator_balance_sat'] as num?)?.toInt() ?? 0,
        peerBalanceSat: (json['peer_balance_sat'] as num?)?.toInt() ?? 0,
      );
}

/// Response to a cooperative close (rest.go cooperativeClose).
class CloseResp {
  final bool accepted;
  final String? rejectReason;
  final String? settlementTxid; // present when L1 settlement enqueued

  const CloseResp({
    required this.accepted,
    this.rejectReason,
    this.settlementTxid,
  });

  factory CloseResp.fromJson(Map<String, dynamic> json) => CloseResp(
        accepted: json['accepted'] as bool? ?? false,
        rejectReason: json['reject_reason'] as String?,
        settlementTxid: json['settlement_txid'] as String?,
      );
}

/// Per-tower entry in the LSP's watchtower-health proxy (one per armed tower).
class TowerProxyEntry {
  final String name; // e.g. "eLTOOwatchtower" | "monitoring-vps"
  final bool available;
  final String? error;
  final TowerStatusDetail? status;

  const TowerProxyEntry({
    required this.name,
    required this.available,
    this.error,
    this.status,
  });

  factory TowerProxyEntry.fromJson(Map<String, dynamic> json) => TowerProxyEntry(
        name: json['name'] as String? ?? '',
        available: json['available'] as bool? ?? false,
        error: json['error'] as String?,
        status: json['status'] is Map<String, dynamic>
            ? TowerStatusDetail.fromJson(json['status'] as Map<String, dynamic>)
            : null,
      );
}

/// Detail block inside a [TowerProxyEntry].
class TowerStatusDetail {
  final int watchedChannels;
  final int totalChecks;
  final int totalTriggers; // >0 means the tower has had to supersede a stale state
  final String lastCheck;
  final String pollInterval;
  final int slaBlocks;

  const TowerStatusDetail({
    required this.watchedChannels,
    required this.totalChecks,
    required this.totalTriggers,
    required this.lastCheck,
    required this.pollInterval,
    required this.slaBlocks,
  });

  factory TowerStatusDetail.fromJson(Map<String, dynamic> json) => TowerStatusDetail(
        watchedChannels: (json['watched_channels'] as num?)?.toInt() ?? 0,
        totalChecks: (json['total_checks'] as num?)?.toInt() ?? 0,
        totalTriggers: (json['total_triggers'] as num?)?.toInt() ?? 0,
        lastCheck: json['last_check'] as String? ?? '',
        pollInterval: json['poll_interval'] as String? ?? '',
        slaBlocks: (json['sla_blocks'] as num?)?.toInt() ?? 0,
      );
}

/// The LSP's aggregated watchtower-health view (/v1/tower/status).
class TowerProxyStatus {
  final bool available; // at least one tower reachable
  final int towerCount;
  final List<TowerProxyEntry> towers;

  const TowerProxyStatus({
    required this.available,
    required this.towerCount,
    required this.towers,
  });

  /// Number of towers currently reachable.
  int get reachable => towers.where((t) => t.available).length;

  factory TowerProxyStatus.fromJson(Map<String, dynamic> json) => TowerProxyStatus(
        available: json['available'] as bool? ?? false,
        towerCount: (json['tower_count'] as num?)?.toInt() ?? 0,
        towers: (json['towers'] as List<dynamic>? ?? const [])
            .map((t) => TowerProxyEntry.fromJson(t as Map<String, dynamic>))
            .toList(),
      );
}
