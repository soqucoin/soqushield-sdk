// Copyright (c) 2026 Soqucoin Labs Inc.
// Distributed under the MIT software license.
//
// lsp_client.dart — REST transport for the Soqucoin Lightning LSP gateway.
//
// Ported from soq-lightning-sdk/src/client.ts. The LSP fronts the soq-lightning-peer at
// https://lsp.soqu.org (valid Let's Encrypt TLS as of 2026-06-24 — no NODE_TLS hack).
// We parse responses as plain text then JSON-decode ourselves so non-JSON bodies (e.g. a
// 404 returning text) surface as a clean [LspError] rather than a Dio decode failure —
// mirroring the TS req() helper exactly.

import 'dart:convert';
import 'package:dio/dio.dart';
import 'lsp_models.dart';

/// Raised for any non-2xx LSP response or a non-JSON body where JSON was expected.
class LspError implements Exception {
  final int status;
  final String message;
  final Object? body;

  LspError(this.status, this.message, [this.body]);

  @override
  String toString() => 'LspError $status: $message';
}

/// Thin typed REST client for the LSP. One instance per [baseUrl].
class LspClient {
  final String baseUrl;
  final Dio _dio;

  LspClient({required String baseUrl, Dio? dio})
      : baseUrl = _stripTrailingSlash(baseUrl),
        _dio = dio ?? Dio() {
    // We own status handling (mirror of res.ok in the TS client): never let Dio throw on
    // a 4xx/5xx, and never let it auto-decode — we read text and parse to control errors.
    _dio.options
      ..validateStatus = ((_) => true)
      ..responseType = ResponseType.plain
      ..headers['accept'] = 'application/json';
  }

  static String _stripTrailingSlash(String s) =>
      s.endsWith('/') ? s.substring(0, s.length - 1) : s;

  /// Issue a request and parse the JSON body, raising [LspError] on a non-2xx status or a
  /// body that should be JSON but is not.
  Future<dynamic> _req(String method, String path, [Object? body]) async {
    final res = await _dio.request<String>(
      '$baseUrl$path',
      data: body == null ? null : jsonEncode(body),
      options: Options(
        method: method,
        headers: body == null ? null : {'content-type': 'application/json'},
      ),
    );

    final text = res.data ?? '';
    final status = res.statusCode ?? 0;

    dynamic json;
    if (text.isNotEmpty) {
      try {
        json = jsonDecode(text);
      } catch (_) {
        json = null; // some endpoints (e.g. 404) return plain text, not JSON
      }
    }

    final ok = status >= 200 && status < 300;
    if (!ok) {
      final msg = (json is Map)
          ? (json['error'] ?? json['reject_reason'] ?? text).toString().trim()
          : text.trim();
      throw LspError(status, msg, json ?? text);
    }
    if (json == null) {
      final snippet = text.length > 80 ? text.substring(0, 80) : text;
      throw LspError(status, 'non-JSON body: $snippet', text);
    }
    return json;
  }

  Future<Map<String, dynamic>> _reqMap(String method, String path, [Object? body]) async =>
      (await _req(method, path, body)) as Map<String, dynamic>;

  // ─── Health / identity ───

  /// LSP liveness — `{ status: "ok", ... }` when the peer + its node backend are healthy.
  Future<Map<String, dynamic>> health() => _reqMap('GET', '/v1/health');

  /// LSP identity/capabilities — peer name, version, network, fee policy, `max_channel_sat`.
  Future<Map<String, dynamic>> info() => _reqMap('GET', '/v1/info');

  // ─── Faucet ───

  Future<Map<String, dynamic>> faucetStatus() => _reqMap('GET', '/v1/faucet');

  /// POST /v1/faucet drips test SOQ AND (default) auto-opens a channel.
  Future<FaucetResp> faucetDrip(FaucetReq req) async =>
      FaucetResp.fromJson(await _reqMap('POST', '/v1/faucet', req.toJson()));

  // ─── Channels ───

  Future<OpenChannelResp> openChannel(OpenChannelReq req) async =>
      OpenChannelResp.fromJson(await _reqMap('POST', '/v1/channels', req.toJson()));

  Future<List<LnChannel>> listChannels() async {
    final m = await _reqMap('GET', '/v1/channels');
    final list = (m['channels'] as List<dynamic>? ?? const []);
    return list.map((c) => LnChannel.fromJson(c as Map<String, dynamic>)).toList();
  }

  Future<LnChannel> getChannel(String id) async =>
      LnChannel.fromJson(await _reqMap('GET', '/v1/channels/$id'));

  Future<UpdateStateResp> updateState(String id, UpdateStateReq req) async =>
      UpdateStateResp.fromJson(
          await _reqMap('POST', '/v1/channels/$id/update', req.toJson()));

  Future<CloseResp> closeChannel(String id) async =>
      CloseResp.fromJson(await _reqMap('POST', '/v1/channels/$id/close'));

  // ─── Diagnostics ───

  Future<Map<String, dynamic>> dashboard() => _reqMap('GET', '/v1/dashboard');

  Future<Map<String, dynamic>> channelHealth() => _reqMap('GET', '/v1/channels/health');

  /// Watchtower health, proxied through the LSP (the towers are firewalled internal-only).
  Future<TowerProxyStatus> towerStatus() async =>
      TowerProxyStatus.fromJson(await _reqMap('GET', '/v1/tower/status'));
}
