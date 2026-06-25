// Copyright (c) 2026 Soqucoin Labs Inc.
// Distributed under the MIT software license.
//
// lightning_test.dart — unit tests for the Dart Lightning SDK port (Opt2 foundation).
//
// Drives the SoqLightning facade against a stateful in-memory fake LSP wired through a mock
// Dio adapter. Covers the full open→pay→close lifecycle plus every invariant branch the
// live stagenet smoke test (2026-06-24) proved: faucet-cap clamp, balance conservation,
// monotonic state advance, dropped-close resilience, watchtower liveness, LspError mapping,
// and the placeholder TX builder seam.

import 'dart:async';
import 'dart:convert';
import 'dart:typed_data';

import 'package:dio/dio.dart';
import 'package:soqushield_sdk/soqushield_sdk.dart';
import 'package:test/test.dart';

// ─── Stateful fake LSP ───

/// A minimal in-memory model of the soq-lightning-peer REST API, enough to exercise the
/// facade end to end. Flags toggle the failure modes we want to assert on.
class FakeLsp {
  final int maxChannelSat;

  /// When true, the faucet declines to open a channel for amount > [faucetHonorSat] but still
  /// reports success with no channel_id — the live silent-decline behaviour. The point of a
  /// separate honor cap is the real bug: the faucet honors LESS than info() advertises, so
  /// clamping to the advertised cap isn't enough.
  final bool faucetSilentDecline;

  /// The capacity the faucet will actually open a channel for (defaults to [maxChannelSat]).
  final int faucetHonorSat;

  /// When true, `update` accepts but does not advance the state index.
  bool freezeState;

  /// When true, `update` corrupts the peer balance so conservation breaks.
  bool corruptConservation;

  /// When true, `close` marks the channel closed but throws a transport error (dropped
  /// response) — exercises the close() resilience path.
  bool closeDropsResponse;

  final Map<String, Map<String, dynamic>> channels = {};
  int _seq = 0;

  /// The most recent update request body seen (for asserting the placeholder TX seam).
  Map<String, dynamic>? lastUpdate;

  FakeLsp({
    this.maxChannelSat = 100000000, // 1 SOQ
    this.faucetSilentDecline = false,
    int? faucetHonorSat,
    this.freezeState = false,
    this.corruptConservation = false,
    this.closeDropsResponse = false,
  }) : faucetHonorSat = faucetHonorSat ?? maxChannelSat;

  Map<String, dynamic> _newChannel(int capacity, String pk, String addr) {
    final id = 'ch_${++_seq}';
    final ch = {
      'channel_id': id,
      'initiator_pub_key_hex': pk,
      'peer_pub_key_hex': 'peerpk',
      'capacity_sat': capacity,
      'initiator_balance_sat': capacity,
      'peer_balance_sat': 0,
      'state_index': 0,
      'state': 'open',
      'csv_delay': 288,
      'created_at_unix': 1700000000,
    };
    channels[id] = ch;
    return ch;
  }

  /// Route a request → (status, json-encoded body). Throws a DioException to simulate a
  /// transport error where noted.
  ({int status, String body}) route(RequestOptions o) {
    final method = o.method.toUpperCase();
    final path = Uri.parse(o.path).path;
    final body = o.data is String && (o.data as String).isNotEmpty
        ? jsonDecode(o.data as String) as Map<String, dynamic>
        : <String, dynamic>{};

    String j(Object? v) => jsonEncode(v);

    if (method == 'GET' && path.endsWith('/v1/info')) {
      return (status: 200, body: j({'peer_name': 'fake', 'max_channel_sat': maxChannelSat}));
    }
    if (method == 'GET' && path.endsWith('/v1/health')) {
      return (status: 200, body: j({'status': 'ok'}));
    }
    if (method == 'POST' && path.endsWith('/v1/faucet')) {
      final amount = (body['amount_sat'] as num).toInt();
      if (faucetSilentDecline && amount > faucetHonorSat) {
        return (status: 200, body: j({'success': true, 'txid': 'tx_drip', 'amount_sat': amount}));
      }
      final ch = _newChannel(amount, body['pub_key_hex'] as String? ?? 'pk',
          body['address'] as String? ?? 'addr');
      return (
        status: 200,
        body: j({'success': true, 'txid': 'tx_drip', 'amount_sat': amount, 'channel_id': ch['channel_id']})
      );
    }
    if (method == 'POST' && path.endsWith('/v1/channels')) {
      final cap = (body['capacity_sat'] as num).toInt();
      if (cap > maxChannelSat) {
        return (status: 200, body: j({'accepted': false, 'reject_reason': 'capacity exceeds max'}));
      }
      final ch = _newChannel(cap, body['initiator_pub_key_hex'] as String? ?? 'pk',
          body['initiator_address'] as String? ?? 'addr');
      return (status: 200, body: j({'accepted': true, 'channel_id': ch['channel_id']}));
    }

    // /v1/channels/{id}/...  and  /v1/channels/{id}
    final segs = path.split('/').where((s) => s.isNotEmpty).toList();
    final chIdx = segs.indexOf('channels');
    if (chIdx >= 0 && segs.length > chIdx + 1) {
      final id = segs[chIdx + 1];
      final ch = channels[id];
      if (ch == null) return (status: 404, body: 'not found');
      final action = segs.length > chIdx + 2 ? segs[chIdx + 2] : null;

      if (method == 'GET' && action == null) {
        return (status: 200, body: j(ch));
      }
      if (method == 'POST' && action == 'update') {
        lastUpdate = body;
        if (!freezeState) ch['state_index'] = (body['state_index'] as num).toInt();
        ch['initiator_balance_sat'] = (body['initiator_balance_sat'] as num).toInt();
        ch['peer_balance_sat'] = corruptConservation
            ? (body['peer_balance_sat'] as num).toInt() + 1 // break conservation
            : (body['peer_balance_sat'] as num).toInt();
        return (status: 200, body: j({'accepted': true, 'peer_signature_hex': 'sig'}));
      }
      if (method == 'POST' && action == 'close') {
        ch['state'] = 'closed';
        if (closeDropsResponse) {
          throw DioException(requestOptions: o, type: DioExceptionType.connectionError);
        }
        return (status: 200, body: j({'accepted': true, 'settlement_txid': 'tx_settle'}));
      }
    }

    if (method == 'GET' && path.endsWith('/v1/tower/status')) {
      return (
        status: 200,
        body: j({
          'available': true,
          'tower_count': 2,
          'towers': [
            {'name': 'eLTOOwatchtower', 'available': true},
            {'name': 'monitoring-vps', 'available': true},
          ],
        })
      );
    }

    return (status: 404, body: 'unhandled: $method $path');
  }
}

/// Dio adapter that routes every request through a [FakeLsp].
class FakeLspAdapter implements HttpClientAdapter {
  final FakeLsp lsp;
  FakeLspAdapter(this.lsp);

  @override
  Future<ResponseBody> fetch(
      RequestOptions options, Stream<Uint8List>? requestStream, Future<void>? cancelFuture) async {
    final r = lsp.route(options); // may throw DioException (transport error)
    return ResponseBody.fromString(
      r.body,
      r.status,
      headers: {
        Headers.contentTypeHeader: ['application/json'],
      },
    );
  }

  @override
  void close({bool force = false}) {}
}

SoqLightning ln(FakeLsp lsp, {WatchtowerArming? wt}) {
  final dio = Dio()..httpClientAdapter = FakeLspAdapter(lsp);
  return SoqLightning(baseUrl: 'https://lsp.test', dio: dio, watchtower: wt);
}

const _params = OpenChannelParams(
  pubKeyHex: 'aaaaaaaa',
  address: 'soq1qtest',
  capacitySat: 100000000,
);

void main() {
  group('SoqLightning facade — lifecycle', () {
    test('open → pay → close, conservation + state advance hold', () async {
      final lsp = FakeLsp();
      final sdk = ln(lsp);

      final ch = await sdk.openChannel(_params);
      expect(ch.isOpen, isTrue);
      expect(ch.initiatorBalanceSat, 100000000);
      expect(ch.peerBalanceSat, 0);
      expect(ch.stateIndex, 0);

      final after = await sdk.pay(ch.channelId, 20000000); // move 0.2 SOQ
      expect(after.stateIndex, 1);
      expect(after.initiatorBalanceSat, 80000000);
      expect(after.peerBalanceSat, 20000000);
      expect(after.initiatorBalanceSat + after.peerBalanceSat, after.capacitySat);

      final closed = await sdk.close(ch.channelId);
      expect(closed.accepted, isTrue);
      expect(closed.settlementTxid, 'tx_settle');
    });

    test('multiple pays advance state monotonically and conserve', () async {
      final lsp = FakeLsp();
      final sdk = ln(lsp);
      final ch = await sdk.openChannel(_params);
      var c = ch;
      for (var i = 1; i <= 3; i++) {
        c = await sdk.pay(ch.channelId, 10000000);
        expect(c.stateIndex, i);
        expect(c.initiatorBalanceSat + c.peerBalanceSat, c.capacitySat);
      }
      expect(c.peerBalanceSat, 30000000);
    });
  });

  group('fundAndOpen — faucet cap clamp', () {
    test('clamps an over-cap request down to max_channel_sat and opens', () async {
      final lsp = FakeLsp(maxChannelSat: 100000000); // 1 SOQ cap
      final sdk = ln(lsp);
      // Ask for 10 SOQ — must clamp to 1 SOQ and still open.
      final ch = await sdk.fundAndOpen(const OpenChannelParams(
        pubKeyHex: 'bb',
        address: 'soq1qx',
        capacitySat: 1000000000,
      ));
      expect(ch.isOpen, isTrue);
      expect(ch.capacitySat, 100000000);
    });

    test('throws a descriptive error when the faucet silently declines to open', () async {
      // info advertises a 10 SOQ cap, but the faucet only honours 1 SOQ → silent decline.
      // The SDK clamps to the advertised 1B (a no-op here), the faucet still declines.
      final lsp = FakeLsp(
          maxChannelSat: 1000000000, faucetHonorSat: 100000000, faucetSilentDecline: true);
      final sdk = ln(lsp);
      expect(
        () => sdk.fundAndOpen(const OpenChannelParams(
          pubKeyHex: 'bb',
          address: 'soq1qx',
          capacitySat: 1000000000,
        )),
        throwsA(isA<StateError>().having(
            (e) => e.message, 'message', contains('did not open a channel'))),
      );
    });
  });

  group('invariant guards', () {
    test('pay rejects a non-positive amount', () async {
      final sdk = ln(FakeLsp());
      final ch = await sdk.openChannel(_params);
      expect(() => sdk.pay(ch.channelId, 0), throwsA(isA<ArgumentError>()));
    });

    test('pay rejects an amount over the initiator balance', () async {
      final sdk = ln(FakeLsp());
      final ch = await sdk.openChannel(_params);
      expect(() => sdk.pay(ch.channelId, 200000000),
          throwsA(isA<StateError>().having((e) => e.message, 'm', contains('insufficient'))));
    });

    test('pay detects a broken conservation invariant', () async {
      final lsp = FakeLsp(corruptConservation: true);
      final sdk = ln(lsp);
      final ch = await sdk.openChannel(_params);
      expect(() => sdk.pay(ch.channelId, 10000000),
          throwsA(isA<StateError>().having((e) => e.message, 'm', contains('not conserved'))));
    });

    test('pay detects a non-advancing state index', () async {
      final lsp = FakeLsp(freezeState: true);
      final sdk = ln(lsp);
      final ch = await sdk.openChannel(_params);
      expect(() => sdk.pay(ch.channelId, 10000000),
          throwsA(isA<StateError>().having((e) => e.message, 'm', contains('did not advance'))));
    });
  });

  group('close resilience', () {
    test('treats a dropped response as success when the channel reads closed', () async {
      final lsp = FakeLsp(closeDropsResponse: true);
      final sdk = ln(lsp);
      final ch = await sdk.openChannel(_params);
      final closed = await sdk.close(ch.channelId);
      expect(closed.accepted, isTrue);
      expect(closed.rejectReason, contains('response dropped'));
    });
  });

  group('watchtower liveness', () {
    test('assertTowersHealthy passes with the dual-tower deployment', () async {
      final sdk = ln(FakeLsp());
      await sdk.assertTowersHealthy(2); // does not throw
      final status = await sdk.towerStatus();
      expect(status.reachable, 2);
    });

    test('assertTowersHealthy throws when coverage is degraded', () async {
      final sdk = ln(FakeLsp());
      expect(() => sdk.assertTowersHealthy(3),
          throwsA(isA<StateError>().having((e) => e.message, 'm', contains('degraded'))));
    });
  });

  group('transport', () {
    test('non-2xx maps to LspError with status + message', () async {
      final sdk = ln(FakeLsp());
      // Unknown channel → fake returns 404 "not found".
      expect(
        () => sdk.channel('ch_does_not_exist'),
        throwsA(isA<LspError>().having((e) => e.status, 'status', 404)),
      );
    });
  });

  group('swappable TX builder seam', () {
    test('default placeholder builder is sent in the update request', () async {
      final lsp = FakeLsp();
      final sdk = ln(lsp);
      final ch = await sdk.openChannel(_params);
      await sdk.pay(ch.channelId, 10000000);
      expect(lsp.lastUpdate, isNotNull);
      expect(lsp.lastUpdate!['update_tx_hex'], 'placeholder');
      expect(lsp.lastUpdate!['settlement_tx_hex'], 'placeholder');
      expect(lsp.lastUpdate!['ctv_hash'], 'placeholder');
    });

    test('a custom builder (Opt3 stand-in) flows through unchanged', () async {
      final lsp = FakeLsp();
      final dio = Dio()..httpClientAdapter = FakeLspAdapter(lsp);
      final sdk = SoqLightning(
        baseUrl: 'https://lsp.test',
        dio: dio,
        txBuilder: _RealishBuilder(),
      );
      final ch = await sdk.openChannel(_params);
      await sdk.pay(ch.channelId, 10000000);
      expect(lsp.lastUpdate!['update_tx_hex'], '0xUPDATE');
      expect(lsp.lastUpdate!['ctv_hash'], '0xCTV');
    });
  });
}

/// Stand-in for the Opt3 DilithiumEltooBuilder: proves a non-placeholder builder swaps in
/// with zero facade change.
class _RealishBuilder implements UpdateTxBuilder {
  @override
  Future<UpdateTx> build(UpdateContext ctx) async => const UpdateTx(
        updateTxHex: '0xUPDATE',
        settlementTxHex: '0xSETTLE',
        ctvHash: '0xCTV',
      );
}
