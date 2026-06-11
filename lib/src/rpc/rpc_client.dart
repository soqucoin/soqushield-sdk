import 'dart:convert';
import 'package:dio/dio.dart';
import 'rpc_models.dart';

/// Typed JSON-RPC client for the Soqucoin node.
///
/// Wraps the standard Bitcoin-derived JSON-RPC interface with
/// type-safe methods for common operations.
///
/// ```dart
/// final rpc = SoqRpcClient(
///   url: 'http://127.0.0.1:22556',
///   username: 'rpcuser',
///   password: 'rpcpassword',
/// );
///
/// final info = await rpc.getBlockchainInfo();
/// print('Block height: ${info.blocks}');
/// ```
class SoqRpcClient {
  final String url;
  final String? username;
  final String? password;
  final Dio _dio;
  int _requestId = 0;

  SoqRpcClient({
    required this.url,
    this.username,
    this.password,
    Dio? dio,
  }) : _dio = dio ?? Dio() {
    if (username != null && password != null) {
      final auth = base64Encode(utf8.encode('$username:$password'));
      _dio.options.headers['Authorization'] = 'Basic $auth';
    }
    _dio.options.headers['Content-Type'] = 'application/json';
  }

  /// Raw JSON-RPC call.
  Future<dynamic> call(String method, [List<dynamic>? params]) async {
    final id = ++_requestId;
    final body = {
      'jsonrpc': '1.0',
      'id': id,
      'method': method,
      'params': params ?? [],
    };

    final response = await _dio.post(url, data: jsonEncode(body));
    final result = response.data;

    if (result is String) {
      final decoded = jsonDecode(result);
      if (decoded['error'] != null) {
        throw RpcException(decoded['error']['message'] ?? 'Unknown RPC error');
      }
      return decoded['result'];
    }

    if (result['error'] != null) {
      throw RpcException(result['error']['message'] ?? 'Unknown RPC error');
    }
    return result['result'];
  }

  // ─── Blockchain ───

  /// Get blockchain info (chain, height, difficulty, etc.).
  Future<BlockchainInfo> getBlockchainInfo() async {
    final result = await call('getblockchaininfo');
    return BlockchainInfo.fromJson(result);
  }

  /// Get current block count.
  Future<int> getBlockCount() async => await call('getblockcount') as int;

  /// Get best block hash.
  Future<String> getBestBlockHash() async => await call('getbestblockhash') as String;

  // ─── Wallet ───

  /// Get balance for the default wallet or a specific address.
  Future<double> getBalance([String? address]) async {
    if (address != null) {
      // Use listunspent to sum UTXOs for a specific address
      final utxos = await listUnspent(addresses: [address]);
      return utxos.fold<double>(0, (sum, u) => sum + u.amount);
    }
    final result = await call('getbalance');
    return (result as num).toDouble();
  }

  /// List unspent transaction outputs.
  Future<List<RpcUtxo>> listUnspent({
    int minConf = 1,
    int maxConf = 9999999,
    List<String>? addresses,
  }) async {
    final result = await call('listunspent', [minConf, maxConf, addresses ?? []]);
    return (result as List).map((u) => RpcUtxo.fromJson(u)).toList();
  }

  /// Send to a Soqucoin address.
  Future<String> sendToAddress(String address, double amount) async {
    final result = await call('sendtoaddress', [address, amount]);
    return result as String;
  }

  /// Validate a Soqucoin address.
  Future<Map<String, dynamic>> validateAddress(String address) async {
    final result = await call('validateaddress', [address]);
    return result as Map<String, dynamic>;
  }

  // ─── Raw Transactions ───

  /// Get raw transaction as hex or decoded JSON.
  Future<dynamic> getRawTransaction(String txid, {bool verbose = true}) async {
    return await call('getrawtransaction', [txid, verbose ? 1 : 0]);
  }

  /// Send a signed raw transaction.
  Future<String> sendRawTransaction(String hex) async {
    return await call('sendrawtransaction', [hex]) as String;
  }

  /// Create a raw transaction.
  Future<String> createRawTransaction(
    List<Map<String, dynamic>> inputs,
    Map<String, dynamic> outputs,
  ) async {
    return await call('createrawtransaction', [inputs, outputs]) as String;
  }
}

/// Exception thrown by RPC calls.
class RpcException implements Exception {
  final String message;
  RpcException(this.message);
  @override
  String toString() => 'RpcException: $message';
}
