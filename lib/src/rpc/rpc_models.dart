/// RPC response models for the Soqucoin node JSON-RPC interface.

/// Represents a UTXO from listunspent.
class RpcUtxo {
  final String txid;
  final int vout;
  final String address;
  final double amount;
  final int confirmations;
  final String scriptPubKey;

  RpcUtxo({
    required this.txid,
    required this.vout,
    required this.address,
    required this.amount,
    required this.confirmations,
    required this.scriptPubKey,
  });

  factory RpcUtxo.fromJson(Map<String, dynamic> json) => RpcUtxo(
    txid: json['txid'] as String,
    vout: json['vout'] as int,
    address: json['address'] as String? ?? '',
    amount: (json['amount'] as num).toDouble(),
    confirmations: json['confirmations'] as int? ?? 0,
    scriptPubKey: json['scriptPubKey'] as String? ?? '',
  );
}

/// Represents block info from getblockchaininfo.
class BlockchainInfo {
  final String chain;
  final int blocks;
  final int headers;
  final String bestBlockHash;
  final double difficulty;

  BlockchainInfo({
    required this.chain,
    required this.blocks,
    required this.headers,
    required this.bestBlockHash,
    required this.difficulty,
  });

  factory BlockchainInfo.fromJson(Map<String, dynamic> json) => BlockchainInfo(
    chain: json['chain'] as String,
    blocks: json['blocks'] as int,
    headers: json['headers'] as int,
    bestBlockHash: json['bestblockhash'] as String,
    difficulty: (json['difficulty'] as num).toDouble(),
  );
}

/// Represents a raw transaction output.
class TxOutput {
  final double value;
  final int n;
  final Map<String, dynamic> scriptPubKey;

  TxOutput({required this.value, required this.n, required this.scriptPubKey});

  factory TxOutput.fromJson(Map<String, dynamic> json) => TxOutput(
    value: (json['value'] as num).toDouble(),
    n: json['n'] as int,
    scriptPubKey: json['scriptPubKey'] as Map<String, dynamic>,
  );
}
