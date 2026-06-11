

/// A Soqucoin transaction (decoded or constructed).
class SoqTransaction {
  /// Transaction ID (double-SHA256)
  final String txid;

  /// Version (currently 1 or 2)
  final int version;

  /// Lock time
  final int lockTime;

  /// Input list
  final List<TxInput> inputs;

  /// Output list
  final List<TxOutput> outputs;

  /// Raw hex (for broadcast)
  final String? rawHex;

  /// Size in bytes
  final int? size;

  /// Virtual size
  final int? vsize;

  /// Block hash (null if unconfirmed)
  final String? blockHash;

  /// Confirmations (0 if unconfirmed)
  final int confirmations;

  /// Block time (epoch seconds)
  final int? time;

  const SoqTransaction({
    required this.txid,
    required this.version,
    required this.lockTime,
    required this.inputs,
    required this.outputs,
    this.rawHex,
    this.size,
    this.vsize,
    this.blockHash,
    this.confirmations = 0,
    this.time,
  });

  /// Total output value in koinu.
  int get totalOutputSat =>
      outputs.fold(0, (sum, o) => sum + o.valueSat);

  /// Total output value in SOQ.
  double get totalOutput =>
      outputs.fold(0.0, (sum, o) => sum + o.value);

  /// Parse from decoded RPC response.
  factory SoqTransaction.fromRpc(Map<String, dynamic> data) {
    final vins = (data['vin'] as List<dynamic>? ?? [])
        .map((v) => TxInput.fromRpc(v as Map<String, dynamic>))
        .toList();
    final vouts = (data['vout'] as List<dynamic>? ?? [])
        .map((v) => TxOutput.fromRpc(v as Map<String, dynamic>))
        .toList();

    return SoqTransaction(
      txid: data['txid'] as String? ?? '',
      version: data['version'] as int? ?? 1,
      lockTime: data['locktime'] as int? ?? 0,
      inputs: vins,
      outputs: vouts,
      rawHex: data['hex'] as String?,
      size: data['size'] as int?,
      vsize: data['vsize'] as int?,
      blockHash: data['blockhash'] as String?,
      confirmations: data['confirmations'] as int? ?? 0,
      time: data['time'] as int?,
    );
  }

  @override
  String toString() => 'SoqTransaction($txid, ${inputs.length} in, ${outputs.length} out)';
}

/// Transaction input.
class TxInput {
  /// Previous transaction ID
  final String txid;

  /// Previous output index
  final int vout;

  /// ScriptSig (unlock script)
  final String scriptSig;

  /// Sequence number
  final int sequence;

  /// Whether this is a coinbase input
  final bool isCoinbase;

  const TxInput({
    required this.txid,
    required this.vout,
    this.scriptSig = '',
    this.sequence = 0xFFFFFFFF,
    this.isCoinbase = false,
  });

  factory TxInput.fromRpc(Map<String, dynamic> data) {
    final coinbase = data['coinbase'] as String?;
    final scriptSig = data['scriptSig'] as Map<String, dynamic>?;

    return TxInput(
      txid: data['txid'] as String? ?? '0' * 64,
      vout: data['vout'] as int? ?? 0,
      scriptSig: scriptSig?['hex'] as String? ?? coinbase ?? '',
      sequence: data['sequence'] as int? ?? 0xFFFFFFFF,
      isCoinbase: coinbase != null,
    );
  }
}

/// Transaction output.
class TxOutput {
  /// Value in SOQ or USDSOQ
  final double value;

  /// Value in koinu (1 SOQ = 100,000,000 koinu)
  final int valueSat;

  /// Output index
  final int n;

  /// ScriptPubKey hex
  final String scriptPubKey;

  /// Script type (e.g. "pubkeyhash", "witness_v1_dilithium")
  final String scriptType;

  /// Destination addresses
  final List<String> addresses;

  /// Asset type: 0x00=SOQ, 0x01=USDSOQ (nAssetType from CTxOut)
  final int assetType;

  /// Visibility: 0x00=transparent, 0x01=confidential (nVisibility from CTxOut)
  final int visibility;

  const TxOutput({
    required this.value,
    required this.valueSat,
    required this.n,
    required this.scriptPubKey,
    this.scriptType = '',
    this.addresses = const [],
    this.assetType = 0,
    this.visibility = 0,
  });

  /// Whether this output carries USDSOQ.
  bool get isUsdsoq => assetType == 1;

  /// Whether this output is confidential (Lattice-BP++ hidden amount).
  bool get isConfidential => visibility == 1;

  factory TxOutput.fromRpc(Map<String, dynamic> data) {
    final spk = data['scriptPubKey'] as Map<String, dynamic>? ?? {};
    final value = (data['value'] as num?)?.toDouble() ?? 0.0;
    final addrs = (spk['addresses'] as List<dynamic>?)
            ?.map((a) => a as String)
            .toList() ??
        [];

    return TxOutput(
      value: value,
      valueSat: (value * 100000000).round(),
      n: data['n'] as int? ?? 0,
      scriptPubKey: spk['hex'] as String? ?? '',
      scriptType: spk['type'] as String? ?? '',
      addresses: addrs,
      assetType: data['assetType'] as int? ?? 0,
      visibility: data['visibility'] as int? ?? 0,
    );
  }
}

/// Fee estimation result.
class FeeEstimate {
  /// Fee rate in SOQ per kilobyte
  final double feePerKb;

  /// Estimated fee for a given transaction size (in koinu)
  final int estimatedFeeSat;

  /// Target confirmation blocks
  final int confTarget;

  const FeeEstimate({
    required this.feePerKb,
    required this.estimatedFeeSat,
    required this.confTarget,
  });

  /// Human-readable fee string.
  String get displayFee {
    final soq = estimatedFeeSat / 100000000;
    return '${soq.toStringAsFixed(4)} SOQ';
  }
}
