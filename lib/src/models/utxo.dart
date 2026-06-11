

/// Asset type for multi-asset UTXO model.
/// Matches consensus-level nAssetType in CTxOut.
enum AssetType {
  soq,     // 0x00 — native SOQ
  usdsoq,  // 0x01 — USDSOQ stablecoin
}

/// UTXO visibility.
/// Matches consensus-level nVisibility in CTxOut.
enum UtxoVisibility {
  transparent,   // 0x00 — visible on-chain
  confidential,  // 0x01 — Lattice-BP++ hidden amount
}

/// A single Unspent Transaction Output (UTXO).
class Utxo {
  /// Transaction ID that created this output
  final String txid;

  /// Output index within the transaction
  final int vout;

  /// Value in SOQ/USDSOQ (whole coins, not satoshis)
  final double value;

  /// Value in koinu (smallest unit — 1 SOQ = 100,000,000 koinu)
  final int valueSat;

  /// The scriptPubKey hex
  final String scriptPubKey;

  /// Address this UTXO belongs to
  final String address;

  /// Block height where this was confirmed (0 = unconfirmed/mempool)
  final int height;

  /// Number of confirmations
  final int confirmations;

  /// Whether this UTXO has been spent in a pending transaction
  final bool locked;

  /// Asset type: SOQ or USDSOQ (nAssetType from CTxOut)
  final AssetType assetType;

  /// Visibility: transparent or confidential (nVisibility from CTxOut)
  final UtxoVisibility visibility;

  const Utxo({
    required this.txid,
    required this.vout,
    required this.value,
    required this.valueSat,
    required this.scriptPubKey,
    required this.address,
    this.height = 0,
    this.confirmations = 0,
    this.locked = false,
    this.assetType = AssetType.soq,
    this.visibility = UtxoVisibility.transparent,
  });

  /// Create from gettxout RPC response.
  factory Utxo.fromTxOut(String txid, int vout, Map<String, dynamic> data) {
    final spk = data['scriptPubKey'] as Map<String, dynamic>? ?? {};
    final addresses = spk['addresses'] as List<dynamic>? ?? [];
    final value = (data['value'] as num?)?.toDouble() ?? 0.0;

    return Utxo(
      txid: txid,
      vout: vout,
      value: value,
      valueSat: (value * 100000000).round(),
      scriptPubKey: spk['hex'] as String? ?? '',
      address: addresses.isNotEmpty ? addresses[0] as String : '',
      confirmations: data['confirmations'] as int? ?? 0,
      assetType: _parseAssetType(data['assetType'] as int?),
      visibility: _parseVisibility(data['visibility'] as int?),
    );
  }

  /// Create from a decoded raw transaction vout.
  factory Utxo.fromVout(String txid, int voutIndex, Map<String, dynamic> vout,
      {int confirmations = 0}) {
    final spk = vout['scriptPubKey'] as Map<String, dynamic>? ?? {};
    final addresses = spk['addresses'] as List<dynamic>? ?? [];
    final value = (vout['value'] as num?)?.toDouble() ?? 0.0;

    return Utxo(
      txid: txid,
      vout: voutIndex,
      value: value,
      valueSat: (value * 100000000).round(),
      scriptPubKey: spk['hex'] as String? ?? '',
      address: addresses.isNotEmpty ? addresses[0] as String : '',
      confirmations: confirmations,
      assetType: _parseAssetType(vout['assetType'] as int?),
      visibility: _parseVisibility(vout['visibility'] as int?),
    );
  }

  /// Total value of a list of UTXOs (filtered by asset type).
  static double totalValue(List<Utxo> utxos, {AssetType? asset}) {
    final filtered = asset == null ? utxos : utxos.where((u) => u.assetType == asset);
    return filtered.fold(0.0, (sum, u) => sum + u.value);
  }

  /// Total koinu value of a list of UTXOs (filtered by asset type).
  static int totalValueSat(List<Utxo> utxos, {AssetType? asset}) {
    final filtered = asset == null ? utxos : utxos.where((u) => u.assetType == asset);
    return filtered.fold(0, (sum, u) => sum + u.valueSat);
  }

  /// Whether this is a SOQ UTXO.
  bool get isSoq => assetType == AssetType.soq;

  /// Whether this is a USDSOQ UTXO.
  bool get isUsdsoq => assetType == AssetType.usdsoq;

  /// Whether this is a confidential (shielded) UTXO.
  bool get isConfidential => visibility == UtxoVisibility.confidential;

  /// Outpoint string (txid:vout).
  String get outpoint => '$txid:$vout';

  /// Serialize to JSON for local persistence.
  Map<String, dynamic> toJson() => {
        'txid': txid,
        'vout': vout,
        'value': value,
        'valueSat': valueSat,
        'scriptPubKey': scriptPubKey,
        'address': address,
        'height': height,
        'confirmations': confirmations,
        'locked': locked,
        'assetType': assetType.index,
        'visibility': visibility.index,
      };

  /// Deserialize from JSON.
  factory Utxo.fromJson(Map<String, dynamic> json) => Utxo(
        txid: json['txid'] as String,
        vout: json['vout'] as int,
        value: (json['value'] as num).toDouble(),
        valueSat: json['valueSat'] as int,
        scriptPubKey: json['scriptPubKey'] as String,
        address: json['address'] as String,
        height: json['height'] as int? ?? 0,
        confirmations: json['confirmations'] as int? ?? 0,
        locked: json['locked'] as bool? ?? false,
        assetType: _parseAssetType(json['assetType'] as int?),
        visibility: _parseVisibility(json['visibility'] as int?),
      );

  Utxo copyWith({bool? locked, int? confirmations, AssetType? assetType}) => Utxo(
        txid: txid,
        vout: vout,
        value: value,
        valueSat: valueSat,
        scriptPubKey: scriptPubKey,
        address: address,
        height: height,
        confirmations: confirmations ?? this.confirmations,
        locked: locked ?? this.locked,
        assetType: assetType ?? this.assetType,
        visibility: visibility,
      );

  @override
  bool operator ==(Object other) =>
      identical(this, other) ||
      other is Utxo && txid == other.txid && vout == other.vout;

  @override
  int get hashCode => Object.hash(txid, vout);

  @override
  String toString() {
    final asset = assetType == AssetType.usdsoq ? 'USDSOQ' : 'SOQ';
    final vis = isConfidential ? ' [shielded]' : '';
    return 'Utxo($outpoint, $value $asset$vis)';
  }
}

// ── Parsing helpers ──

AssetType _parseAssetType(int? raw) => switch (raw) {
  1 => AssetType.usdsoq,
  _ => AssetType.soq,
};

UtxoVisibility _parseVisibility(int? raw) => switch (raw) {
  1 => UtxoVisibility.confidential,
  _ => UtxoVisibility.transparent,
};
