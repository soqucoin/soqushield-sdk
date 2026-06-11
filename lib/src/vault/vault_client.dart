/// Vault bridge client for pSOQ↔SOQ operations.
///
/// Handles the cross-chain bridge between Solana pSOQ tokens and
/// native SOQ. All bridge signing uses ML-DSA-44 — never Ed25519/ECDSA.
///
/// This is a stub for the initial SDK release. Full implementation
/// will be extracted from SoquShield's vault_bridge_service.dart.
class VaultClient {
  final String bridgeApiUrl;

  VaultClient({required this.bridgeApiUrl});

  /// Check bridge vault status.
  Future<Map<String, dynamic>> getVaultStatus() async {
    // TODO: Extract from vault_bridge_service.dart
    throw UnimplementedError('VaultClient.getVaultStatus not yet implemented');
  }

  /// Initiate a pSOQ→SOQ bridge transfer.
  Future<String> bridgeToNative({
    required String solanaAddress,
    required String soqAddress,
    required double amount,
  }) async {
    // TODO: Extract from vault_bridge_service.dart
    throw UnimplementedError('VaultClient.bridgeToNative not yet implemented');
  }

  /// Initiate a SOQ→pSOQ bridge transfer.
  Future<String> bridgeToSolana({
    required String soqAddress,
    required String solanaAddress,
    required double amount,
  }) async {
    // TODO: Extract from vault_bridge_service.dart
    throw UnimplementedError('VaultClient.bridgeToSolana not yet implemented');
  }
}
