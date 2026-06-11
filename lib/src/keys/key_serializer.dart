import 'dart:typed_data';
import 'dart:convert';
import '../models/wallet_keys.dart';

/// Serialization/deserialization for wallet keys and seed phrases.
///
/// Handles secure export/import of wallet data for backup and restore.
class KeySerializer {
  /// Serialize a [SeedPhrase] to JSON.
  String serializeSeedPhrase(SeedPhrase phrase) {
    return jsonEncode({'words': phrase.words});
  }

  /// Deserialize a [SeedPhrase] from JSON.
  SeedPhrase deserializeSeedPhrase(String json) {
    final map = jsonDecode(json) as Map<String, dynamic>;
    final words = (map['words'] as List).cast<String>();
    return SeedPhrase(words: words);
  }

  /// Serialize a public key to hex string.
  String publicKeyToHex(Uint8List publicKey) {
    return publicKey.map((b) => b.toRadixString(16).padLeft(2, '0')).join();
  }

  /// Deserialize a public key from hex string.
  Uint8List publicKeyFromHex(String hex) {
    final bytes = <int>[];
    for (var i = 0; i < hex.length; i += 2) {
      bytes.add(int.parse(hex.substring(i, i + 2), radix: 16));
    }
    return Uint8List.fromList(bytes);
  }
}
