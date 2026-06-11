import 'dart:typed_data';
import 'dilithium/dilithium_native.dart';
import 'keys/key_generator.dart';
import 'models/wallet_keys.dart';

/// High-level wallet interface for Soqucoin.
///
/// Provides a simple API for generating wallets, signing transactions,
/// and verifying signatures using ML-DSA-44 post-quantum cryptography.
///
/// ```dart
/// // Generate a new wallet
/// final wallet = await SoqWallet.generate();
/// print('Address: ${wallet.address}');
/// print('Mnemonic: ${wallet.mnemonic}');
///
/// // Restore from mnemonic
/// final restored = await SoqWallet.fromMnemonic('word1 word2 ... word24');
/// ```
class SoqWallet {
  final WalletKeys keys;
  final SeedPhrase _seedPhrase;
  final int _accountIndex;

  SoqWallet._({
    required this.keys,
    required SeedPhrase seedPhrase,
    required int accountIndex,
  })  : _seedPhrase = seedPhrase,
        _accountIndex = accountIndex;

  /// The wallet's Bech32m address.
  String get address => keys.address;

  /// The wallet's mnemonic seed phrase (24 words).
  String get mnemonic => _seedPhrase.mnemonic;

  /// The wallet's public key (1312 bytes).
  Uint8List get publicKey => keys.publicKey;

  /// Generate a new wallet with a fresh mnemonic.
  static Future<SoqWallet> generate({
    SoqNetwork network = SoqNetwork.stagenet,
    int accountIndex = 0,
  }) async {
    final keyGen = KeyGenerator();
    final phrase = keyGen.generateMnemonic();
    final keys = await keyGen.deriveFromMnemonic(
      phrase,
      network: network,
      accountIndex: accountIndex,
    );
    return SoqWallet._(
      keys: keys,
      seedPhrase: phrase,
      accountIndex: accountIndex,
    );
  }

  /// Restore a wallet from a mnemonic seed phrase.
  static Future<SoqWallet> fromMnemonic(
    String mnemonic, {
    SoqNetwork network = SoqNetwork.stagenet,
    int accountIndex = 0,
    String passphrase = '',
  }) async {
    final phrase = SeedPhrase(words: mnemonic.split(' '));
    final keyGen = KeyGenerator();
    if (!keyGen.validateMnemonic(mnemonic)) {
      throw ArgumentError('Invalid mnemonic seed phrase');
    }
    final keys = await keyGen.deriveFromMnemonic(
      phrase,
      network: network,
      accountIndex: accountIndex,
      passphrase: passphrase,
    );
    return SoqWallet._(
      keys: keys,
      seedPhrase: phrase,
      accountIndex: accountIndex,
    );
  }

  /// Sign a message using ML-DSA-44.
  ///
  /// Returns a 2420-byte signature.
  /// ⚠️ This derives the secret key in memory, signs, then discards it.
  Future<Uint8List> sign(Uint8List message) async {
    final keyGen = KeyGenerator();
    final (_, secretKey) = await keyGen.deriveNativeKeyPair(
      _seedPhrase,
      accountIndex: _accountIndex,
    );

    try {
      return DilithiumNative.instance.sign(message, secretKey);
    } finally {
      // Zeroize secret key
      for (var i = 0; i < secretKey.length; i++) {
        secretKey[i] = 0;
      }
    }
  }

  /// Verify a signature against this wallet's public key.
  bool verify(Uint8List signature, Uint8List message) {
    return DilithiumNative.instance.verify(signature, message, keys.publicKey);
  }
}
