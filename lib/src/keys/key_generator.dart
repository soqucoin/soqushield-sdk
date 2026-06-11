import 'dart:typed_data';
import 'package:bip39/bip39.dart' as bip39;
import 'package:hashlib/hashlib.dart';
import 'package:pointycastle/export.dart';
import '../dilithium/dilithium_native.dart' hide dilithiumPkBytes, dilithiumSkBytes, dilithiumSigBytes;
import '../dilithium/constants.dart';
import '../models/wallet_keys.dart';

/// Post-quantum key generation service.
///
/// Implements the Soqucoin key derivation pipeline:
///   BIP-39 mnemonic → PBKDF2 → 64-byte seed → HKDF-SHA256 → 32-byte Dilithium seed
///   → ML-DSA-44 keygen → 1312-byte pubkey → SHA-256 → 32-byte witness → Bech32m address
///
/// HKDF parameters match audited C++ pqderive.cpp (Halborn-reviewed):
///   Salt = SHA-256(masterSeed) — 256-bit pseudorandom (RFC 5869 §3.1)
///   Info = "soqucoin-pqwallet-v1" || PathToBytes(path) — domain-separated
///
/// Wire-compatible with soqucoin-build/src/wallet/pqwallet/pqderive.cpp
/// Patent: SOQ-P003 (Pure-Dart ML-DSA Mobile Wallet)
class KeyGenerator {
  /// Domain separator for wallet key derivation (Whitepaper §10.4)
  static const String _domainWallet = 'soqucoin-pqwallet-v1';

  /// Soqucoin BIP-44 coin type.
  static const int coinType = 21329;

  /// Generate a new 24-word BIP-39 mnemonic seed phrase.
  SeedPhrase generateMnemonic() {
    final mnemonic = bip39.generateMnemonic(strength: 256);
    return SeedPhrase(words: mnemonic.split(' '));
  }

  /// Validate a mnemonic seed phrase.
  bool validateMnemonic(String mnemonic) {
    return bip39.validateMnemonic(mnemonic);
  }

  /// Derive a wallet keypair from a mnemonic seed phrase.
  ///
  /// Returns [WalletKeys] containing the public key, address, and derivation path.
  /// The secret key is NOT included — use [deriveNativeKeyPair] for signing.
  Future<WalletKeys> deriveFromMnemonic(
    SeedPhrase phrase, {
    SoqNetwork network = SoqNetwork.stagenet,
    int accountIndex = 0,
    String passphrase = '',
  }) async {
    final masterSeed = bip39.mnemonicToSeed(phrase.mnemonic, passphrase: passphrase);
    final dilithiumSeed = _hkdfDerive(
      Uint8List.fromList(masterSeed),
      _buildDeriveInfo(accountIndex),
    );

    final native = DilithiumNative.instance;
    final (pubKeyBytes, _) = native.keypairFromSeed(dilithiumSeed);

    final address = deriveAddress(pubKeyBytes, network);
    final path = "m/44'/$coinType'/0'/0/$accountIndex";

    return WalletKeys(
      publicKey: pubKeyBytes,
      address: address,
      derivationPath: path,
      accountIndex: accountIndex,
      createdAt: DateTime.now(),
    );
  }

  /// Derive the native FIPS 204 key pair for transaction signing.
  ///
  /// Returns `(publicKey, secretKey)` as raw byte arrays.
  /// ⚠️ SECURITY: The returned secret key is 2560 bytes.
  /// Callers MUST NOT persist or log it.
  Future<(Uint8List publicKey, Uint8List secretKey)> deriveNativeKeyPair(
    SeedPhrase phrase, {
    int accountIndex = 0,
    String passphrase = '',
  }) async {
    final masterSeed = bip39.mnemonicToSeed(phrase.mnemonic, passphrase: passphrase);
    final dilithiumSeed = _hkdfDerive(
      Uint8List.fromList(masterSeed),
      _buildDeriveInfo(accountIndex),
    );

    final native = DilithiumNative.instance;
    return native.keypairFromSeed(dilithiumSeed);
  }

  /// Derive a Bech32m address from a Dilithium public key.
  ///
  /// Pipeline: pubkey (1312 bytes) → SHA-256 → 32-byte hash
  ///   → witness v1 (OP_1 <32-byte-hash>) → Bech32m encode
  String deriveAddress(Uint8List publicKey, SoqNetwork network) {
    assert(publicKey.length == dilithiumPkBytes,
      'Expected $dilithiumPkBytes byte public key, got ${publicKey.length}');

    final hash = sha256.convert(publicKey);
    final hashBytes = Uint8List.fromList(hash.bytes);
    return _encodeBech32m(hashBytes, network.hrp);
  }

  // ─── Private Helpers ───

  Uint8List _buildDeriveInfo(int accountIndex) {
    final domainBytes = Uint8List.fromList(_domainWallet.codeUnits);
    final pathBytesArr = _pathToBytes(44, coinType, 0, 0, accountIndex);
    final info = Uint8List(domainBytes.length + pathBytesArr.length);
    info.setRange(0, domainBytes.length, domainBytes);
    info.setRange(domainBytes.length, info.length, pathBytesArr);
    return info;
  }

  Uint8List _pathToBytes(int purpose, int coinType, int account, int change, int index) {
    final buf = Uint8List(20);
    final bd = ByteData.view(buf.buffer);
    bd.setUint32(0, (purpose | 0x80000000) & 0xFFFFFFFF);
    bd.setUint32(4, (coinType | 0x80000000) & 0xFFFFFFFF);
    bd.setUint32(8, (account | 0x80000000) & 0xFFFFFFFF);
    bd.setUint32(12, change);
    bd.setUint32(16, index);
    return buf;
  }

  Uint8List _hkdfDerive(Uint8List masterSeed, Uint8List info) {
    final saltHash = sha256.convert(masterSeed);
    final salt = Uint8List.fromList(saltHash.bytes);

    final hmacExtract = HMac(SHA256Digest(), 64)..init(KeyParameter(salt));
    final prk = Uint8List(32);
    hmacExtract.update(masterSeed, 0, masterSeed.length);
    hmacExtract.doFinal(prk, 0);

    final expandInput = Uint8List(info.length + 1);
    expandInput.setRange(0, info.length, info);
    expandInput[info.length] = 0x01;

    final hmacExpand = HMac(SHA256Digest(), 64)..init(KeyParameter(prk));
    final okm = Uint8List(32);
    hmacExpand.update(expandInput, 0, expandInput.length);
    hmacExpand.doFinal(okm, 0);

    return okm;
  }

  String _encodeBech32m(Uint8List witnessProgram, String hrp) {
    assert(witnessProgram.length == 32);
    final converted = <int>[pqWitnessVersion] + _convertBits(witnessProgram, 8, 5, true);
    return _bech32mEncode(hrp, converted);
  }

  List<int> _convertBits(Uint8List data, int fromBits, int toBits, bool pad) {
    int acc = 0;
    int bits = 0;
    final ret = <int>[];
    final maxv = (1 << toBits) - 1;
    for (final value in data) {
      acc = (acc << fromBits) | value;
      bits += fromBits;
      while (bits >= toBits) {
        bits -= toBits;
        ret.add((acc >> bits) & maxv);
      }
    }
    if (pad && bits > 0) {
      ret.add((acc << (toBits - bits)) & maxv);
    }
    return ret;
  }

  String _bech32mEncode(String hrp, List<int> data) {
    const bech32mConst = 0x2bc830a3;
    const charset = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l';
    final values = _bech32HrpExpand(hrp) + data;
    final polymod = _bech32Polymod(values + [0, 0, 0, 0, 0, 0]) ^ bech32mConst;
    final checksum = List<int>.generate(6, (i) => (polymod >> (5 * (5 - i))) & 31);
    final combined = data + checksum;
    return '$hrp${1}${combined.map((d) => charset[d]).join()}';
  }

  List<int> _bech32HrpExpand(String hrp) {
    final ret = <int>[];
    for (final c in hrp.codeUnits) { ret.add(c >> 5); }
    ret.add(0);
    for (final c in hrp.codeUnits) { ret.add(c & 31); }
    return ret;
  }

  int _bech32Polymod(List<int> values) {
    const gen = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];
    var chk = 1;
    for (final v in values) {
      final b = chk >> 25;
      chk = ((chk & 0x1ffffff) << 5) ^ v;
      for (var i = 0; i < 5; i++) {
        if ((b >> i) & 1 == 1) chk ^= gen[i];
      }
    }
    return chk;
  }
}
