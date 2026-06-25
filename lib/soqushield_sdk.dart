/// SoquShield SDK — Post-Quantum Cryptographic Primitives for Soqucoin.
///
/// This library provides the core building blocks for interacting with the
/// Soqucoin blockchain using NIST FIPS 204 ML-DSA-44 (Dilithium) post-quantum
/// cryptography.
///
/// ## Modules
///
/// - **Dilithium** — ML-DSA-44 key generation, signing, and verification
///   via native FFI to the Soqucoin node's exact C implementation.
/// - **Keys** — BIP-39 mnemonic seed generation, HKDF key derivation,
///   and secure key serialization.
/// - **Address** — Soqucoin Bech32m address encoding/decoding with PQ
///   witness program support.
/// - **RPC** — Typed client for the Soqucoin node JSON-RPC interface.
///
/// ## Quick Start
///
/// ```dart
/// import 'package:soqushield_sdk/soqushield_sdk.dart';
///
/// void main() {
///   // Generate a new wallet
///   final wallet = SoqWallet.generate();
///   print('Address: ${wallet.address}');
///   print('Mnemonic: ${wallet.mnemonic}');
///
///   // Sign a message
///   final signature = wallet.sign(Uint8List.fromList([1, 2, 3]));
///   final valid = wallet.verify(signature, Uint8List.fromList([1, 2, 3]));
///   print('Valid: $valid'); // true
/// }
/// ```
///
/// ## Security Notice
///
/// This SDK uses FIPS 204 ML-DSA-44, a NIST-standardized post-quantum
/// digital signature algorithm. All signing operations use the same C
/// implementation as the Soqucoin full node, ensuring byte-for-byte
/// compatibility.
///
/// **⚠️ NEVER use Ed25519/ECDSA for bridge signing — ML-DSA-44 only.**
library soqushield_sdk;

// Core types
export 'src/models/wallet_keys.dart';
export 'src/models/utxo.dart';
export 'src/models/transaction.dart';

// Dilithium (ML-DSA-44) cryptography
export 'src/dilithium/dilithium_native.dart' hide dilithiumPkBytes, dilithiumSkBytes, dilithiumSigBytes;
export 'src/dilithium/constants.dart';

// Key management
export 'src/keys/key_generator.dart';
export 'src/keys/key_serializer.dart';

// Address codec
export 'src/address/address_codec.dart';

// RPC client
export 'src/rpc/rpc_client.dart';
export 'src/rpc/rpc_models.dart' hide TxOutput;

// Lightning (eLTOO, quantum-safe) — LSP client + SoqLightning facade + swappable TX builder
export 'src/lightning/lightning.dart';

// High-level wallet
export 'src/wallet.dart';
