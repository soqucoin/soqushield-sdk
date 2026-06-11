# SoquShield SDK

Post-quantum cryptographic primitives for the Soqucoin blockchain.

Built by [Soqucoin Labs Inc.](https://soqu.org)

## Overview

The SoquShield SDK exposes the same ML-DSA-44 (FIPS 204 Dilithium) cryptographic engine used by the SoquShield wallet and the Soqucoin full node. This means signatures produced by the SDK verify on the node, and vice versa — byte-for-byte compatibility.

## Features

- **ML-DSA-44 (Dilithium)** — NIST FIPS 204 key generation, signing, and verification via native C FFI
- **Key Derivation** — BIP-39 mnemonic → HKDF-SHA256 → Dilithium seed (Halborn-audited derivation chain)
- **Address Codec** — Bech32m encoding/decoding for Soqucoin mainnet and testnet addresses
- **RPC Client** — Typed JSON-RPC client for the Soqucoin node
- **Vault Bridge** — pSOQ↔SOQ cross-chain bridge operations (coming soon)
- **Pure Dart** — No Flutter dependency. Works on iOS, Android, macOS, Linux, Windows, and web.

## Quick Start

```dart
import 'package:soqushield_sdk/soqushield_sdk.dart';

void main() async {
  // Generate a new post-quantum wallet
  final wallet = await SoqWallet.generate(network: SoqNetwork.stagenet);
  print('Address: ${wallet.address}');
  print('Mnemonic: ${wallet.mnemonic}');

  // Sign a transaction hash
  final txHash = Uint8List(32); // Your SHA256d sighash
  final signature = await wallet.sign(txHash);
  print('Signature: ${signature.length} bytes'); // 2420

  // Verify
  final valid = wallet.verify(signature, txHash);
  print('Valid: $valid'); // true
}
```

## Architecture

```
┌─────────────────────────────────────────┐
│           SoqWallet (high-level)        │
├────────────┬───────────┬────────────────┤
│ KeyGenerator│ AddressCodec│ SoqRpcClient │
├────────────┴───────────┴────────────────┤
│        DilithiumNative (C FFI)          │
├─────────────────────────────────────────┤
│   Native ML-DSA-44 C Library            │
│   (same source as soqucoin-build)       │
└─────────────────────────────────────────┘
```

## Key Sizes

| Component | Size |
|-----------|------|
| Public Key | 1,312 bytes |
| Secret Key | 2,560 bytes |
| Signature | 2,420 bytes |
| Seed | 32 bytes |
| Address | ~62 chars (Bech32m) |

## Security

- Uses NIST FIPS 204 ML-DSA-44 — a standardized post-quantum digital signature algorithm
- Native C implementation matches the Soqucoin full node byte-for-byte
- Secret keys are zeroized after use
- Key derivation is Halborn-audited (pqderive.cpp)
- **⚠️ NEVER use Ed25519/ECDSA for bridge signing — ML-DSA-44 only**

## License

Copyright © 2026 Soqucoin Labs Inc. All rights reserved.

Patent: SOQ-P003 (Pure-Dart ML-DSA Mobile Wallet)
