/// Native Dilithium FFI bindings for SoquShield.
///
/// Provides a Dart interface to the Soqucoin node's exact FIPS 204 ML-DSA-44
/// C implementation. This ensures cryptographic compatibility — signatures
/// produced here verify on the node, and vice versa.
///
/// The underlying C library is compiled from the same source as the node
/// (src/crypto/dilithium/) and includes the FIPS 204 domain separation
/// (context prefix), 64-byte `tr`, and 64-byte CRH that the `dilithium_crypto`
/// Dart package does not implement.
library;

import 'dart:ffi';
import 'dart:io' show Platform;
import 'dart:typed_data';

/// ML-DSA-44 (FIPS 204) public key size in bytes.
const int dilithiumPkBytes = 1312;

/// ML-DSA-44 (FIPS 204) secret key size in bytes.
const int dilithiumSkBytes = 2560;

/// ML-DSA-44 (FIPS 204) signature size in bytes.
const int dilithiumSigBytes = 2420;

// ---- Native function typedefs ----

// int soq_dilithium_keypair_from_seed(uint8_t* pk, uint8_t* sk, const uint8_t* seed, int seed_len)
typedef _KeypairFromSeedC = Int32 Function(
    Pointer<Uint8> pk, Pointer<Uint8> sk, Pointer<Uint8> seed, Int32 seedLen);
typedef _KeypairFromSeedDart = int Function(
    Pointer<Uint8> pk, Pointer<Uint8> sk, Pointer<Uint8> seed, int seedLen);

// int soq_dilithium_sign(uint8_t* sig, size_t* siglen, const uint8_t* msg, size_t msglen, const uint8_t* sk)
typedef _SignC = Int32 Function(Pointer<Uint8> sig, Pointer<Size> siglen,
    Pointer<Uint8> msg, Size msglen, Pointer<Uint8> sk);
typedef _SignDart = int Function(Pointer<Uint8> sig, Pointer<Size> siglen,
    Pointer<Uint8> msg, int msglen, Pointer<Uint8> sk);

// int soq_dilithium_verify(const uint8_t* sig, size_t siglen, const uint8_t* msg, size_t msglen, const uint8_t* pk)
typedef _VerifyC = Int32 Function(Pointer<Uint8> sig, Size siglen,
    Pointer<Uint8> msg, Size msglen, Pointer<Uint8> pk);
typedef _VerifyDart = int Function(Pointer<Uint8> sig, int siglen,
    Pointer<Uint8> msg, int msglen, Pointer<Uint8> pk);

/// Provides access to the native FIPS 204 ML-DSA-44 Dilithium library.
///
/// This class wraps the Soqucoin node's exact C implementation, ensuring
/// byte-for-byte compatibility in key generation, signing, and verification.
class DilithiumNative {
  static DilithiumNative? _instance;

  final _KeypairFromSeedDart _keypairFromSeed;
  final _SignDart _sign;
  final _VerifyDart _verify;

  DilithiumNative._(this._keypairFromSeed, this._sign, this._verify);

  /// Gets the singleton instance, loading the native library on first access.
  ///
  /// Library loading strategy (iOS/macOS with CocoaPods use_frameworks!):
  /// 1. Try DynamicLibrary.open for the framework bundle (dynamic linking)
  /// 2. Fall back to DynamicLibrary.process() for static linking
  /// 3. Fall back to DynamicLibrary.executable() for embedded symbols
  static DilithiumNative get instance {
    if (_instance != null) return _instance!;

    DynamicLibrary lib;
    try {
      if (Platform.isAndroid) {
        // Android: native assets are bundled as .so files in the APK's lib/ dir.
        // The Android dynamic linker finds them by name.
        lib = DynamicLibrary.open('libdilithium_soq.so');
      } else {
        // iOS/macOS: With use_frameworks!, CocoaPods wraps the pod in a
        // .framework bundle. Try RTLD_DEFAULT first.
        lib = DynamicLibrary.process();
        lib.lookup<NativeFunction<Void Function()>>('soq_dilithium_keypair_from_seed');
      }
    } catch (_) {
      try {
        // Fallback: try opening the framework directly (iOS)
        lib = DynamicLibrary.open('dilithium_soq.framework/dilithium_soq');
      } catch (_) {
        try {
          // Try the executable itself (symbols may be merged in release builds)
          lib = DynamicLibrary.executable();
          lib.lookup<NativeFunction<Void Function()>>('soq_dilithium_keypair_from_seed');
        } catch (_) {
          throw StateError(
            'Failed to load dilithium_soq native library. '
            'Ensure the dilithium_soq pod is installed and the app is rebuilt from clean.',
          );
        }
      }
    }

    final keypairFromSeed = lib.lookupFunction<_KeypairFromSeedC, _KeypairFromSeedDart>(
        'soq_dilithium_keypair_from_seed');
    final sign = lib.lookupFunction<_SignC, _SignDart>('soq_dilithium_sign');
    final verify =
        lib.lookupFunction<_VerifyC, _VerifyDart>('soq_dilithium_verify');

    _instance = DilithiumNative._(keypairFromSeed, sign, verify);
    return _instance!;
  }

  /// Generates a deterministic key pair from a 32-byte seed.
  ///
  /// Returns `(publicKey, secretKey)` as raw byte arrays.
  /// The secret key is 2560 bytes and contains all material needed for signing
  /// (rho, tr, key, t0, s1, s2 — packed per FIPS 204).
  (Uint8List publicKey, Uint8List secretKey) keypairFromSeed(Uint8List seed) {
    if (seed.length != 32) {
      throw ArgumentError('Seed must be exactly 32 bytes, got ${seed.length}');
    }

    final pkPtr = calloc<Uint8>(dilithiumPkBytes);
    final skPtr = calloc<Uint8>(dilithiumSkBytes);
    final seedPtr = calloc<Uint8>(32);

    try {
      // Copy seed to native memory
      for (var i = 0; i < 32; i++) {
        seedPtr[i] = seed[i];
      }

      final result = _keypairFromSeed(pkPtr, skPtr, seedPtr, 32);
      if (result != 0) {
        throw StateError('Dilithium keypair generation failed: $result');
      }

      // Copy results back to Dart
      final pk = Uint8List(dilithiumPkBytes);
      final sk = Uint8List(dilithiumSkBytes);
      for (var i = 0; i < dilithiumPkBytes; i++) {
        pk[i] = pkPtr[i];
      }
      for (var i = 0; i < dilithiumSkBytes; i++) {
        sk[i] = skPtr[i];
      }

      return (pk, sk);
    } finally {
      calloc.free(pkPtr);
      calloc.free(skPtr);
      // Zeroize seed in native memory
      for (var i = 0; i < 32; i++) {
        seedPtr[i] = 0;
      }
      calloc.free(seedPtr);
    }
  }

  /// Signs a message using the FIPS 204 ML-DSA-44 algorithm.
  ///
  /// [message] is the raw bytes to sign (typically a 32-byte sighash).
  /// [secretKey] is the 2560-byte packed secret key.
  ///
  /// Returns the 2420-byte signature.
  Uint8List sign(Uint8List message, Uint8List secretKey) {
    if (secretKey.length != dilithiumSkBytes) {
      throw ArgumentError(
          'Secret key must be $dilithiumSkBytes bytes, got ${secretKey.length}');
    }

    final sigPtr = calloc<Uint8>(dilithiumSigBytes);
    final siglenPtr = calloc<Size>(1);
    final msgPtr = calloc<Uint8>(message.length);
    final skPtr = calloc<Uint8>(dilithiumSkBytes);

    try {
      // Copy message and secret key to native memory
      for (var i = 0; i < message.length; i++) {
        msgPtr[i] = message[i];
      }
      for (var i = 0; i < dilithiumSkBytes; i++) {
        skPtr[i] = secretKey[i];
      }

      final result =
          _sign(sigPtr, siglenPtr, msgPtr, message.length, skPtr);
      if (result != 0) {
        throw StateError('Dilithium signing failed: $result');
      }

      final sigLen = siglenPtr.value;
      if (sigLen != dilithiumSigBytes) {
        throw StateError(
            'Unexpected signature length: $sigLen (expected $dilithiumSigBytes)');
      }

      // Copy signature back to Dart
      final sig = Uint8List(dilithiumSigBytes);
      for (var i = 0; i < dilithiumSigBytes; i++) {
        sig[i] = sigPtr[i];
      }
      return sig;
    } finally {
      calloc.free(sigPtr);
      calloc.free(siglenPtr);
      calloc.free(msgPtr);
      // Zeroize secret key in native memory
      for (var i = 0; i < dilithiumSkBytes; i++) {
        skPtr[i] = 0;
      }
      calloc.free(skPtr);
    }
  }

  /// Verifies a FIPS 204 ML-DSA-44 signature.
  ///
  /// Returns `true` if the signature is valid, `false` otherwise.
  bool verify(Uint8List signature, Uint8List message, Uint8List publicKey) {
    if (signature.length != dilithiumSigBytes) return false;
    if (publicKey.length != dilithiumPkBytes) return false;

    final sigPtr = calloc<Uint8>(dilithiumSigBytes);
    final msgPtr = calloc<Uint8>(message.length);
    final pkPtr = calloc<Uint8>(dilithiumPkBytes);

    try {
      for (var i = 0; i < dilithiumSigBytes; i++) {
        sigPtr[i] = signature[i];
      }
      for (var i = 0; i < message.length; i++) {
        msgPtr[i] = message[i];
      }
      for (var i = 0; i < dilithiumPkBytes; i++) {
        pkPtr[i] = publicKey[i];
      }

      return _verify(sigPtr, dilithiumSigBytes, msgPtr, message.length, pkPtr) == 0;
    } finally {
      calloc.free(sigPtr);
      calloc.free(msgPtr);
      calloc.free(pkPtr);
    }
  }
}

/// FFI calloc allocator for native memory.
final calloc = _Calloc();

class _Calloc implements Allocator {
  @override
  Pointer<T> allocate<T extends NativeType>(int byteCount, {int? alignment}) {
    final ptr = malloc.allocate<T>(byteCount, alignment: alignment);
    // Zero-initialize (critical for crypto memory)
    final bytePtr = ptr.cast<Uint8>();
    for (var i = 0; i < byteCount; i++) {
      bytePtr[i] = 0;
    }
    return ptr;
  }

  @override
  void free(Pointer<NativeType> pointer) => malloc.free(pointer);
}

/// System malloc allocator.
final malloc = _Malloc();

class _Malloc implements Allocator {
  static final _mallocFn = DynamicLibrary.process()
      .lookupFunction<Pointer Function(Size), Pointer Function(int)>('malloc');
  static final _freeFn = DynamicLibrary.process()
      .lookupFunction<Void Function(Pointer), void Function(Pointer)>('free');

  @override
  Pointer<T> allocate<T extends NativeType>(int byteCount, {int? alignment}) {
    final ptr = _mallocFn(byteCount);
    if (ptr == nullptr) {
      throw StateError('malloc failed to allocate $byteCount bytes');
    }
    return ptr.cast<T>();
  }

  @override
  void free(Pointer<NativeType> pointer) => _freeFn(pointer);
}
