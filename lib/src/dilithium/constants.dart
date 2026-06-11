/// ML-DSA-44 (FIPS 204) cryptographic constants.
///
/// These values match the Soqucoin node's Dilithium implementation exactly.
/// Do not modify unless the node's parameters change.
library;

/// ML-DSA-44 public key size: 1312 bytes.
const int dilithiumPkBytes = 1312;

/// ML-DSA-44 secret key size: 2560 bytes.
const int dilithiumSkBytes = 2560;

/// ML-DSA-44 signature size: 2420 bytes.
const int dilithiumSigBytes = 2420;

/// Seed size for deterministic key generation: 32 bytes.
const int dilithiumSeedBytes = 32;

/// Soqucoin address human-readable part (HRP) for mainnet.
const String soqAddressHrp = 'ssq';

/// Soqucoin address human-readable part (HRP) for testnet.
const String soqTestnetHrp = 'tsq';

/// Witness version for PQ (post-quantum) addresses.
const int pqWitnessVersion = 1;
