import 'dart:typed_data';
import '../dilithium/constants.dart';

/// Soqucoin Bech32m address encoding and decoding.
///
/// Supports both mainnet (ssq1...) and testnet (tsq1...) addresses.
/// Uses witness version 1 for post-quantum (Dilithium) outputs.
class AddressCodec {
  static const _charset = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l';
  static const _bech32mConst = 0x2bc830a3;

  /// Decode a Bech32m address into its components.
  ///
  /// Returns `(hrp, witnessVersion, witnessProgram)` or throws on invalid input.
  (String hrp, int witnessVersion, Uint8List witnessProgram) decode(String address) {
    // Find the separator '1'
    final sepIndex = address.lastIndexOf('1');
    if (sepIndex < 1 || sepIndex + 7 > address.length) {
      throw FormatException('Invalid Bech32m address: missing separator');
    }

    final hrp = address.substring(0, sepIndex).toLowerCase();
    final dataStr = address.substring(sepIndex + 1).toLowerCase();

    // Decode from charset
    final data = <int>[];
    for (final c in dataStr.codeUnits) {
      final idx = _charset.indexOf(String.fromCharCode(c));
      if (idx == -1) throw FormatException('Invalid Bech32m character');
      data.add(idx);
    }

    // Verify checksum
    final expanded = _hrpExpand(hrp) + data;
    if (_polymod(expanded) != _bech32mConst) {
      throw FormatException('Invalid Bech32m checksum');
    }

    // Strip checksum (last 6 values)
    final payload = data.sublist(0, data.length - 6);
    if (payload.isEmpty) throw FormatException('Empty Bech32m payload');

    final witnessVersion = payload[0];
    final programBits = payload.sublist(1);

    // Convert from 5-bit to 8-bit
    final program = _convertBits(Uint8List.fromList(programBits), 5, 8, false);

    return (hrp, witnessVersion, Uint8List.fromList(program));
  }

  /// Encode a witness program as a Bech32m address.
  String encode(String hrp, int witnessVersion, Uint8List witnessProgram) {
    final converted = <int>[witnessVersion] + _convertBits(
      Uint8List.fromList(witnessProgram), 8, 5, true,
    );

    final values = _hrpExpand(hrp) + converted;
    final polymod = _polymod(values + [0, 0, 0, 0, 0, 0]) ^ _bech32mConst;
    final checksum = List<int>.generate(6, (i) => (polymod >> (5 * (5 - i))) & 31);

    final combined = converted + checksum;
    return '$hrp${1}${combined.map((d) => _charset[d]).join()}';
  }

  /// Validate a Soqucoin address.
  bool isValid(String address) {
    try {
      final (hrp, version, program) = decode(address);
      return (hrp == soqAddressHrp || hrp == soqTestnetHrp) &&
             version == pqWitnessVersion &&
             program.length == 32;
    } catch (_) {
      return false;
    }
  }

  /// Check if an address is mainnet.
  bool isMainnet(String address) {
    try {
      final (hrp, _, _) = decode(address);
      return hrp == soqAddressHrp;
    } catch (_) {
      return false;
    }
  }

  List<int> _convertBits(Uint8List data, int fromBits, int toBits, bool pad) {
    int acc = 0, bits = 0;
    final ret = <int>[];
    final maxv = (1 << toBits) - 1;
    for (final v in data) {
      acc = (acc << fromBits) | v;
      bits += fromBits;
      while (bits >= toBits) {
        bits -= toBits;
        ret.add((acc >> bits) & maxv);
      }
    }
    if (pad && bits > 0) ret.add((acc << (toBits - bits)) & maxv);
    return ret;
  }

  List<int> _hrpExpand(String hrp) {
    final ret = <int>[];
    for (final c in hrp.codeUnits) { ret.add(c >> 5); }
    ret.add(0);
    for (final c in hrp.codeUnits) { ret.add(c & 31); }
    return ret;
  }

  int _polymod(List<int> values) {
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
