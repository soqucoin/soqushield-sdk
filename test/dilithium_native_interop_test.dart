// Copyright (c) 2026 Soqucoin Labs Inc.
// Distributed under the MIT software license.
//
// dilithium_native_interop_test.dart — Dart-side ML-DSA-44 node-interop (vector_mldsa, Dart half).
//
// Loads the native dilithium_soq dylib (FFI to the node's OWN src/crypto/dilithium C) and proves:
//   - round-trip: keypair_from_seed -> sign -> verify (Dart FFI marshalling is correct);
//   - Direction 1: Dart-FFI verify ACCEPTS a pinned NODE-produced signature;
//   - keygen cross-check: pqcrystals-C keypair_from_seed(0x42) == @noble keygen(0x42) BYTE-EXACT
//     -> node / @noble / Dart share the 1312-byte encoding, so keyhash commitments line up and
//        the node (which already verifies @noble sigs, soqucoin#15) verifies Dart sigs too.
//
// Build the dylib (macOS):
//   cd ~/soqucoin-ops/soqushield/native/dilithium && clang -O2 -fPIC -shared \
//     -o libdilithium_soq.dylib dilithium_ffi.c sign.c packing.c polyvec.c poly.c ntt.c \
//     reduce.c rounding.c fips202.c symmetric-shake.c randombytes.c -I.
//   SOQ_DILITHIUM_DYLIB=<path> dart test test/dilithium_native_interop_test.dart
// (skips cleanly if the dylib is absent; uses libc malloc/free via dart:ffi — no package:ffi.)

import 'dart:ffi';
import 'dart:io';
import 'dart:typed_data';

import 'package:test/test.dart';

typedef _KpC = Int32 Function(Pointer<Uint8>, Pointer<Uint8>, Pointer<Uint8>, Int32);
typedef _KpD = int Function(Pointer<Uint8>, Pointer<Uint8>, Pointer<Uint8>, int);
typedef _SignC = Int32 Function(Pointer<Uint8>, Pointer<Size>, Pointer<Uint8>, Size, Pointer<Uint8>);
typedef _SignD = int Function(Pointer<Uint8>, Pointer<Size>, Pointer<Uint8>, int, Pointer<Uint8>);
typedef _VfyC = Int32 Function(Pointer<Uint8>, Size, Pointer<Uint8>, Size, Pointer<Uint8>);
typedef _VfyD = int Function(Pointer<Uint8>, int, Pointer<Uint8>, int, Pointer<Uint8>);

final _proc = DynamicLibrary.process();
final _malloc = _proc.lookupFunction<Pointer<Uint8> Function(IntPtr), Pointer<Uint8> Function(int)>('malloc');
final _free = _proc.lookupFunction<Void Function(Pointer<Uint8>), void Function(Pointer<Uint8>)>('free');

Pointer<Uint8> _buf(Uint8List b) {
  final p = _malloc(b.length);
  p.asTypedList(b.length).setAll(0, b);
  return p;
}

Uint8List _hex(String s) =>
    Uint8List.fromList([for (var i = 0; i < s.length; i += 2) int.parse(s.substring(i, i + 2), radix: 16)]);

const int pkLen = 1312, skLen = 2560, sigLen = 2420;

void main() {
  final path = Platform.environment['SOQ_DILITHIUM_DYLIB'] ??
      '${Platform.environment['HOME']}/soqucoin-ops/soqushield/native/dilithium/libdilithium_soq.dylib';
  final skip = File(path).existsSync() ? null : 'dilithium_soq dylib not built ($path) — see header';

  group('ML-DSA-44 Dart node-interop (vector_mldsa, Dart half)', () {
    late _KpD keypairFromSeed;
    late _SignD sign;
    late _VfyD verify;

    setUp(() {
      final lib = DynamicLibrary.open(path);
      keypairFromSeed = lib.lookupFunction<_KpC, _KpD>('soq_dilithium_keypair_from_seed');
      sign = lib.lookupFunction<_SignC, _SignD>('soq_dilithium_sign');
      verify = lib.lookupFunction<_VfyC, _VfyD>('soq_dilithium_verify');
    });

    Uint8List keygen(int seedByte, Uint8List outSk) {
      final seed = _buf(Uint8List(32)..fillRange(0, 32, seedByte));
      final pk = _malloc(pkLen), sk = _malloc(skLen);
      expect(keypairFromSeed(pk, sk, seed, 32), 0);
      final pub = Uint8List.fromList(pk.asTypedList(pkLen));
      outSk.setAll(0, sk.asTypedList(skLen));
      _free(seed); _free(pk); _free(sk);
      return pub;
    }

    test('round-trip: keypair_from_seed -> sign(0xcc) -> verify', () {
      final sk = Uint8List(skLen);
      final pub = keygen(0x42, sk);
      expect(pub.length, pkLen);

      final digest = _buf(Uint8List(32)..fillRange(0, 32, 0xcc));
      final skP = _buf(sk);
      final sigP = _malloc(sigLen);
      final sigLenP = _malloc(8).cast<Size>();
      expect(sign(sigP, sigLenP, digest, 32, skP), 0);
      expect(sigLenP.value, sigLen);

      final pubP = _buf(pub);
      expect(verify(sigP, sigLen, digest, 32, pubP), 0, reason: 'Dart FFI round-trip verifies');

      final wrong = _buf(Uint8List(32)..fillRange(0, 32, 0xdd));
      expect(verify(sigP, sigLen, wrong, 32, pubP) == 0, isFalse);
      _free(digest); _free(skP); _free(sigP); _free(sigLenP.cast()); _free(pubP); _free(wrong);
    });

    test('Direction 1: Dart-FFI verify ACCEPTS a pinned node signature', () {
      final pub = _buf(_hex(NODE_PUBKEY));
      final sig = _buf(_hex(NODE_SIG));
      final digest = _buf(Uint8List(32)..fillRange(0, 32, 0xcc));
      expect(verify(sig, sigLen, digest, 32, pub), 0,
          reason: 'node ML-DSA-44 signature verifies under the Dart FFI (pqcrystals)');
      _free(pub); _free(sig); _free(digest);
    });

    test('keygen cross-check: pqcrystals-C(seed 0x42) == @noble(seed 0x42) byte-exact', () {
      final sk = Uint8List(skLen);
      final cPub = keygen(0x42, sk);
      expect(cPub, equals(_hex(NOBLE_PUBKEY)),
          reason: 'FIPS-204 keygen agrees across pqcrystals-C and @noble-JS -> shared encoding');
    });
  }, skip: skip);
}

// ---- pinned fixtures ----
const String NODE_PUBKEY = "08de94978d8fcefe3e933a3218b411800717b1191fa07838603cbc93efc09460592c16b9ddf0f34c3fe38fc7eb357b09b20c1e72fe8e583a60b7830e635ba9b10571d7aac214faa3dbed8eb661b941a82d9ad60eb0c7bf73f6d810509d9f1892ad1d96a528ff54e0fc761a9d929ba9c9ff698cdd19c8e9021973e0b77431439699d54ae103fc7dd4a8f27aadbe0eac0b9801eb8f0784574a5fd386f841d5248e81ff4267dc694d74c4243262054e0aeaf4a4baffd63b09843a32cb3d83f74dc18e94865f5e5dc0e7788022441201da128a5bb7404e8c15f0e90523fb1ad304c6a97cf5687a58a69e21676c5b7aa8b138de4fdc89f3edee7ef6773e2b238dfbdf2c9d308cc9fe9c145cd0f6ccd0ec4628f5f99b17856dfc684dddb0fb6fc2a73ab369651e43783be3f08055f42469cadf0c1806cdf14dbf725dde3c6cafd73bd437fa4d2b07d5e01558a464dc806ddf7e0c902a31b1a6439497f25d8c756a834b9c2f89617f7cba493721e5531c25afd3fa23f94d6d35d9a7cdb90af7bffeb6e1bd3e368a196d48adb490c403e4b6d5beca5c5a0a10b2a00b774afe16050a6f22e665a48a59ec4cb40d5cf8641641d89ed9d89697ecd241da2b55fb289eee6581770a96bcb5599ad95ed30ff6c50e4ea4446c047559cfa4ac4f36a773c7922d4e6b9348fff2215a635c68a2da94dbd3330fc56bdd54bb8d3420f089b5b0f9836cbebc50918a85f51d0fa47e21ce0e31c7cb25109b8ebebed4aef7d66994b3413ff42ae254eee7da4d5de9dbe24dc86158cdc3f3ae93aa79d2bbfcd65f3596a9717b2b9bb6cf164f8e80651a2a9e95138272d44e2e5db3754f65717e6ef5acf4582e6ada8522a12e76adfbe45deaf34cdaf5f48b52c817df07fb5b5574d7149abf6b9003c9aa268d51319ec5bc9d6a9df3cba4fcf0c22b6a5fb337923144f53dd00bf4a860219f3ade465b1ab77c5043d2952c7ca20da60b5b80a8ddeb4c773b4939dbf9b58292d2da4ccd3f9a691983a0d2c2ca0d4fd094063d67735857ccb86957555787648bf93e7939b02150e201ee66ea6645081cd273fb2c894e4ba5333498ac8d516ba715550facc9114e54b1064f69c7d32e5ce4a4c23db8e0ce6a1d9e2b953aff779e5c95780a74454074aeda004686445df6694d4dd32ec5655e4d72aa08dadb2e1923d84892c38d08d51c0b89beabba1af98695098098d1391e8bf0caf5c00dcc70fa4a913b3230d8b405c714e488bba63be5ace4a4f27149cd438cd9a581329fdb35ca8111fa26a01cfcef7dabddccdf13f91389c263d23bab2103cdeb8ebf6ea9c53b3fb4fed56b9d9ce1ac06c5baec5623d70f48fe3916d6ec39dac4d0b8616616a4bdc5339cc968e757c297fc6206770bf740e9294901818524bae6dcfd3c56d04f62c53bf105a87370a8db4f425f03e07e3b9112c775cfeedfe585a8b4acce8c73b61f37ccf9b8be9272784d94f222c12cc68f52b71f9bbef8d872933816bdd063667a0474122e6e635d785edeb2f9e2b3871fb6f5d8d10f3ab814c9c8c23041758883677412ab688b27ef370db687eabe20185a379b07a3cdf4cd8133316c34d987e985592bd4f485174b7a8a9c77abcca042b45e10993aedd80d956d6fcf51be7338eefe3d71660b7fb151a9b5f636fe9acaa1b83516e735893f9acd00488fee595785bd99255eb050bd59de8a206b23959a78dfba5bfd82fe42e44b825a4461e52d4a85f396ed58bef20cbedc5871c15c1e520034a0fec7670fcedbf838f288bb1c7e0bbf15b2f3badb99f16f07dc31a89c258947b569496fa08f4e41551f712d3d3c5f58d3ca8562f1285540dd2a4801daa79c86ac0702";
const String NODE_SIG = "16d4b8a12c9b928cc16d06f4efb86b9539c3f8b346747c7aeace90e2b18f86d9d4673cac910e61d18f7555d0f6e871cd20149bb094a69255d383a6fa8fbd0d3938e598a18eabd357e19de6b01a99cf772ef9b93077193518a79a32a38edf8ff86f2afcd17c8e6874989d82e5e5f029d5f8a811a8513a56384ead4f3d3e88b8017c030ae205ac15c865011275976b88c7d6114e866e841af385177b62bf25ff9ea857fe11161ba039c33510e3a4edfb0168a55a9733a7186f389902a2db0095489434eb64d0867b19d51c7eb33a98e18b1ad9a86635a19880907556b8daeb5b9b49fe67d61e09c18b9bdd229fe6531db900dbbe8e50ccb4456d42578fd815527dcf38b4f558d377a3c1ae0dba3183370e46d8b47c995842b82fc2ba2d165b046bfb8e497d39186e82ec8237dea209af96bdf6c1b8b50434e8dbb380de478ec49730170b4561639668994f55a8f9b84d40ec749edcaebe6f76408a7e5f2e87ced9629ced41ab76df0a3a47659ab8bc4604a06b131f50bccf8e59a4c565d70195f739ff498e25b36ae05d5689d5f28aac1610bd7d38021d03d14fb77afa967f72ec169b86c4b038b869e5326133c20412a5be02c5e3996f2a3bba99d099a4860fb91d1d34dd6a68aa8f71d58a517ec7f79c2f0f8e4026a16192299762fe44d35b817d5940dbef6074c06a5b06efa459d600bf3eac465e6eb7d024f1d023d564010275b2859791f9603dcff8e7ccce2fa1278ac40b20d3e58d4adadda294b4126c050967b7b246058c823781746683137207a85db83d0585a28353a034cbc195d122e4d5971646fd8f7496f9af522225b76da97ef10a043df3a43201ce3748e595fb4e7ac0535ab5677b07ef9b8aa23a312ecb301c2b9edf3f78edab34614bd3fae5db65861da3873f821670b86dca886e8357128511e2b4a8ac4d271ecbdebeb102b4b17ef994251d5e672034d619be865de34426c7e69baade6c9aa909681e27b31bfbe8e8f61730efbc2d775ba558ab55db281c7ba6004811bb57acc16371efcff9158a5f4734ad514d31e1aa31c8df319b4f30fc01664df153e74e020792925a9f2231e563950a40e7359f003cad5166b4810f9581d11f733d7a162fc59d2c3f4e2e797cc43b0559995f6f22bb13025e143ed13d812db24046a35a8bc118d7d7e6d305b0ef5ef57521390b8922a57f49b0263c10fddf03c682ffc79d15e6e16386ce305163dcf4fb76be74f21e9d4bb1199fb7b4110c11645ddd8d7640f5e162baafe60de05090a72953863ce5b39c6618aa82c9203969480ca86f66085a3e27e3f72a38705dbc69f86c858ac8c38a92915746f30703c126996ff2208364654e8dd17608bb3af3dc4fbdba55d8204c65c423af7473a60dab556e6288ab416f4914e75fb7fddb2d57d91b314bd849135258072a4c365daeddb897c852006a1d1496b77ede86e0eebc9935316b6d412a68d6ec77a20efad47f06de5688a40f5a9395333dd3cdf36f14d436e13831cc421d00986a0e52ffd76043f457cb7c2f4a9dce36ccf6e12a5f98365a9753c5184f2e622d241a86c58a4a8cc267f38b16c7c7ee8b5621af801263b95b1402b66af5a56cf5f56a43aa8968772a40bf7cb9a70408e7d11e9b3906aca1be415877ac3a4a180ad66add89eb332bb4ba7a97fdafd9805af0b6059e853a95b8fddde797e23faabb22a61a6daadc4d8d1ddf5fcc82c44710fa65f95cc7da3c2aad85c31c08e285a5f81565b42828ee9244e8cbaf837017db4306d42b5093b8ae5920421069904939c067e7f2541ba03ac22c75bc0ea8961b2dd07b95dbe2c928693841ce492a40d73a990d8c224c02b83ddc5922f0781e728a406d6c3e772ce993f58896a644b777f6abd10265566e3723a443a05851ab6f40ed528b6cfc917825b8f7b37ae9f09e1ad8c5509ce38e8247011a0b92abab290a73b8dcca4969e22d688e799717ec61f48ab0038482824f2e6b7ad8f32f9797bbff38182ba761cf1ba43fbdec7aa41b3b7457e68c72d581fc822338be409aa6f52831a66785697ed82ab7ba97fb0198a60418e1c1ee82a9fd0bec37077949a069846afac4d9c519d2d865466a2ae772c5082bac715c4db1f5964eb734cc4959fea406d7a564810df9c4f8b7f34b15f074533c8f39a54874ad41fc250b3f42127d9e3da35ef90a808ba5cb3bfaba528fa22967e2b46e442397a2bdb1940554817c01fb056aa25039c6910868772692e9ef4efacaad76e23fc1fe77a0e7217c1b9f2a6467b067a33017b91a7874ad8bebfab3c900b113248c47f8571a05801a4bcac0e24ec00b3515132add84080e81e8bfb7b742a16d6f22081ed32cbb724231d13d48ccffc8ff84747a2d283aab8e686785c15de070e328c713b5749e8643ad0d69367525e0edfbcc5e380aa71e88501ea7bd74bfa725d28e6cd4c7e77d8e1ef04982bdf7c3213194ecf70b7cedc4d35ee2abecefe6cedaa1985474bc886d62fc1b6b63b3780a39d700d800430dde638e7ee7f1b1094fdd15be6d2f9f8626296c16eaeeca4d4df02aedfb16987badf93c87dca73f23e32a9c2b86b1fe9a75511772d470ebd659e552c2e205c4eab8e02a58cbc1e50f7546ce8a7165f8ee93846d7d880f2ac7d49717263a34ef7a36998615dadc8836b84e95092dc336b83dd849ff6e25836364c1da9e6f666720d020590527c4fb016f666f7fa04fc9ba6a0c53ceb35f8a630b5bafa7a9f1d8268dd9e304c9ca2f1d96344485a0e7c11f09f07874a61a28cfc87763335dd712711c3129c24491c002c80c219efb193a8d48e149e8034ce75dcda5f149a54129150cfb2d0e14ad8dec3f4d8271ffca339b1d463e57fcf8ddbf598f4169fa7377359a44934277f6273305c6dac4f95d3117528d41e0353d5046569aeef6ec41c5ee7f40b64324c06e265c770d9e5976b6dec1b69b86feda2f2e04a3e464626529416eb3a5e1fdce4e19025dbfaa48976af2e3e43c59ee8fae2a99adb2f6e69fa1b6585cf1a96b62833380d440396e91957a464445d71c136158ef39936eeafe4096b57c34d31d50ff17f98b89a74f12217c95c515dc74b2be79e0851dbe87e441bcfa718c493135325c0e2802c085aff7b8c7985012795a49924096e64ca01e3d777fbdc2bfce9dda9fdf0e0adef811961fe7cb5843fe6ac92188e42a3e4891175f726d00c815b5ffb8978d4fd5b007ce0a49dba7cb3149ec32a3fd68b2b19965b777ab8bf21ffba9b242c9365477b35d13e4e3508e8d202e92571b952f959f4cc9f15a97ee46b376a1ab1018c92bb2006a132e474a4d525d79a5bdd9fd0d181b2122415c5f767d8b90959cc7d5db09263b42455e666f7f88898a8d9a9c9fabafced0d4e2e50207184c9dc0ccd1f9fe0000000000000000000000000000000000000c1d343e";
const String NOBLE_PUBKEY = "dfab4158c8952a54f8bd019ae3ccba701bd8f0baf78e308d71c2b6a7f95a70668d291af8c54de4c8707b0068be72e4da2d0e319d82fc23c1025858645449a927bf52cdf81fa06dc8c0791ba1ed14201d30670b539ddcd31d501b7b618db72039b4bf911245f76d0b41bcd4389f06a2fd6d312d644b27939034580c0ee3f1bd14528fefb59219d45fbe15371e509fd2784b4324e9a3d234fcf351254b571889713744f926df76b778cd3d6824f9442acf0c42d0c71797f2d59bf156f43348336faaca71819386d5983ff340499189dfaede03e29778908eadcc9390b85ac9a7b4900b5a7c5cd58d06423cd5cd666b77351008def98a1426b73179c50882b5318b21f9ff8235cc5a61f135a88e0a98d19e68b6405ef78a48eb50a2c3b772c03aa9c5f332efff9e93c79328ccfbf7353fba7c124023742799e4f424926d743cda109be5716951942395a51fc36b66dddd9afb45feca30adcd6809f484608db8f9b05820dec3a5fe076c8ba456c33755ea4f6cc69cb9a27d3e985ea4753815c3efc1decedaf4e488a91bb8216629d621860b75ea027d9b47843da4ee031b3a4aa3b1d1da2cc70a0d9d29eaa11e721991bed9204123464b2a823f85a01304097114ae9f66e5560db7830a6191380943d7dc4547b9980d74a9333408afff51816611ad1962641f9cb3e4cc5d5db896e11cdb15219bf88cc8dc3a97f8414c884824b2d9763930a10aeb5e4dc637a8bfce19e3a4b112a2d67d13e6e0ad1888dd89a828d3871376b740db3fef153f6656b4df6ce5602e6902382a6f5ada047a80e80077032cee6870eca2159363c8d57168a3f7766f32a5e59a6559a7609a5452194a3d292cf8c28466c6de926cc8e8bbbafde77c60be7becb75b86fe68707ef2cf4410fd725234bcf0869b35bf10ce1c9f5ea36461d1032181fd8871807179ab2e9bd7e24b53693dffb8753eca17ced2a675b174772a74a7fe5dc80ad10e66c98b9d7031334ce3168c96c3bf56c63b20dc4478a07daf394a5b68a929fdeb1e91b127464a765bfc0e9334e72be72d4c7236fb42b84822bc45249a5845494a4b5be3927561762ef9e3a39aa31c2765a4d217f9649017de1ab834bc31ad58dff16877c607283983fb29692e457ce5711827073578555b3612b46ddc2e92a308029540d354513231fb4f94a3c4f1e42956bd91e9d4c4d75725ba0542dc678cedb6de812c713015d67abd8a03f0bc03d894efdce2f326634d3e2c422b92890ca3eb7228920e2a485deadc60b92d9fbd5a82a8f1f012ef852049aa40413b4fa5d0e4ca2464978fbe56c5211c4e59998c048d689121cba0c011c783462452b1a183448d18a13c013184080e766afba778de67c12da98a6072a524bc2242d93bc6d9c0842c0bdf992a06c2e202588beed1adc7f03b21d50f7745869adfdfc9b33003fccf54180f6248f8726e4496d13e42e4dfb61b511d2cee098d783a85482bd600ce7204f052b5bdf786933c7fb8448b5809d1884335405c2c1b70053985aae87b655a01a25caf98c64620fdf2aca55c9c5d064674fa4f281a17172e1bbb6f804a5fa7850f8a457a8eebceedd9ec2c6d4a056f7a18b6e14b46dc1dd2bccfca8c755c635c8c59a95e52dbd53ad4483ad27bdb0bdd6198d076cc69e14375181c33d5ac7d8debb5f6de8901a8976fe3b919d0ac8564d213e71650cbc05ec8ab39a21039d2f33c3113ccff090e45031bc426915a43d4860d5623d685e6940340260febd35c06427d806cfa93b6e2df43ba7d1ffe60f3d63b5ed4e30386def7e7b94ee13ab21ac6eace87f7b286913d0e0e44b73827519cad3c5dd2d459e3a2cf952bedf59d8256f296"; // @noble ml_dsa44.keygen(seed=0x42 x32).publicKey
