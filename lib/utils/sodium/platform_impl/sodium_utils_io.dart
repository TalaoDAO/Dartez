import 'dart:typed_data';

import 'package:dartez/utils/sodium/platform_impl/sodium_utils_base.dart';
import 'package:sodium_libs/sodium_libs.dart' hide KeyPair;

class SodiumUtilsImpl extends SodiumUtilsBase {
  late final Sodium sodium;
  @override
  Future<void> init() async {
    sodium = await SodiumInit.init();
    return Future.value();
  }

  @override
  Uint8List close(Uint8List message, Uint8List nonce, Uint8List keyBytes) {
    return sodium.crypto.secretBox.easy(message: message, nonce: nonce, key: SecureKey.fromList(sodium, keyBytes));
  }

  @override
  Uint8List nonce() {
    return rand(sodium.crypto.box.nonceBytes);
  }

  @override
  Uint8List open(Uint8List nonceAndCiphertext, Uint8List key) {
    final nonce =
        nonceAndCiphertext.sublist(0, sodium.crypto.secretBox.nonceBytes);
    final cipherText =
        nonceAndCiphertext.sublist(sodium.crypto.secretBox.nonceBytes);

    return sodium.crypto.secretBox.openEasy(cipherText: cipherText, nonce: nonce, key: SecureKey.fromList(sodium, key));
  }

  @override
  KeyPair publicKey(Uint8List sk) {
    /// TODO(hawkbee): looks like it is not used => throwing error and commenting the old code for now
    // var seed = sodium.Sodium.cryptoSignEd25519SkToSeed(sk);
    // var temp = sodium.Sodium.cryptoSignSeedKeypair(seed);
    // return KeyPair(temp.pk, temp.sk);
    throw UnimplementedError('Not implemented');
  }

  @override
  Uint8List pwhash(String passphrase, Uint8List salt) {
    // return sodium.Sodium.cryptoPwhash(
    //     sodium.Sodium.cryptoBoxSeedbytes,
    //     Uint8List.fromList(passphrase.codeUnits),
    //     salt,
    //     4,
    //     33554432,
    //     sodium.Sodium.cryptoPwhashAlgArgon2i13);
    throw UnimplementedError('Not implemented');

  }

  @override
  Uint8List rand(int length) {
    // return sodium.Sodium.randombytesBuf(length);
    throw UnimplementedError('Not implemented');
  }

  @override
  Uint8List salt() {
    // return Uint8List.fromList(
    //     rand(sodium.Sodium.cryptoPwhashSaltbytes).toList());
    throw UnimplementedError('Not implemented');
  }

  @override
  Uint8List sign(Uint8List simpleHash, Uint8List key) {
    // return sodium.Sodium.cryptoSignDetached(simpleHash, key);
    throw UnimplementedError('Not implemented');
  }

  @override
  getSodium() {
    // return sodium.Sodium;
    throw UnimplementedError('Not implemented');
  }

  @override
  KeyPair cryptoSignSeedKeypair(Uint8List seed) {
    // var temp = sodium.Sodium.cryptoSignSeedKeypair(seed);
    // return KeyPair(temp.pk, temp.sk);
    throw UnimplementedError('Not implemented');
  }

  @override
  Uint8List cryptoSignDetached(Uint8List message, Uint8List key) {
    // return sodium.Sodium.cryptoSignDetached(message, key);
    throw UnimplementedError('Not implemented');
  }
}
