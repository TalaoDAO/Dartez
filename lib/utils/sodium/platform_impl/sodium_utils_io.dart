import 'dart:math';
import 'dart:typed_data';

import 'package:argon2/argon2.dart';
import 'package:dartez/utils/sodium/platform_impl/sodium_utils_base.dart';
import 'package:sodium_libs/sodium_libs_sumo.dart' hide KeyPair;

class SodiumUtilsImpl extends SodiumUtilsBase {
  late final Sodium sodium;
  @override
  Future<void> init() async {
    sodium = await SodiumSumoInit.init();
    return Future.value();
  }

  @override
  Uint8List close(Uint8List message, Uint8List nonce, Uint8List keyBytes) {
    return sodium.crypto.secretBox.easy(
        message: message,
        nonce: nonce,
        key: SecureKey.fromList(sodium, keyBytes));
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

    return sodium.crypto.secretBox.openEasy(
        cipherText: cipherText,
        nonce: nonce,
        key: SecureKey.fromList(sodium, key));
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
    var parameters = Argon2Parameters(
      Argon2Parameters.ARGON2_i,
      salt,
      version: Argon2Parameters.ARGON2_VERSION_13,
      iterations: 4,
      memoryPowerOf2: 16,
    );
    var argon2 = Argon2BytesGenerator();

    argon2.init(parameters);

    final passwordBytes = parameters.converter.convert(passphrase);

    final result = Uint8List(32);
    argon2.generateBytes(passwordBytes, result, 0, result.length);

    return result;
  }

  @override
  Uint8List rand(int length) {
    // Not used for now
    // return sodium.Sodium.randombytesBuf(length);
    throw UnimplementedError('Not implemented');
  }

  @override
  Uint8List salt() {
    final random = Random.secure();
    return Uint8List.fromList(
      List<int>.generate(32, (_) => random.nextInt(256)),
    );
  }

  @override
  Uint8List sign(Uint8List simpleHash, Uint8List key) {
    return sodium.crypto.sign.detached(
      message: simpleHash,
      secretKey: SecureKey.fromList(sodium, key),
    );
  }

  @override
  getSodium() {
    return sodium;
  }

  @override
  KeyPair cryptoSignSeedKeypair(Uint8List seed) {
    var temp = sodium.crypto.sign.seedKeyPair(SecureKey.fromList(sodium, seed));
    return KeyPair(temp.publicKey, temp.secretKey.extractBytes());
  }

  @override
  Uint8List cryptoSignDetached(Uint8List message, Uint8List key) {
    return sodium.crypto.sign.detached(
      message: message,
      secretKey: SecureKey.fromList(sodium, key),
    );
  }
}
