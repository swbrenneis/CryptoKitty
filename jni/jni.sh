#! /bin/sh

javah -cp CryptoKitty.jar org.cryptokitty.jni.BigInteger
javah -cp CryptoKitty.jar org.cryptokitty.jni.BerkeleySocketImpl
javah -cp CryptoKitty.jar org.cryptokitty.random.FortunaSecureRandom
javah -cp CryptoKitty.jar org.cryptokitty.cipher.AES
javah -cp CryptoKitty.jar org.cryptokitty.modes.GCM
javah -cp CryptoKitty.jar org.cryptokitty.mac.HMAC
javah -cp CryptoKitty.jar org.cryptokitty.keys.RSAKeyPairGenerator
javah -cp CryptoKitty.jar org.cryptokitty.tls.TLSCredentials
javah -cp CryptoKitty.jar org.cryptokitty.tls.TLSSession

make

