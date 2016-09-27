#! /bin/sh

javah -cp CryptoKitty.jar org.cryptokitty.jni.BigInteger
javah -cp CryptoKitty.jar org.cryptokitty.random.FortunaSecureRandom

make

