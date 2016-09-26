#! /bin/sh

BUILD=build

if [ ! -d "$BUILD" ]; then
    mkdir $BUILD  
fi

javac -cp ../src -d build ../src/org/cryptokitty/random/SecureRandom.java
javac -cp ../src -d build ../src/org/cryptokitty/jni/BigInteger.java
javah -cp build org.cryptokitty.jni.BigInteger

