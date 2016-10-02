#include "org_cryptokitty_keys_RSAKeyPairGenerator.h"
#include <CryptoKitty-C/keys/RSAKeyPairGenerator.h>
#include <CryptoKitty-C/keys/RSAPublicKey.h>
#include <CryptoKitty-C/keys/RSAPrivateCrtKey.h>
#include <CryptoKitty-C/keys/KeyPair.h>
#include <CryptoKitty-C/random/FortunaSecureRandom.h>
#include <CryptoKitty-C/data/BigInteger.h>

/**
 * Retrieve the opaque pointer reference.
 */
static CK::RSAKeyPairGenerator *getReference(JNIEnv *env, jobject thisObj) {

    jclass thisClass = env->GetObjectClass(thisObj);
    // TODO Throw an exception if null.
    jfieldID fieldId = env->GetFieldID(thisClass, "pointer", "J");
    jlong pointer = env->GetLongField(thisObj, fieldId);
    return reinterpret_cast<CK::RSAKeyPairGenerator*>(pointer);

}

static jobject newBigInteger(JNIEnv *env, const CK::BigInteger& integer) {

    jclass biClass = env->FindClass("org/cryptokitty/jni/BigInteger");
    jmethodID initId = env->GetMethodID(biClass, "<init>", "()V");
    jobject biObj = env->NewObject(biClass, initId);
    jfieldID fieldId = env->GetFieldID(biClass, "pointer", "J");
    jlong pointer = env->GetLongField(biObj, fieldId);
    pointer = reinterpret_cast<jlong>(new CK::BigInteger(integer));
    env->SetLongField(biObj, fieldId, pointer);
    return biObj;

}

JNIEXPORT void JNICALL
Java_org_cryptokitty_keys_RSAKeyPairGenerator_initialize (JNIEnv *env, jobject thisObj, jint keysize) {

    CK::RSAKeyPairGenerator *ref = new CK::RSAKeyPairGenerator;
    ref->initialize(keysize, new CK::FortunaSecureRandom);
    jclass thisClass = env->GetObjectClass(thisObj);
    // TODO Throw an exception if null.
    jfieldID fieldId = env->GetFieldID(thisClass, "pointer", "J");
    jlong pointer = env->GetLongField(thisObj, fieldId);
    pointer = reinterpret_cast<jlong>(ref);
    env->SetLongField(thisObj, fieldId, pointer);

}

JNIEXPORT jobject JNICALL
Java_org_cryptokitty_keys_RSAKeyPairGenerator_generateKeyPair (JNIEnv *env, jobject thisObj) {

    CK::RSAKeyPairGenerator *ref = getReference(env, thisObj);
    if (ref == 0) {
        jclass ise = env->FindClass("org/cryptokitty/exceptions/IllegalStateException");
        env->ThrowNew(ise, "Key pair generator not initialized");
    }

    CK::KeyPair<CK::RSAPublicKey, CK::RSAPrivateKey> *pair = ref->generateKeyPair();
    CK::RSAPublicKey *pub = pair->publicKey();
    jobject e = newBigInteger(env, pub->getPublicExponent());
    jobject n = newBigInteger(env, pub->getModulus());
    jclass pubKeyClass = env->FindClass("org/cryptokitty/keys/RSAPublicKey");
    jmethodID initId = env->GetMethodID(pubKeyClass, "<init>",
            "(Lorg/cryptokitty/jni/BigInteger;Lorg/cryptokitty/jni/BigInteger;)V");
    jobject publicKey = env->NewObject(pubKeyClass, initId, n, e);

    CK::RSAPrivateCrtKey *prv = dynamic_cast<CK::RSAPrivateCrtKey*>(pair->privateKey());
    jobject p = newBigInteger(env, prv->getPrimeP());
    jobject q = newBigInteger(env, prv->getPrimeQ());
    jobject dP = newBigInteger(env, prv->getPrimeExponentP());
    jobject dQ = newBigInteger(env, prv->getPrimeExponentQ());
    jobject qInv = newBigInteger(env, prv->getInverse());
    jclass prvKeyClass = env->FindClass("org/cryptokitty/keys/RSAPrivateCrtKey");
    initId = env->GetMethodID(prvKeyClass, "<init>",
    "(Lorg/cryptokitty/jni/BigInteger;Lorg/cryptokitty/jni/BigInteger;Lorg/cryptokitty/jni/BigInteger;Lorg/cryptokitty/jni/BigInteger;Lorg/cryptokitty/jni/BigInteger;)V");
    jobject privateKey = env->NewObject(prvKeyClass, initId, p, q, dP, dQ, qInv);

    jclass keyPairClass = env->FindClass("java/security/KeyPair");
    initId = env->GetMethodID(keyPairClass, "<init>",
                        "(Ljava/security/PublicKey;Ljava/security/PrivateKey;)V");
    jobject keyPair = env->NewObject(keyPairClass, initId, publicKey, privateKey);
    delete prv;
    return keyPair;

}

