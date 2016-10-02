#include "org_cryptokitty_mac_HMAC.h"
#include "ByteArrayCodec.h"
#include <CryptoKitty-C/mac/HMAC.h>
//#include <CryptoKitty-C/digest/SHA224.h>
#include <CryptoKitty-C/digest/SHA256.h>
#include <CryptoKitty-C/digest/SHA384.h>
#include <CryptoKitty-C/digest/SHA512.h>
#include <CryptoKitty-C/exceptions/IllegalStateException.h>
#include <CryptoKitty-C/exceptions/BadParameterException.h>

/**
 * Retrieve the opaque jniImpl reference.
 */
static CK::HMAC *getReference(JNIEnv *env, jobject thisObj) {

    jclass thisClass = env->GetObjectClass(thisObj);
    // TODO Throw an exception if null.
    jfieldID fieldId = env->GetFieldID(thisClass, "jniImpl", "J");
    jlong jniImpl = env->GetLongField(thisObj, fieldId);
    return reinterpret_cast<CK::HMAC*>(jniImpl);

}

JNIEXPORT jboolean
JNICALL Java_org_cryptokitty_mac_HMAC_authenticate (JNIEnv *env, jobject thisObj,
                                                                    jbyteArray hmacIn) {

    CK::HMAC *ref = getReference(env, thisObj);
    ByteArrayCodec hmacCodec(env, hmacIn);
    try {
        return ref->authenticate(hmacCodec.getBytes());
    }
    catch (CK::IllegalStateException& e) {
        jclass ise = env->FindClass("org/cryptokitty/exceptions/IllegalStateException");
        env->ThrowNew(ise, e.what());
    }
    // Won't get here.
    return 0;

}

JNIEXPORT void JNICALL
Java_org_cryptokitty_mac_HMAC_dispose (JNIEnv *env, jobject thisObj) {

    delete getReference(env, thisObj);

}

JNIEXPORT jbyteArray JNICALL
Java_org_cryptokitty_mac_HMAC_generateKey (JNIEnv *env, jobject thisObj, jint bitsize) {

    CK::HMAC *ref = getReference(env, thisObj);
    try {
        ByteArrayCodec keyCodec(env, ref->generateKey(bitsize));
        return keyCodec.getJBytes();
    }
    catch (CK::BadParameterException& e) {
        jclass bpe = env->FindClass("org/cryptokitty/exceptions/BadParameterException");
        env->ThrowNew(bpe, e.what());
    }
    // Won't get here.
    return 0;

}

JNIEXPORT jbyteArray JNICALL 
Java_org_cryptokitty_mac_HMAC_getHMAC (JNIEnv *env, jobject thisObj) {

    CK::HMAC *ref = getReference(env, thisObj);
    try {
        ByteArrayCodec hmacCodec(env, ref->getHMAC());
        return hmacCodec.getJBytes();
    }
    catch (CK::IllegalStateException& e) {
        jclass ise = env->FindClass("org/cryptokitty/exceptions/IllegalStateException");
        env->ThrowNew(ise, e.what());
    }
    // Won't get here.
    return 0;

}

JNIEXPORT jlong JNICALL
Java_org_cryptokitty_mac_HMAC_getDigestLength (JNIEnv *env, jobject thisObj) {

    CK::HMAC *ref = getReference(env, thisObj);
    return ref->getDigestLength();

}

JNIEXPORT jlong JNICALL
Java_org_cryptokitty_mac_HMAC_initialize (JNIEnv *env, jobject thisObj, jint digestType) {

    CK::Digest *digest;
    switch (digestType) {
        // TODO
        //case org_cryptokitty_mac_HMAC_SHA224:
        //    digest = new CK::SHA224;
        //    break;
        case org_cryptokitty_mac_HMAC_SHA256:
            digest = new CK::SHA256;
            break;
        case org_cryptokitty_mac_HMAC_SHA384:
            digest = new CK::SHA384;
            break;
        case org_cryptokitty_mac_HMAC_SHA512:
            digest = new CK::SHA512;
            break;
    }
    return reinterpret_cast<jlong>(new CK::HMAC(digest));

}

JNIEXPORT void JNICALL
Java_org_cryptokitty_mac_HMAC_setKey (JNIEnv *env, jobject thisObj, jbyteArray keyIn) {

    CK::HMAC *ref = getReference(env, thisObj);
    ByteArrayCodec keyCodec(env, keyIn);
    try {
        ref->setKey(keyCodec.getBytes());
    }
    catch (CK::BadParameterException& e) {
        jclass bpe = env->FindClass("org/cryptokitty/exceptions/BadParameterException");
        env->ThrowNew(bpe, e.what());
    }

}

JNIEXPORT void JNICALL
Java_org_cryptokitty_mac_HMAC_setMessage (JNIEnv *env, jobject thisObj, jbyteArray msgIn) {

    CK::HMAC *ref = getReference(env, thisObj);
    ByteArrayCodec msgCodec(env, msgIn);
    ref->setMessage(msgCodec.getBytes());

}

