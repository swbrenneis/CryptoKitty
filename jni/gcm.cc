#include "org_cryptokitty_modes_GCM.h"
#include "ByteArrayCodec.h"
#include <CryptoKitty-C/ciphermodes/GCM.h>
#include <CryptoKitty-C/cipher/BlockCipher.h>
#include <CryptoKitty-C/exceptions/BadParameterException.h>
#include <CryptoKitty-C/exceptions/AuthenticationException.h>
#include <coder/ByteArray.h>

/**
 * Retrieve the opaque pointer reference.
 */
static CK::GCM *getReference(JNIEnv *env, jobject thisObj) {

    jclass thisClass = env->GetObjectClass(thisObj);
    // TODO Throw an exception if null.
    jfieldID fieldId = env->GetFieldID(thisClass, "pointer", "J");
    jlong pointer = env->GetLongField(thisObj, fieldId);
    return reinterpret_cast<CK::GCM*>(pointer);

}

/**
 * Retrieve the opaque pointer reference.
 */
static CK::BlockCipher *getCipherReference(JNIEnv *env, jobject cipherObj) {

    jclass thisClass = env->GetObjectClass(cipherObj);
    // TODO Throw an exception if null.
    jfieldID fieldId = env->GetFieldID(thisClass, "pointer", "J");
    jlong pointer = env->GetLongField(cipherObj, fieldId);
    return reinterpret_cast<CK::BlockCipher*>(pointer);

}

JNIEXPORT jbyteArray JNICALL
Java_org_cryptokitty_modes_GCM_decrypt (JNIEnv *env, jobject thisObj, jbyteArray ciphertextIn,
                                                                                jbyteArray keyIn) {

    CK::GCM *ref = getReference(env, thisObj);
    // Retrieve ciphertext and key
    ByteArrayCodec ctCodec(env, ciphertextIn);
    ByteArrayCodec keyCodec(env, keyIn);
    // Do decryption
    try {
        coder::ByteArray plaintext(ref->decrypt(ctCodec.getBytes(), keyCodec.getBytes()));
        // Convert output array
        ByteArrayCodec ptCodec(env, plaintext);
        return ptCodec.getJBytes();
    }
    catch (CK::BadParameterException& e) {
        jclass bpe = env->FindClass("org/cryptokitty/exceptions/BadParameterException");
        env->ThrowNew(bpe, e.what());
    }
    catch (CK::AuthenticationException& e) {
        jclass ae = env->FindClass("org/cryptokitty/exceptions/AuthenticationException");
        env->ThrowNew(ae, e.what());
    }
    // Won't get here.
    return 0;

}

JNIEXPORT jbyteArray JNICALL
Java_org_cryptokitty_modes_GCM_encrypt (JNIEnv *env, jobject thisObj, jbyteArray plaintextIn,
                                                                            jbyteArray keyIn) {

    CK::GCM *ref = getReference(env, thisObj);
    // Retrieve plaintext and key
    ByteArrayCodec ptCodec(env, plaintextIn);
    ByteArrayCodec keyCodec(env, keyIn);
    try {
        // Do encryption
        coder::ByteArray ciphertext(ref->encrypt(ptCodec.getBytes(), keyCodec.getBytes()));
        // Convert output array
        ByteArrayCodec ctCodec(env, ciphertext);
        return ctCodec.getJBytes();
    }
    catch (CK::BadParameterException& e) {
        jclass bpe = env->FindClass("org/cryptokitty/exceptions/BadParameterException");
        env->ThrowNew(bpe, e.what());
    }
    // Won't get here.
    return 0;

}

JNIEXPORT void JNICALL
Java_org_cryptokitty_modes_GCM_initialize (JNIEnv *env, jobject thisObj, jobject cipherObj,
                                                                            jboolean appendTag) {

    CK::BlockCipher *cipher = getCipherReference(env, cipherObj);
    CK::GCM *ref = new CK::GCM(cipher, appendTag);
    jclass thisClass = env->GetObjectClass(thisObj);
    // TODO Throw an exception if null.
    jfieldID fieldId = env->GetFieldID(thisClass, "pointer", "J");
    jlong pointer = env->GetLongField(thisObj, fieldId);
    pointer = reinterpret_cast<jlong>(ref);
    env->SetLongField(thisObj, fieldId, pointer);

}

JNIEXPORT void JNICALL
Java_org_cryptokitty_modes_GCM_setAuthenticationData (JNIEnv *env, jobject thisObj,
                                                                            jbyteArray adIn) {

    CK::GCM *ref = getReference(env, thisObj);
    ByteArrayCodec adCodec(env, adIn);
    ref->setAuthenticationData(adCodec.getBytes());

}

JNIEXPORT void JNICALL
Java_org_cryptokitty_modes_GCM_setIV (JNIEnv *env, jobject thisObj, jbyteArray ivIn) {

    CK::GCM *ref = getReference(env, thisObj);
    ByteArrayCodec ivCodec(env, ivIn);
    ref->setIV(ivCodec.getBytes());

}

