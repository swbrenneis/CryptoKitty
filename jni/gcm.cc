#include "org_cryptokitty_modes_GCM.h"
#include "ByteArrayHolder.h"
#include <CryptoKitty-C/ciphermodes/GCM.h>
#include <CryptoKitty-C/cipher/BlockCipher.h>
#include <CryptoKitty-C/exceptions/BadParameterException.h>
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
    ByteArrayHolder ctHolder(env, ciphertextIn);
    ByteArrayHolder keyHolder(env, keyIn);
    // Do decryption
    try {
        coder::ByteArray plaintext(ref->decrypt(ctHolder.getBytes(), keyHolder.getBytes()));
        // Convert output array
        uint8_t *pbytes = plaintext.asArray();
        jbyte *jarray = reinterpret_cast<jbyte*>(pbytes);
        jbyteArray out = env->NewByteArray(plaintext.getLength());
        env->SetByteArrayRegion(out, 0, plaintext.getLength(), jarray);
        delete[] pbytes;
        return out;
    }
    catch (CK::BadParameterException& e) {
        jclass bpe = env->FindClass("org/cryptokitty/exceptions/BadParameterException");
        env->ThrowNew(bpe, e.what());
    }
    // Won't get here.
    return 0;

}

JNIEXPORT jbyteArray JNICALL
Java_org_cryptokitty_modes_GCM_encrypt (JNIEnv *env, jobject thisObj, jbyteArray plaintextIn,
                                                                            jbyteArray keyIn) {

    CK::GCM *ref = getReference(env, thisObj);
    // Retrieve plaintext and key
    ByteArrayHolder ptHolder(env, plaintextIn);
    ByteArrayHolder keyHolder(env, keyIn);
    try {
        // Do encryption
        coder::ByteArray ciphertext(ref->encrypt(ptHolder.getBytes(), keyHolder.getBytes()));
        // Convert output array
        uint8_t *cbytes = ciphertext.asArray();
        jbyte *jarray = reinterpret_cast<jbyte*>(cbytes);
        jbyteArray out = env->NewByteArray(ciphertext.getLength());
        env->SetByteArrayRegion(out, 0, ciphertext.getLength(), jarray);
        delete[] cbytes;
        return out;
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
    ByteArrayHolder adHolder(env, adIn);
    ref->setAuthenticationData(adHolder.getBytes());

}

JNIEXPORT void JNICALL
Java_org_cryptokitty_modes_GCM_setIV (JNIEnv *env, jobject thisObj, jbyteArray ivIn) {

    CK::GCM *ref = getReference(env, thisObj);
    ByteArrayHolder ivHolder(env, ivIn);
    ref->setIV(ivHolder.getBytes());

}

