#include "org_cryptokitty_cipher_AES.h"
#include "ByteArrayHolder.h"
#include <CryptoKitty-C/cipher/AES.h>
#include <CryptoKitty-C/exceptions/BadParameterException.h>
#include <coder/ByteArray.h>
//#include <iostream>

/**
 * Retrieve the opaque pointer reference.
 */
static CK::AES *getReference(JNIEnv *env, jobject thisObj) {

    jclass thisClass = env->GetObjectClass(thisObj);
    // TODO Throw an exception if null.
    jfieldID fieldId = env->GetFieldID(thisClass, "pointer", "J");
    jlong pointer = env->GetLongField(thisObj, fieldId);
    return reinterpret_cast<CK::AES*>(pointer);

}

JNIEXPORT jbyteArray JNICALL
Java_org_cryptokitty_cipher_AES_decrypt (JNIEnv *env, jobject thisObj, jbyteArray ciphertextIn,
                                                                                jbyteArray keyIn) {

    CK::AES *ref = getReference(env, thisObj);
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
Java_org_cryptokitty_cipher_AES_encrypt (JNIEnv *env, jobject thisObj, jbyteArray plaintextIn,
                                                                                jbyteArray keyIn) {

    CK::AES *ref = getReference(env, thisObj);
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
Java_org_cryptokitty_cipher_AES_initialize (JNIEnv *env, jobject thisObj, jint keysize) {

    CK::AES::KeySize ks;
    switch (keysize) {
        case 16:
            ks = CK::AES::AES128;
            break;
        case 24:
            ks = CK::AES::AES192;
            break;
        case 32:
            ks = CK::AES::AES256;
            break;
    }
    CK::AES *ref = new CK::AES(ks);

    jclass thisClass = env->GetObjectClass(thisObj);
    // TODO Throw an exception if null.
    jfieldID fieldId = env->GetFieldID(thisClass, "pointer", "J");
    jlong pointer = env->GetLongField(thisObj, fieldId);
    pointer = reinterpret_cast<jlong>(ref);
    env->SetLongField(thisObj, fieldId, pointer);

}
