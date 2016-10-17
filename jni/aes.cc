#include "org_cryptokitty_cipher_AES.h"
#include "ByteArrayCodec.h"
#include "ReferenceManager.h"
#include <CryptoKitty-C/cipher/AES.h>
#include <CryptoKitty-C/exceptions/BadParameterException.h>
#include <coder/ByteArray.h>
//#include <iostream>

/**
 * Retrieve the opaque jniImpl reference.
 */
static CK::AES *getReference(JNIEnv *env, jobject thisObj) {

    jclass thisClass = env->GetObjectClass(thisObj);
    jfieldID fieldId = env->GetFieldID(thisClass, "jniImpl", "J");
    jlong jniImpl = env->GetLongField(thisObj, fieldId);
    CK::JNIReference *ref = ReferenceManager::instance()->getRef(jniImpl);
    if (ref == 0) {
        jclass ise = env->FindClass("org/cryptokitty/exceptions/IllegalStateException");
        env->ThrowNew(ise, "Invalid JNI reference");
        // Won't get here
        return 0;
    }
    else {
        return dynamic_cast<CK::AES*>(ref);
    }

}

JNIEXPORT jbyteArray JNICALL
Java_org_cryptokitty_cipher_AES_decrypt (JNIEnv *env, jobject thisObj, jbyteArray ciphertextIn,
                                                                                jbyteArray keyIn) {

    CK::AES *ref = getReference(env, thisObj);
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
    // Won't get here.
    return 0;

}

JNIEXPORT void JNICALL
Java_org_cryptokitty_cipher_AES_dispose (JNIEnv *env, jobject thisObj) {

    jclass thisClass = env->GetObjectClass(thisObj);
    jfieldID fieldId = env->GetFieldID(thisClass, "jniImpl", "J");
    jlong jniImpl = env->GetLongField(thisObj, fieldId);
    ReferenceManager::instance()->deleteRef(jniImpl);

}

JNIEXPORT jbyteArray JNICALL
Java_org_cryptokitty_cipher_AES_encrypt (JNIEnv *env, jobject thisObj, jbyteArray plaintextIn,
                                                                                jbyteArray keyIn) {

    CK::AES *ref = getReference(env, thisObj);
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

JNIEXPORT jlong JNICALL
Java_org_cryptokitty_cipher_AES_initialize (JNIEnv *env, jobject thisobj, jint keysize) {

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
    return ReferenceManager::instance()->addRef(ref);

}
