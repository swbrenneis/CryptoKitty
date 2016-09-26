#include "org_cryptokitty_random_FortunaSecureRandom.h"
#include <CryptoKitty-C/random/FortunaSecureRandom.h>
#include <coder/ByteArray.h>
#include <memory>

/**
 * Retrieve the opaque pointer reference.
 */
static CK::FortunaSecureRandom *getReference(JNIEnv *env, jobject thisObj) {

    jclass thisClass = env->GetObjectClass(thisObj);
    // TODO Throw an exception if null.
    jfieldID fieldId = env->GetFieldID(thisClass, "pointer", "L");
    jlong pointer = env->GetLongField(thisObj, fieldId);
    return reinterpret_cast<CK::FortunaSecureRandom*>(pointer);

}

JNIEXPORT void JNICALL
Java_org_cryptokitty_random_FortunaSecureRandom_initialize (JNIEnv *env, jobject thisObj) {

    jclass thisClass = env->GetObjectClass(thisObj);
    // TODO Throw an exception if null.
    jfieldID fieldId = env->GetFieldID(thisClass, "pointer", "L");
    jlong pointer = env->GetLongField(thisObj, fieldId);
    pointer = reinterpret_cast<jlong>(new CK::FortunaSecureRandom);
    env->SetLongField(thisObj, fieldId, pointer);

}

JNIEXPORT void JNICALL
Java_org_cryptokitty_random_FortunaSecureRandom_nextBytes (JNIEnv *env, jobject thisObj,
                                                                jbyteArray bytes) {

    CK::FortunaSecureRandom *ref = getReference(env, thisObj);
    jsize length = env->GetArrayLength(bytes);
    coder::ByteArray rndBytes(length, 0);
    ref->nextBytes(rndBytes);
    uint8_t *rndArray = rndBytes.asArray();
    const signed char *cbuf = reinterpret_cast<const signed char*>(rndArray);
    env->SetByteArrayRegion(bytes, 0, length, cbuf);
    delete[] rndArray;

}

