#include "org_cryptokitty_jni_BigInteger.h"
#include <CryptoKitty-C/data/BigInteger.h>

/**
 * Retrieve the opaque pointer reference.
 */
static CK::BigInteger *getReference(JNIEnv *env, jobject thisObj) {

    jclass thisClass = env->GetObjectClass(thisObj);
    // TODO Throw an exception if null.
    jfieldID fieldId = env->GetFieldID(thisClass, "pointer", "L");
    jlong pointer = env->GetLongField(thisObj, fieldId);
    return reinterpret_cast<CK::BigInteger*>(pointer);

}

JNIEXPORT void JNICALL
Java_org_cryptokitty_jni_BigInteger_initialize__ (JNIEnv *env, jobject thisObj) {

    jclass thisClass = env->GetObjectClass(thisObj);
    // TODO Throw an exception if null.
    jfieldID fieldId = env->GetFieldID(thisClass, "pointer", "L");
    jlong pointer = env->GetLongField(thisObj, fieldId);
    pointer = reinterpret_cast<jlong>(new CK::BigInteger);
    env->SetLongField(thisObj, fieldId, pointer);

}

JNIEXPORT void JNICALL
Java_org_cryptokitty_jni_BigInteger_initialize__J (JNIEnv *env, jobject thisObj, jlong lValue) {

    jclass thisClass = env->GetObjectClass(thisObj);
    // TODO Throw an exception if null.
    jfieldID fieldId = env->GetFieldID(thisClass, "pointer", "L");
    jlong pointer = env->GetLongField(thisObj, fieldId);
    pointer = reinterpret_cast<jlong>(new CK::BigInteger(lValue));
    env->SetLongField(thisObj, fieldId, pointer);

}

