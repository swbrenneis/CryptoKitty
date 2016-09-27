#include "org_cryptokitty_jni_BigInteger.h"
#include <CryptoKitty-C/data/BigInteger.h>
#include <CryptoKitty-C/random/FortunaSecureRandom.h>
#include <sstream>

/**
 * Retrieve the opaque pointer reference.
 */
static CK::BigInteger *getReference(JNIEnv *env, jobject thisObj) {

    jclass thisClass = env->GetObjectClass(thisObj);
    // TODO Throw an exception if null.
    jfieldID fieldId = env->GetFieldID(thisClass, "pointer", "J");
    jlong pointer = env->GetLongField(thisObj, fieldId);
    if (pointer != 0) {
        return reinterpret_cast<CK::BigInteger*>(pointer);
    }
    else {
        CK::BigInteger *ref = new CK::BigInteger;
        pointer = reinterpret_cast<jlong>(ref);
        env->SetLongField(thisObj, fieldId, pointer);
        return ref;
    }

}

JNIEXPORT jint JNICALL
Java_org_cryptokitty_jni_BigInteger_bitLength (JNIEnv *env, jobject thisObj) {

    CK::BigInteger *ref = getReference(env, thisObj);
    return ref->bitLength();

}

JNIEXPORT void JNICALL
Java_org_cryptokitty_jni_BigInteger_initialize (JNIEnv *env, jobject thisObj, jlong lValue) {

    jclass thisClass = env->GetObjectClass(thisObj);
    // TODO Throw an exception if null.
    jfieldID fieldId = env->GetFieldID(thisClass, "pointer", "J");
    jlong pointer = env->GetLongField(thisObj, fieldId);
    pointer = reinterpret_cast<jlong>(new CK::BigInteger(lValue));
    env->SetLongField(thisObj, fieldId, pointer);

}

JNIEXPORT jobject JNICALL
Java_org_cryptokitty_jni_BigInteger_modPow (JNIEnv *env, jobject thisObj, jobject expObj,
                                                                            jobject modObj) {

    CK::BigInteger *me = getReference(env, thisObj);
    CK::BigInteger *exp = getReference(env, expObj);
    CK::BigInteger *mod = getReference(env, modObj);
    CK::BigInteger *answer = new CK::BigInteger(me->modPow(*exp, *mod));

    jclass biClass = env->FindClass("org/cryptokitty/jni/BigInteger");
    jmethodID biInitId = env->GetMethodID(biClass, "<init>", "()V");
    jobject newBI = env->NewObject(biClass, biInitId);
    jfieldID fieldId = env->GetFieldID(biClass, "pointer", "J");
    jlong pointer = reinterpret_cast<jlong>(answer);
    env->SetLongField(newBI, fieldId, pointer);

    return newBI;

}

JNIEXPORT jobject JNICALL
Java_org_cryptokitty_jni_BigInteger_probablePrime (JNIEnv *env, jclass, jint bitsize) {

    CK::FortunaSecureRandom rnd;
    CK::BigInteger *bi = new CK::BigInteger(bitsize, false, rnd);
    jclass biClass = env->FindClass("org/cryptokitty/jni/BigInteger");
    jmethodID biInitId = env->GetMethodID(biClass, "<init>", "()V");
    jobject newBI = env->NewObject(biClass, biInitId);
    jfieldID fieldId = env->GetFieldID(biClass, "pointer", "J");
    jlong pointer = reinterpret_cast<jlong>(bi);
    env->SetLongField(newBI, fieldId, pointer);

    return newBI;

}

JNIEXPORT jstring JNICALL
Java_org_cryptokitty_jni_BigInteger_toString (JNIEnv *env, jobject thisObj) {

    CK::BigInteger *ref = getReference(env, thisObj);
    std::ostringstream str;
    str << *ref;
    return env->NewStringUTF(str.str().c_str());

}

