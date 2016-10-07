#include "org_cryptokitty_jni_BigInteger.h"
#include "ByteArrayCodec.h"
#include "ReferenceManager.h"
#include <CryptoKitty-C/data/BigInteger.h>
#include <CryptoKitty-C/random/FortunaSecureRandom.h>
#include <sstream>

/**
 * Retrieve the opaque jniImpl reference.
 */
static CK::BigInteger *getReference(JNIEnv *env, jobject thisObj) {

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
        return dynamic_cast<CK::BigInteger*>(ref);
    }

}

static jobject newBigInteger(JNIEnv *env, const CK::BigInteger& integer) {

    jclass biClass = env->FindClass("org/cryptokitty/jni/BigInteger");
    jmethodID initId = env->GetMethodID(biClass, "<init>", "()V");
    jobject biObj = env->NewObject(biClass, initId);
    jfieldID fieldId = env->GetFieldID(biClass, "jniImpl", "J");
    CK::BigInteger *ref = new CK::BigInteger(integer);
    jlong jniImpl = ReferenceManager::instance()->addRef(ref);
    env->SetLongField(biObj, fieldId, jniImpl);
    return biObj;

}

JNIEXPORT jobject JNICALL
Java_org_cryptokitty_jni_BigInteger_add (JNIEnv *env, jobject thisObj, jobject otherObj) {

    CK::BigInteger *ref = getReference(env, thisObj);
    CK::BigInteger *other = getReference(env, otherObj);
    return newBigInteger(env, ref->add(*other));

}

JNIEXPORT jobject JNICALL
Java_org_cryptokitty_jni_BigInteger_and (JNIEnv *env, jobject thisObj, jobject otherObj) {

    CK::BigInteger *ref = getReference(env, thisObj);
    CK::BigInteger *other = getReference(env, otherObj);
    return newBigInteger(env, ref->And(*other));

}

JNIEXPORT jint JNICALL
Java_org_cryptokitty_jni_BigInteger_bitLength (JNIEnv *env, jobject thisObj) {

    CK::BigInteger *ref = getReference(env, thisObj);
    return ref->bitLength();

}

JNIEXPORT jbyte JNICALL
Java_org_cryptokitty_jni_BigInteger_byteValue (JNIEnv *env, jobject thisObj) {

    CK::BigInteger *ref = getReference(env, thisObj);
    long lValue = ref->toLong();
    return lValue & 0xff;

}

JNIEXPORT jint JNICALL
Java_org_cryptokitty_jni_BigInteger_compareTo (JNIEnv *env, jobject thisObj, jobject otherObj) {

    CK::BigInteger *ref = getReference(env, thisObj);
    CK::BigInteger *other = getReference(env, otherObj);

    if (ref->equals(*other)) {
        return 0;
    }
    else if (ref->lessThan(*other)) {
        return -1;
    }
    else {
        return 1;
    }

}

JNIEXPORT jobject JNICALL
Java_org_cryptokitty_jni_BigInteger_copy (JNIEnv *env, jclass, jobject otherObj) {

    CK::BigInteger *ref = getReference(env, otherObj);
    return newBigInteger(env, *ref);

}

JNIEXPORT void JNICALL
Java_org_cryptokitty_jni_BigInteger_dispose (JNIEnv *env, jobject thisObj) {

    jclass thisClass = env->GetObjectClass(thisObj);
    jfieldID fieldId = env->GetFieldID(thisClass, "jniImpl", "J");
    jlong jniImpl = env->GetLongField(thisObj, fieldId);
    ReferenceManager::instance()->deleteRef(jniImpl);

}

JNIEXPORT jobject JNICALL
Java_org_cryptokitty_jni_BigInteger_gcd (JNIEnv *env, jobject thisObj, jobject otherObj) {

    CK::BigInteger *ref = getReference(env, thisObj);
    CK::BigInteger *other = getReference(env, otherObj);
    return newBigInteger(env, ref->gcd(*other));

}

JNIEXPORT jbyteArray JNICALL
Java_org_cryptokitty_jni_BigInteger_getEncoded (JNIEnv *env, jobject thisObj) {

    CK::BigInteger *ref = getReference(env, thisObj);
    ByteArrayCodec encoded(env, ref->getEncoded(CK::BigInteger::BIGENDIAN));
    return encoded.getJBytes();

}

JNIEXPORT jlong JNICALL
Java_org_cryptokitty_jni_BigInteger_initialize__ (JNIEnv *, jobject) {

    return reinterpret_cast<jlong>(new CK::BigInteger);

}

JNIEXPORT jlong JNICALL
Java_org_cryptokitty_jni_BigInteger_initialize__J (JNIEnv *env, jobject thisObj, jlong lValue) {

    return reinterpret_cast<jlong>(new CK::BigInteger(lValue));

}

JNIEXPORT jlong JNICALL
Java_org_cryptokitty_jni_BigInteger_initialize___3B (JNIEnv *env, jobject thisObj,
                                                                    jbyteArray encoded) {

    ByteArrayCodec eCodec(env, encoded);
    return reinterpret_cast<jlong>(
                    new CK::BigInteger(eCodec.getBytes(), CK::BigInteger::BIGENDIAN));

}

JNIEXPORT jobject JNICALL
Java_org_cryptokitty_jni_BigInteger_mod (JNIEnv *env, jobject thisObj, jobject otherObj) {

    CK::BigInteger *ref = getReference(env, thisObj);
    CK::BigInteger *other = getReference(env, otherObj);
    return newBigInteger(env, ref->mod(*other));

}

JNIEXPORT jobject JNICALL
Java_org_cryptokitty_jni_BigInteger_modInverse (JNIEnv *env, jobject thisObj, jobject otherObj) {

    CK::BigInteger *ref = getReference(env, thisObj);
    CK::BigInteger *other = getReference(env, otherObj);
    return newBigInteger(env, ref->modInverse(*other));

}

JNIEXPORT jobject JNICALL
Java_org_cryptokitty_jni_BigInteger_modPow (JNIEnv *env, jobject thisObj, jobject expObj,
                                                                            jobject modObj) {

    CK::BigInteger *me = getReference(env, thisObj);
    CK::BigInteger *exp = getReference(env, expObj);
    CK::BigInteger *mod = getReference(env, modObj);
    return newBigInteger(env, me->modPow(*exp, *mod));

}

JNIEXPORT jobject JNICALL
Java_org_cryptokitty_jni_BigInteger_multiply (JNIEnv *env, jobject thisObj, jobject otherObj) {

    CK::BigInteger *ref = getReference(env, thisObj);
    CK::BigInteger *other = getReference(env, otherObj);
    return newBigInteger(env, ref->multiply(*other));

}

JNIEXPORT jobject JNICALL
Java_org_cryptokitty_jni_BigInteger_or (JNIEnv *env, jobject thisObj, jobject otherObj) {

    CK::BigInteger *ref = getReference(env, thisObj);
    CK::BigInteger *other = getReference(env, otherObj);
    return newBigInteger(env, ref->Or(*other));

}

JNIEXPORT jobject JNICALL
Java_org_cryptokitty_jni_BigInteger_pow (JNIEnv *env, jobject thisObj, jlong exp) {

    CK::BigInteger *ref = getReference(env, thisObj);
    return newBigInteger(env, ref->pow(exp));

}

JNIEXPORT jobject JNICALL
Java_org_cryptokitty_jni_BigInteger_probablePrime (JNIEnv *env, jclass, jint bitsize) {

    CK::FortunaSecureRandom rnd;
    CK::BigInteger *bi = new CK::BigInteger(bitsize, false, rnd);
    jclass biClass = env->FindClass("org/cryptokitty/jni/BigInteger");
    jmethodID biInitId = env->GetMethodID(biClass, "<init>", "()V");
    jobject newBI = env->NewObject(biClass, biInitId);
    jfieldID fieldId = env->GetFieldID(biClass, "jniImpl", "J");
    jlong jniImpl = reinterpret_cast<jlong>(bi);
    env->SetLongField(newBI, fieldId, jniImpl);

    return newBI;

}

JNIEXPORT jobject JNICALL
Java_org_cryptokitty_jni_BigInteger_shiftLeft (JNIEnv *env, jobject thisObj, jlong count) {

    CK::BigInteger *ref = getReference(env, thisObj);
    return newBigInteger(env, ref->leftShift(count));

}

JNIEXPORT jobject JNICALL
Java_org_cryptokitty_jni_BigInteger_shiftRight (JNIEnv *env, jobject thisObj, jlong count) {

    CK::BigInteger *ref = getReference(env, thisObj);
    return newBigInteger(env, ref->rightShift(count));

}

JNIEXPORT jobject JNICALL
Java_org_cryptokitty_jni_BigInteger_subtract (JNIEnv *env, jobject thisObj, jobject otherObj) {

    CK::BigInteger *ref = getReference(env, thisObj);
    CK::BigInteger *other = getReference(env, otherObj);
    return newBigInteger(env, ref->subtract(*other));

}

JNIEXPORT jstring JNICALL
Java_org_cryptokitty_jni_BigInteger_toString (JNIEnv *env, jobject thisObj) {

    CK::BigInteger *ref = getReference(env, thisObj);
    std::ostringstream str;
    str << *ref;
    return env->NewStringUTF(str.str().c_str());

}

