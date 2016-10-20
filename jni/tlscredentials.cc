#include "org_cryptokitty_tls_TLSCredentials.h"
#include "ReferenceManager.h"
#include "StringHandler.h"
#include <tls/TLSCredentials.h>
#include <exceptions/TLSException.h>

/**
 * Retrieve the opaque jniImpl reference.
 */
static CK::TLSCredentials *getReference(JNIEnv *env, jobject thisObj) {

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
        return dynamic_cast<CK::TLSCredentials*>(ref);
    }

}

JNIEXPORT jobject JNICALL
Java_org_cryptokitty_tls_TLSCredentials_allocate (JNIEnv *env, jclass clazz) {

    jmethodID initId = env->GetMethodID(clazz, "<init>", "()V");
    jobject cred = env->NewObject(clazz, initId);
    jfieldID fieldId = env->GetFieldID(clazz, "jniImpl", "J");
    CK::TLSCredentials *ref = CK::TLSCredentials::allocate();
    jlong jniImpl = ReferenceManager::instance()->addRef(ref);
    env->SetLongField(cred, fieldId, jniImpl);
    return cred;

}

JNIEXPORT void JNICALL
Java_org_cryptokitty_tls_TLSCredentials_dispose (JNIEnv *env, jobject thisObj) {

    jclass thisClass = env->GetObjectClass(thisObj);
    jfieldID fieldId = env->GetFieldID(thisClass, "jniImpl", "J");
    jlong jniImpl = env->GetLongField(thisObj, fieldId);
    ReferenceManager::instance()->deleteRef(jniImpl);

}

JNIEXPORT void JNICALL
Java_org_cryptokitty_tls_TLSCredentials_setCRLFile (JNIEnv *env, jobject thisObj,
                                                        jstring crlpath, jint format) {

    CK::TLSCredentials *ref = getReference(env, thisObj);
    StringHandler handler(env,crlpath);
    try {
        ref->setCRLFile(handler.getNativeString(),
                                        static_cast<CK::TLSCredentials::Format>(format));
    }
    catch (CK::TLSException e) {
        jclass te = env->FindClass("org/cryptokitty/exceptions/TLSException");
        env->ThrowNew(te, e.what());
    }

}

JNIEXPORT void JNICALL
Java_org_cryptokitty_tls_TLSCredentials_setDiffieHellmanSecurity (JNIEnv *env, jobject thisObj,
                                                                                    jint sec) {

    CK::TLSCredentials *ref = getReference(env, thisObj);
    try {
        ref->setDiffieHellmanSecurity(static_cast<CK::TLSCredentials::Security>(sec));
    }
    catch (CK::TLSException e) {
        jclass te = env->FindClass("org/cryptokitty/exceptions/TLSException");
        env->ThrowNew(te, e.what());
    }

}

JNIEXPORT void JNICALL
Java_org_cryptokitty_tls_TLSCredentials_setKeyFile (JNIEnv *env, jobject thisObj, jstring certpath,
                                                                jstring keypath, jint format) {

    CK::TLSCredentials *ref = getReference(env, thisObj);
    StringHandler certHandler(env, certpath);
    StringHandler keyHandler(env, keypath);
    try {
        ref->setKeyFile(certHandler.getNativeString(), keyHandler.getNativeString(),
                                             static_cast<CK::TLSCredentials::Format>(format));
    }
    catch (CK::TLSException e) {
        jclass te = env->FindClass("org/cryptokitty/exceptions/TLSException");
        env->ThrowNew(te, e.what());
    }

}

JNIEXPORT void JNICALL
Java_org_cryptokitty_tls_TLSCredentials_setTrustFile (JNIEnv *env, jobject thisObj,
                                                        jstring capath, jint format) {

    CK::TLSCredentials *ref = getReference(env, thisObj);
    StringHandler handler(env,capath);
    try {
        ref->setTrustFile(handler.getNativeString(),
                                    static_cast<CK::TLSCredentials::Format>(format));
    }
    catch (CK::TLSException e) {
        jclass te = env->FindClass("org/cryptokitty/exceptions/TLSException");
        env->ThrowNew(te, e.what());
    }

}

