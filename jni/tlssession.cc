#include "org_cryptokitty_tls_TLSSession.h"
#include "ReferenceManager.h"
#include "StringHandler.h"
#include "ByteArrayCodec.h"
#include "SocketImpl.h"
#include <tls/TLSSession.h>
#include <tls/TLSCredentials.h>
#include <exceptions/TLSException.h>
#include <iostream>

/**
 * Retrieve the opaque jniImpl reference.
 */
static CK::TLSSession *getReference(JNIEnv *env, jobject thisObj) {

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
        return dynamic_cast<CK::TLSSession*>(ref);
    }

}

JNIEXPORT void JNICALL
Java_org_cryptokitty_tls_TLSSession_dispose (JNIEnv *env, jobject thisObj) {

    jclass thisClass = env->GetObjectClass(thisObj);
    jfieldID fieldId = env->GetFieldID(thisClass, "jniImpl", "J");
    jlong jniImpl = env->GetLongField(thisObj, fieldId);
    ReferenceManager::instance()->deleteRef(jniImpl);

}

JNIEXPORT jboolean JNICALL
Java_org_cryptokitty_tls_TLSSession_doHandshake (JNIEnv *env, jobject thisObj) {

    CK::TLSSession *ref = getReference(env, thisObj);
    return ref->doHandshake();

}

JNIEXPORT jstring JNICALL
Java_org_cryptokitty_tls_TLSSession_getCertificateError (JNIEnv *env, jobject thisObj) {

    CK::TLSSession *ref = getReference(env, thisObj);
    StringHandler handler(env, ref->getCertError());
    return handler.getJNIString();

}

JNIEXPORT jstring JNICALL
Java_org_cryptokitty_tls_TLSSession_getHostname (JNIEnv *env, jobject thisObj) {

    CK::TLSSession *ref = getReference(env, thisObj);
    StringHandler handler(env, ref->getHostname());
    return handler.getJNIString();

}

JNIEXPORT jstring JNICALL
Java_org_cryptokitty_tls_TLSSession_getLastError (JNIEnv *env, jobject thisObj) {

    CK::TLSSession *ref = getReference(env, thisObj);
    StringHandler handler(env, ref->getLastError());
    return handler.getJNIString();

}

JNIEXPORT jobject JNICALL
Java_org_cryptokitty_tls_TLSSession_initializeClient (JNIEnv *env, jclass clazz) {

    jmethodID initId = env->GetMethodID(clazz, "<init>", "()V");
    jobject session = env->NewObject(clazz, initId);
    jfieldID fieldId = env->GetFieldID(clazz, "jniImpl", "J");
    CK::TLSSession *ref = CK::TLSSession::initializeClient();
    jlong jniImpl = ReferenceManager::instance()->addRef(ref);
    env->SetLongField(session, fieldId, jniImpl);
    return session;

}

JNIEXPORT jobject JNICALL
Java_org_cryptokitty_tls_TLSSession_initializeServer (JNIEnv *env, jclass clazz) {

    jmethodID initId = env->GetMethodID(clazz, "<init>", "()V");
    jobject session = env->NewObject(clazz, initId);
    jfieldID fieldId = env->GetFieldID(clazz, "jniImpl", "J");
    CK::TLSSession *ref = CK::TLSSession::initializeServer();
    jlong jniImpl = ReferenceManager::instance()->addRef(ref);
    env->SetLongField(session, fieldId, jniImpl);
    return session;

}

JNIEXPORT jlong JNICALL
Java_org_cryptokitty_tls_TLSSession_receiveRecord (JNIEnv *env, jobject thisObj,
                                                                jbyteArray buffer, jlong count) {

    CK::TLSSession *ref = getReference(env, thisObj);
    coder::ByteArray data;
    long received = 0;
    try {
        received = ref->receiveRecord(data, count);
        uint8_t *byteArray = data.asArray();
        const signed char *cbuf = reinterpret_cast<const signed char*>(byteArray);
        env->SetByteArrayRegion(buffer, 0, data.getLength(), cbuf);
        delete[] byteArray;
    }
    catch (CK::TLSException& e) {
        jclass te = env->FindClass("org/cryptokitty/exceptions/TLSException");
        env->ThrowNew(te, e.what());
    }
    return received;

}

JNIEXPORT void JNICALL
Java_org_cryptokitty_tls_TLSSession_sendRecord (JNIEnv *env, jobject thisObj, jbyteArray data) {

    CK::TLSSession *ref = getReference(env, thisObj);
    ByteArrayCodec codec(env, data);
    try {
        ref->sendRecord(codec.getBytes());
    }
    catch (CK::TLSException& e) {
        jclass te = env->FindClass("org/cryptokitty/exceptions/TLSException");
        env->ThrowNew(te, e.what());
    }

}

JNIEXPORT void JNICALL
Java_org_cryptokitty_tls_TLSSession_setCredentials (JNIEnv *env, jobject thisObj,
                                                                        jobject credObj) {

    CK::TLSSession *ref = getReference(env, thisObj);
    jclass credClass = env->GetObjectClass(credObj);
    jfieldID fieldId = env->GetFieldID(credClass, "jniImpl", "J");
    jlong jniImpl = env->GetLongField(credObj, fieldId);
    CK::TLSCredentials *cred = dynamic_cast<CK::TLSCredentials*>
                                        (ReferenceManager::instance()->getRef(jniImpl));
    if (cred != 0) {
        try {
            ref->setCredentials(cred);
        }
        catch (CK::TLSException e) {
            jclass te = env->FindClass("org/cryptokitty/exceptions/TLSException");
            env->ThrowNew(te, e.what());
        }
    }
    else {
        jclass ise = env->FindClass("org/cryptokitty/exceptions/IllegalStateException");
        env->ThrowNew(ise, "Invalid JNI reference");
    }

}

JNIEXPORT void JNICALL
Java_org_cryptokitty_tls_TLSSession_setHostname (JNIEnv *env, jobject thisObj,
                                                                        jstring hostname) {

    CK::TLSSession *ref = getReference(env, thisObj);
    StringHandler handler(env, hostname);
    ref->setHostname(handler.getNativeString());

}

JNIEXPORT void JNICALL
Java_org_cryptokitty_tls_TLSSession_setRequireClientAuth (JNIEnv *env, jobject thisObj,
                                                                            jboolean require) {

    CK::TLSSession *ref = getReference(env, thisObj);
    ref->setRequireClientAuth(require);

}

JNIEXPORT jboolean JNICALL
Java_org_cryptokitty_tls_TLSSession_startSocketTransport (JNIEnv *env, jobject thisObj,
                                                                            jobject socketObj) {

    CK::TLSSession *ref = getReference(env, thisObj);
    jclass clazz = env->FindClass("org/cryptokitty/jni/BerkeleySocketImpl");
    jfieldID fdId = env->GetFieldID(clazz, "fd" , "I");
    jint fd = env->GetIntField(socketObj, fdId);
    return ref->startSocketTransport(fd);

}

