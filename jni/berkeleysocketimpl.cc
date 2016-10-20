#include "org_cryptokitty_jni_BerkeleySocketImpl.h"
#include "SocketImpl.h"
#include "SocketException.h"
#include "ReferenceManager.h"
#include "StringHandler.h"
#include <sstream>
//#include <iostream>

static const int SO_REUSEADDR = 4;

/**
 * Retrieve the opaque jniImpl reference.
 */
static SocketImpl *getReference(JNIEnv *env, jobject thisObj) {

    jclass thisClass = env->GetObjectClass(thisObj);
    jfieldID fieldId = env->GetFieldID(thisClass, "jniImpl", "J");
    jlong jniImpl = env->GetLongField(thisObj, fieldId);
    CK::JNIReference *ref = ReferenceManager::instance()->getRef(jniImpl);
    if (ref == 0) {
        jclass ise = env->FindClass("java/lang/IllegalStateException");
        env->ThrowNew(ise, "Invalid JNI reference");
        // Won't get here
        return 0;
    }
    else {
        return dynamic_cast<SocketImpl*>(ref);
    }

}

bool getBoolean(JNIEnv *env, jobject boolObj) {

    jclass clazz = env->GetObjectClass(boolObj);
    jmethodID getId = env->GetMethodID(clazz, "booleanValue", "()Z");
    return env->CallBooleanMethod(boolObj, getId);

}

JNIEXPORT jobject JNICALL
Java_org_cryptokitty_jni_BerkeleySocketImpl_accept (JNIEnv *env, jobject thisObj) {

    SocketImpl *ref = getReference(env, thisObj);
    try {
        SocketImpl::Accepted accepted = ref->accept();
        SocketImpl *newSocket = new SocketImpl(accepted.fd);
        newSocket->setHostname(accepted.address);
        long jniImpl = ReferenceManager::instance()->addRef(newSocket);
        jclass clazz = env->FindClass("org/cryptokitty/jni/BerkeleySocketImpl");
        jmethodID initId = env->GetMethodID(clazz, "<init>", "()V");
        jobject socketObj = env->NewObject(clazz, initId);
        jfieldID implId = env->GetFieldID(clazz, "jniImpl", "J");
        env->SetLongField(socketObj, implId, jniImpl);
        jfieldID fdId = env->GetFieldID(clazz, "fd", "I");
        env->SetIntField(socketObj, fdId, accepted.fd);
        return socketObj;
    }
    catch (SocketException& e) {
        jclass ioe = env->FindClass("org/cryptokitty/exceptions/CKSocketException");
        env->ThrowNew(ioe, e.what());
        // Won't get here
        return 0;
    }

}

JNIEXPORT void JNICALL
Java_org_cryptokitty_jni_BerkeleySocketImpl_bind (JNIEnv *env, jobject thisObj,
                                                            jstring hostname, jint port) {

    SocketImpl *ref = getReference(env, thisObj);
    try {
        StringHandler handler(env, hostname);
        ref->bind(handler.getNativeString(), port);
    }
    catch (SocketException& e) {
        jclass ioe = env->FindClass("org/cryptokitty/exceptions/CKSocketException");
        env->ThrowNew(ioe, e.what());
    }

}

JNIEXPORT void JNICALL
Java_org_cryptokitty_jni_BerkeleySocketImpl_close (JNIEnv *env, jobject thisObj) {

    SocketImpl *ref = getReference(env, thisObj);
    ref->close();

}

JNIEXPORT void JNICALL
Java_org_cryptokitty_jni_BerkeleySocketImpl_connect (JNIEnv *env, jobject thisObj,
                                                            jstring hostname, jint port) {

    SocketImpl *ref = getReference(env, thisObj);
    try {
        StringHandler handler(env, hostname);
        ref->connect(handler.getNativeString(), port, 0);
    }
    catch (SocketException& e) {
        jclass ioe = env->FindClass("org/cryptokitty/exceptions/CKSocketException");
        env->ThrowNew(ioe, e.what());
    }

}

JNIEXPORT void JNICALL
Java_org_cryptokitty_jni_BerkeleySocketImpl_create (JNIEnv *env, jobject thisObj,
                                                                    jboolean stream) {

    SocketImpl *ref = getReference(env, thisObj);
    try {
        if (stream) {
            ref->createTCPSocket();
        }
        else {
            ref->createUDPSocket();
        }
        jclass clazz = env->GetObjectClass(thisObj);
        jfieldID fdId = env->GetFieldID(clazz, "fd", "I");
        env->SetIntField(thisObj, fdId, ref->getSocket());
    }
    catch (SocketException& e) {
        jclass ioe = env->FindClass("org/cryptokitty/exceptions/CKSocketException");
        env->ThrowNew(ioe, e.what());
    }

}

JNIEXPORT jstring JNICALL
Java_org_cryptokitty_jni_BerkeleySocketImpl_getHostname (JNIEnv *env, jobject thisObj) {

    SocketImpl *ref = getReference(env, thisObj);
    //std::string hostname(ref->getHostname());
    //std::cout << "hostname = " << hostname << std::endl;
    StringHandler handler(env, ref->getHostname());
    return handler.getJNIString();

}

JNIEXPORT jlong JNICALL
Java_org_cryptokitty_jni_BerkeleySocketImpl_initialize (JNIEnv *, jobject) {

    SocketImpl *ref = new SocketImpl;
    return ReferenceManager::instance()->addRef(ref);

}

JNIEXPORT jboolean JNICALL
Java_org_cryptokitty_jni_BerkeleySocketImpl_isConnected (JNIEnv *env, jobject thisObj) {

    SocketImpl *ref = getReference(env, thisObj);
    return ref->isConnected();

}

JNIEXPORT void JNICALL
Java_org_cryptokitty_jni_BerkeleySocketImpl_listen (JNIEnv *env, jobject thisObj, jint backlog) {

    SocketImpl *ref = getReference(env, thisObj);
    try {
        ref->listen(backlog);
    }
    catch (SocketException& e) {
        jclass ioe = env->FindClass("org/cryptokitty/exceptions/CKSocketException");
        env->ThrowNew(ioe, e.what());
    }

}

JNIEXPORT void JNICALL
Java_org_cryptokitty_jni_BerkeleySocketImpl_setOption (JNIEnv *env, jobject thisObj, 
                                                        jint option, jobject optObj) {
    SocketImpl *ref = getReference(env, thisObj);
    try {
        switch (option) {
        case SO_REUSEADDR:
            {
            bool reuse = getBoolean(env, optObj);
            ref->setSocketOption(SO_REUSEADDR, reuse ? 1 : 0);
            }
            break;
        default:
            jclass se = env->FindClass("java/net/SocketException");
            std::ostringstream str;
            str << "Invalid socket option: " << option;
            env->ThrowNew(se, str.str().c_str());
        }
    }
    catch (SocketException& e) {
        jclass se = env->FindClass("java/net/SocketException");
        env->ThrowNew(se, e.what());
    }

}

