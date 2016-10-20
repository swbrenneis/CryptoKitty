#include "StringHandler.h"

StringHandler::StringHandler(JNIEnv *e, jstring str)
: env(e),
  jniString(str) {

    chars = env->GetStringUTFChars(str, NULL);
    nativeString = std::string(chars);

}

StringHandler::StringHandler(JNIEnv *env, const std::string& nativeString)
: env(0){

    jniString = env->NewStringUTF(nativeString.c_str());

}

StringHandler::~StringHandler() {

    if (env != 0) {
        env->ReleaseStringUTFChars(jniString, chars);
    }

}

