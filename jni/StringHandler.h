#ifndef STRINGHANDLER_H_INCLUDED
#define STRINGHANDLER_H_INCLUDED

#include <jni.h>
#include <string>

class StringHandler {

    public:
        StringHandler(JNIEnv *env, jstring jniString);
        StringHandler(JNIEnv *env, const std::string& nativeString);
        ~StringHandler();

    private:
        StringHandler(const StringHandler& other);
        StringHandler& operator= (const StringHandler& other);

    public:
        const jstring getJNIString() const { return jniString; }
        const std::string& getNativeString() const { return nativeString; }

    private:
        JNIEnv *env;
        jstring jniString;
        const char *chars;
        std::string nativeString;

};

#endif // STRINGHANDLER_H_INCLUDED

