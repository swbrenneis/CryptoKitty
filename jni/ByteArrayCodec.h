#ifndef BYTEARRAYCODEC_H_INCLUDED
#define BYTEARRAYCODEC_H_INCLUDED

#include <jni.h>
#include <coder/ByteArray.h>

class ByteArrayCodec {

    public:
        ByteArrayCodec(JNIEnv *env, jbyteArray jniArray);
        ByteArrayCodec(JNIEnv *env, const coder::ByteArray& bytes);
        ~ByteArrayCodec() {}

    private:
        ByteArrayCodec(const ByteArrayCodec& other);
        ByteArrayCodec& operator =(const ByteArrayCodec& other);

    public:
        const coder::ByteArray& getBytes() const { return bytes; }
        jbyteArray getJBytes() const { return jbytes; }

    private:
        coder::ByteArray bytes;
        jbyteArray jbytes;

};

#endif // BYTEARRAYCODEC_H_INCLUDED
