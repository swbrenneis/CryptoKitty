#include "ByteArrayCodec.h"

ByteArrayCodec::ByteArrayCodec(JNIEnv *env, jbyteArray jniArray) {

    jbyte *inBytes = env->GetByteArrayElements(jniArray, NULL);
    uint8_t *ubytes = reinterpret_cast<uint8_t*>(inBytes);
    jsize length = env->GetArrayLength(jniArray);
    bytes = coder::ByteArray(ubytes, length);
    env->ReleaseByteArrayElements(jniArray, inBytes, 0);

}

ByteArrayCodec::ByteArrayCodec(JNIEnv *env, const coder::ByteArray& bytes) {

    uint8_t *byteArray = bytes.asArray();
    const signed char *cbuf = reinterpret_cast<const signed char*>(byteArray);
    jbytes = env->NewByteArray(bytes.getLength());
    env->SetByteArrayRegion(jbytes, 0, bytes.getLength(), cbuf);
    delete[] byteArray;

}

