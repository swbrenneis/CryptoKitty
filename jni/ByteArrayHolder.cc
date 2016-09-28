#include "ByteArrayHolder.h"

ByteArrayHolder::ByteArrayHolder(JNIEnv *env, jbyteArray jniArray) {

    jbyte *inBytes = env->GetByteArrayElements(jniArray, NULL);
    uint8_t *ubytes = reinterpret_cast<uint8_t*>(inBytes);
    jsize length = env->GetArrayLength(jniArray);
    bytes = coder::ByteArray(ubytes, length);
    env->ReleaseByteArrayElements(jniArray, inBytes, 0);

}
