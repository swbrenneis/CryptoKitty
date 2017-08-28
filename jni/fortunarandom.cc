#include "org_cryptokitty_random_FortunaSecureRandom.h"
#include <CryptoKitty-C/random/FortunaSecureRandom.h>
#include <coder/ByteArray.h>

JNIEXPORT void JNICALL
Java_org_cryptokitty_random_FortunaSecureRandom_nextBytes (JNIEnv *env, jobject thisObj,
                                                                jbyteArray bytes) {

    CK::FortunaSecureRandom rnd;
    jsize length = env->GetArrayLength(bytes);
    coder::ByteArray rndBytes(length, 0);
    rnd.nextBytes(rndBytes);
    uint8_t *rndArray = rndBytes.asArray();
    const signed char *cbuf = reinterpret_cast<const signed char*>(rndArray);
    env->SetByteArrayRegion(bytes, 0, length, cbuf);
    delete[] rndArray;

}

