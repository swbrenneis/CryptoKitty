#include <jni.h>
#include <coder/ByteArray.h>

class ByteArrayHolder {

    public:
        ByteArrayHolder(JNIEnv *env, jbyteArray jniArray);
        ~ByteArrayHolder() {}

    private:
        ByteArrayHolder(const ByteArrayHolder& other);
        ByteArrayHolder& operator =(const ByteArrayHolder& other);

    public:
        const coder::ByteArray& getBytes() const { return bytes; }

    private:
        coder::ByteArray bytes;

};

