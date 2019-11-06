#include <jni.h>
#include <string>
#include <cstdlib>
#include "sha.h"

using namespace std;

typedef long long longlong;
typedef unsigned long long ulonglong;
typedef int8_t byte;

/*
 * Pointer 전역 필수
 */
ulonglong stringAddress;
char *__dest;
char *__dest2;
char *string1;
char *string2;
char *stringUTF;


SHA_INT_TYPE *
GenHash(JNIEnv *env, jstring jidtoken, jstring jtimestamp) {
    uint timestamp;
    uint timestampAbs;
    size_t stringUTFLength;
    ulonglong idTokenLength;
    bool notZero;
    SHA1_DATA *sha1Data;

    stringUTF = const_cast<char *>(env->GetStringUTFChars(jtimestamp, nullptr));
    stringUTFLength = strlen(stringUTF);
    if ((int) stringUTFLength < 1) {
        timestamp = 0;
    } else {
        longlong i = 0;
        longlong append = 0;
        byte charAt;
        do {
            timestamp = (uint) append;
            charAt = stringUTF[i++];
            if (9 < (byte) (charAt - 0x30)) break; //NOT NUMBER -> BREAK
            append = (ulonglong) charAt + append * 10 + -0x30;
            timestamp = (uint) append;
        } while (i < (int) stringUTFLength);
    }
    stringUTF = const_cast<char *>(env->GetStringUTFChars(jidtoken, nullptr));
    timestampAbs = static_cast<uint>(abs(static_cast<int>(timestamp)));
    stringAddress = 0;
    __dest2 = (char *) 0;
    stringUTFLength = strlen(stringUTF);
    idTokenLength = (ulonglong) stringUTFLength;
    if (0xffffffffffffffef < idTokenLength) {
        return nullptr;
    }
    if (stringUTFLength < 0x17) {
        __dest = (char *) ((ulonglong) &stringAddress | 1);
        stringAddress =
                stringAddress & 0xffffffffffffff00 | (ulonglong) (byte) (stringUTFLength << 1);
        string1 = __dest;
        if (stringUTFLength != 0)
            memcpy(__dest, stringUTF, stringUTFLength);
    } else {
        ulonglong newLength = idTokenLength + 0x10 & 0xfffffffffffffff0;
        __dest = new char[(u_long) newLength];
        stringAddress = newLength | 1;
        string1 = (char *) ((ulonglong) &stringAddress | 1);
        __dest2 = __dest;
        memcpy(__dest, stringUTF, stringUTFLength);
    }
    __dest[idTokenLength] = '\0';
    stringUTF = (char *) ((longlong) &stringAddress + 1);
    notZero = (stringAddress & 1) != 0;
    __dest = notZero ? __dest2 : stringUTF;
    string2 = notZero ? __dest2 : string1;
    string2[(ulonglong) timestampAbs & 3] =
            __dest[timestampAbs - (timestampAbs / 5 +
                                   ((uint) (
                                           (ulonglong) timestampAbs *
                                           0xcccccccd
                                                   >> 0x20) &
                                    0xfffffffc))];
    notZero = (stringAddress & 1) != 0;
    __dest = notZero ? __dest2 : stringUTF;
    string2 = notZero ? __dest2 : string1;
    timestamp = timestampAbs / 0x1e + 5;
    string2[(ulonglong) ((timestampAbs >> 3) % 6) + 2] =
            __dest[
                    (timestampAbs - (timestampAbs / 3 +
                                     ((uint) ((ulonglong) timestampAbs * 0xaaaaaaab >> 0x20) &
                                      0xfffffffe))) *
                    2];
    notZero = (stringAddress & 1) != 0;
    __dest = notZero ? __dest2 : string1;
    if (notZero) {
        stringUTF = __dest2;
    }
    __dest[(ulonglong) timestampAbs / 5 & 7] =
            stringUTF[timestamp - (timestamp / 5 +
                                   ((uint) (
                                           (ulonglong) timestamp *
                                           0xcccccccd
                                                   >> 0x20) &
                                    0xfffffffc))];

    if ((stringAddress & 1) != 0) {
        string1 = __dest2;
    }

    SHA1(sha1Data = new SHA1_DATA, string1, 0);

    return sha1Data->Value;
}

extern "C" JNIEXPORT jintArray JNICALL
Java_com_kimjio_hash_HashTool_getHashBytes(
        JNIEnv *env,
        jclass /* this */,
        jstring idToken,
        jstring timestamp) {
    jintArray array = env->NewIntArray(5);
    SHA_INT_TYPE *shaBytes = GenHash(env, idToken, timestamp);
    env->SetIntArrayRegion(array, 0, 5, reinterpret_cast<const jint *>(shaBytes));
    return array;
}
