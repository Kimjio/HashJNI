#include <stdio.h>
#include <string.h>
#include <malloc.h>
#include "sha.h"

SHA_INT_TYPE SHA1_K(SHA_INT_TYPE t) {
    if (t <= 19)return 0x5a827999;
    else if (t <= 39)return 0x6ed9eba1;
    else if (t <= 59)return 0x8f1bbcdc;
    else if (t <= 79)return 0xca62c1d6;
    return 0;
}

SHA_INT_TYPE SHA1_f(SHA_INT_TYPE t, SHA_INT_TYPE B, SHA_INT_TYPE C, SHA_INT_TYPE D) {
    if (t <= 19)return (B & C) | (~B & D);
    else if (t <= 39)return B ^ C ^ D;
    else if (t <= 59)return (B & C) | (B & D) | (C & D);
    else if (t <= 79)return B ^ C ^ D;
    return 0;
}

SHA_INT_TYPE SHA1_rotl(SHA_INT_TYPE r, SHA_INT_TYPE x) {
    SHA_INT_TYPE rot = r % 32;
    return (x >> (32 - rot)) | (x << rot);
}

void SHA_Reverse_INT64(unsigned char *data, uint64_t write) {
    unsigned char cdata[8];
    memcpy(cdata, &write, sizeof(uint64_t));
    for (int i = 0; i <= 7; i++)*(data + i) = cdata[7 - i];
}

SHA_INT_TYPE SHA_Reverse(SHA_INT_TYPE d) {
    unsigned char b_data[4], a_data[4];
    SHA_INT_TYPE ret;
    memcpy(b_data, &d, sizeof(int32_t));
    for (int i = 0; i < 4; i++)a_data[i] = b_data[3 - i];
    memcpy(&ret, a_data, sizeof(a_data));
    return ret;
}

void SHA1_HashBlock(SHA_INT_TYPE *SHA1_H_Data, const unsigned char *data) {
    SHA_INT_TYPE SIT[80];
    SHA_INT_TYPE SIT_d[16];
    SHA_INT_TYPE a, b, c, d, e;
    for (int i = 0, j = 0; i < 16; i++, j += 4)SIT_d[i] = static_cast<SHA_INT_TYPE>(
                ((*(data + j + 3) & 0xFF) << 24) |
                ((*(data + j + 2) & 0xFF) << 16) |
                ((*(data + j + 1) & 0xFF) << 8) |
                ((*(data + j) & 0xFF)));
    for (int i = 0; i < 16; i++)SIT[i] = SHA_Reverse(SIT_d[i]);
    for (int t = 16; t <= 79; t++)SIT[t] = SHA1_rotl(1, SIT[t - 3] ^ SIT[t - 8] ^ SIT[t - 14] ^
                                                        SIT[t - 16]);
    a = *SHA1_H_Data;
    b = *(SHA1_H_Data + 1);
    c = *(SHA1_H_Data + 2);
    d = *(SHA1_H_Data + 3);
    e = *(SHA1_H_Data + 4);
    for (int t = 0; t <= 79; t++) {
        SHA_INT_TYPE tmp;
        tmp = SHA1_rotl(5, a) + SHA1_f(static_cast<SHA_INT_TYPE>(t), b, c, d) + e + SIT[t] + SHA1_K(
                static_cast<SHA_INT_TYPE>(t));
        e = d;
        d = c;
        c = SHA1_rotl(30, b);
        b = a;
        a = tmp;
    }
    *SHA1_H_Data += a;
    *(SHA1_H_Data + 1) += b;
    *(SHA1_H_Data + 2) += c;
    *(SHA1_H_Data + 3) += d;
    *(SHA1_H_Data + 4) += e;
}

bool SHA1(SHA1_DATA *sha1d, const char *data, SHA_INT_TYPE size) {
    SHA_INT_TYPE s, h[5], ns;
    uint64_t s64;
    unsigned char d[64];
    if (!sha1d)return false;
    s = (size) ? size : strlen(data);
    memcpy(h, SHA1_H_Val, sizeof(SHA1_H_Val));

    for (SHA_INT_TYPE i = s, j = 0; i >= 64; i -= 64, j += 64)
        SHA1_HashBlock(h, (const unsigned char *) (data + j));

    ns = s % 64;

    memset(d, 0, 64);

    memcpy(d, data + (s - ns), ns);

    d[ns] = 0x80;

    if (ns >= 56) {
        SHA1_HashBlock(h, d);
        memset(d, 0, 56);
    }

    s64 = s * 8;

    SHA_Reverse_INT64(&d[56], s64);

    SHA1_HashBlock(h, d);
    memcpy(sha1d->Value, h, sizeof(h));
    sprintf(sha1d->Val_String, "%08X%08X%08X%08X%08X", h[0], h[1], h[2], h[3], h[4]);
    return true;
}