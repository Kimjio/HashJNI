typedef uint32_t SHA_INT_TYPE;

typedef struct tagSHA1_DATA {
    SHA_INT_TYPE Value[5];
    char Val_String[45];
} SHA1_DATA;

const SHA_INT_TYPE SHA1_H_Val[] = {0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0};

SHA_INT_TYPE SHA1_K(SHA_INT_TYPE);

SHA_INT_TYPE SHA1_f(SHA_INT_TYPE, SHA_INT_TYPE, SHA_INT_TYPE, SHA_INT_TYPE);

SHA_INT_TYPE SHA1_rotl(SHA_INT_TYPE, SHA_INT_TYPE);

SHA_INT_TYPE SHA_Reverse(SHA_INT_TYPE);

void SHA1_HashBlock(SHA_INT_TYPE *, const unsigned char *);

bool SHA1(SHA1_DATA *, const char *, SHA_INT_TYPE);
