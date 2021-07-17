#define _FILE_OFFSET_BITS 64

#define printSysError(errCode) \
    { \
        fprintf(stderr, "%s:%s:%d: %s\n", __FILE__, __func__, __LINE__, strerror(errCode)); \
    }

#define printFileError(fileName, errCode) \
    { \
        fprintf(stderr, "%s: %s (Line: %i)\n", fileName, strerror(errCode), __LINE__); \
    }

#define printError(errMsg) \
    { \
        fprintf(stderr, "%s:%s:%d: %s\n", __FILE__, __func__, __LINE__, errMsg); \
    }

#define MAX_PASS_SIZE 512

#define YAXA_KEYBUF_SIZE (1024 * 1024) * 32

#define YAXA_KEY_CHUNK_SIZE SHA512_DIGEST_LENGTH

#define YAXA_SALT_SIZE YAXA_KEYBUF_SIZE / YAXA_KEY_CHUNK_SIZE

#define DEFAULT_SCRYPT_N 1048576

#define DEFAULT_SCRYPT_R 8

#define DEFAULT_SCRYPT_P 1

#define PASS_KEYED_HASH_SIZE SHA512_DIGEST_LENGTH

#define HMAC_KEY_SIZE SHA512_DIGEST_LENGTH

#define MAC_SIZE SHA512_DIGEST_LENGTH
