#include "headers.h"

void allocateBuffers(struct dataStruct *st)
{
    st->cryptSt.yaxaKey = calloc(st->cryptSt.keyBufSize, sizeof(*st->cryptSt.yaxaKey));
    if (st->cryptSt.yaxaKey == NULL) {
        printSysError(errno);
        printError("Could not allocate yaxaKey buffer");
        exit(EXIT_FAILURE);
    }

    st->cryptSt.yaxaKeyChunk = calloc(YAXA_KEY_CHUNK_SIZE, sizeof(*st->cryptSt.yaxaKeyChunk));
    if (st->cryptSt.yaxaKeyChunk == NULL) {
        printSysError(errno);
        printError("Could not allocate yaxaKeyChunk buffer");
        exit(EXIT_FAILURE);
    }

    st->cryptSt.yaxaSalt = calloc(st->cryptSt.yaxaSaltSize, sizeof(*st->cryptSt.yaxaSalt));
    if (st->cryptSt.yaxaSalt == NULL) {
        printSysError(errno);
        printError("Could not allocate yaxaSalt buffer");
        exit(EXIT_FAILURE);
    }

    st->cryptSt.hmacKey = calloc(HMAC_KEY_SIZE, sizeof(*st->cryptSt.hmacKey));
    if (st->cryptSt.hmacKey == NULL) {
        printSysError(errno);
        printError("Could not allocate hmacKey buffer");
        exit(EXIT_FAILURE);
    }
}

void cleanUpBuffers(struct dataStruct *st)
{
    OPENSSL_cleanse(st->cryptSt.yaxaKey, st->cryptSt.keyBufSize);
    free(st->cryptSt.yaxaKey);
    OPENSSL_cleanse(st->cryptSt.hmacKey, HMAC_KEY_SIZE);
    free(st->cryptSt.hmacKey);
    OPENSSL_cleanse(st->cryptSt.yaxaKeyChunk, YAXA_KEY_CHUNK_SIZE);
    free(st->cryptSt.yaxaKeyChunk);
    
    OPENSSL_cleanse(st->cryptSt.userPass, strlen(st->cryptSt.userPass));
    OPENSSL_cleanse(st->cryptSt.userPassToVerify, strlen(st->cryptSt.userPassToVerify));

    free(st->cryptSt.yaxaSalt);
}
