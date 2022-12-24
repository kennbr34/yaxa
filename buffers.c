void allocateBuffers()
{
    cryptSt.yaxaKey = calloc(sizesSt.keyBufSize, sizeof(*cryptSt.yaxaKey));
    if (cryptSt.yaxaKey == NULL) {
        printSysError(errno);
        printError("Could not allocate yaxaKey buffer");
        exit(EXIT_FAILURE);
    }

    cryptSt.yaxaKeyChunk = calloc(YAXA_KEY_CHUNK_SIZE, sizeof(*cryptSt.yaxaKeyChunk));
    if (cryptSt.yaxaKeyChunk == NULL) {
        printSysError(errno);
        printError("Could not allocate yaxaKeyChunk buffer");
        exit(EXIT_FAILURE);
    }

    cryptSt.yaxaSalt = calloc(sizesSt.yaxaSaltSize, sizeof(*cryptSt.yaxaSalt));
    if (cryptSt.yaxaSalt == NULL) {
        printSysError(errno);
        printError("Could not allocate yaxaSalt buffer");
        exit(EXIT_FAILURE);
    }

    cryptSt.hmacKey = calloc(HMAC_KEY_SIZE, sizeof(*cryptSt.hmacKey));
    if (cryptSt.hmacKey == NULL) {
        printSysError(errno);
        printError("Could not allocate hmacKey buffer");
        exit(EXIT_FAILURE);
    }
}

void cleanUpBuffers()
{
    OPENSSL_cleanse(cryptSt.yaxaKey, sizesSt.keyBufSize);
    free(cryptSt.yaxaKey);
    OPENSSL_cleanse(cryptSt.hmacKey, HMAC_KEY_SIZE);
    free(cryptSt.hmacKey);
    OPENSSL_cleanse(cryptSt.yaxaKeyChunk, YAXA_KEY_CHUNK_SIZE);
    free(cryptSt.yaxaKeyChunk);
    
    OPENSSL_cleanse(cryptSt.userPass, strlen(cryptSt.userPass));
    OPENSSL_cleanse(cryptSt.userPassToVerify, strlen(cryptSt.userPassToVerify));

    free(cryptSt.yaxaSalt);
}
