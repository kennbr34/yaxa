void allocateBuffers()
{
    yaxaKey = calloc(keyBufSize, sizeof(*yaxaKey));
    if (yaxaKey == NULL) {
        printSysError(errno);
        printError("Could not allocate yaxaKey buffer");
        exit(EXIT_FAILURE);
    }

    userPass = calloc(MAX_PASS_SIZE, sizeof(*userPass));
    if (userPass == NULL) {
        printSysError(errno);
        printError("Could not allocate userPass buffer");
        exit(EXIT_FAILURE);
    }
    
    userPassToVerify = calloc(MAX_PASS_SIZE, sizeof(*userPassToVerify));
    if (userPassToVerify == NULL) {
        printSysError(errno);
        printError("Could not allocate userPass buffer");
        exit(EXIT_FAILURE);
    }

    yaxaKeyChunk = calloc(YAXA_KEY_CHUNK_SIZE, sizeof(*yaxaKeyChunk));
    if (yaxaKeyChunk == NULL) {
        printSysError(errno);
        printError("Could not allocate yaxaKeyChunk buffer");
        exit(EXIT_FAILURE);
    }

    yaxaSalt = calloc(yaxaSaltSize, sizeof(*yaxaSalt));
    if (yaxaSalt == NULL) {
        printSysError(errno);
        printError("Could not allocate yaxaSalt buffer");
        exit(EXIT_FAILURE);
    }

    hmacKey = calloc(HMAC_KEY_SIZE, sizeof(*hmacKey));
    if (hmacKey == NULL) {
        printSysError(errno);
        printError("Could not allocate hmacKey buffer");
        exit(EXIT_FAILURE);
    }
}

void cleanUpBuffers()
{
    OPENSSL_cleanse(yaxaKey, keyBufSize);
    free(yaxaKey);
    OPENSSL_cleanse(hmacKey, HMAC_KEY_SIZE);
    free(hmacKey);
    OPENSSL_cleanse(yaxaKeyChunk, YAXA_KEY_CHUNK_SIZE);
    free(yaxaKeyChunk);
    OPENSSL_cleanse(userPass, strlen(userPass));
    free(userPass);
    OPENSSL_cleanse(userPassToVerify, strlen(userPassToVerify));
    free(userPassToVerify);

    free(yaxaSalt);
}
