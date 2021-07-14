void allocateBuffers()
{
    yaxaKey = calloc(YAXA_KEYBUF_SIZE, sizeof(*yaxaKey));
    if (yaxaKey == NULL) {
        printSysError(errno);
        printError("Could not allocate yaxaKey buffer");
        exit(EXIT_FAILURE);
    }

    userPass = calloc(YAXA_KEY_LENGTH, sizeof(*userPass));
    if (userPass == NULL) {
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

    yaxaSalt = calloc(YAXA_SALT_SIZE, sizeof(*yaxaSalt));
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
    OPENSSL_cleanse(yaxaKey, YAXA_KEYBUF_SIZE);
    free(yaxaKey);
    OPENSSL_cleanse(hmacKey, HMAC_KEY_SIZE);
    free(hmacKey);
    OPENSSL_cleanse(yaxaKeyChunk, YAXA_KEY_CHUNK_SIZE);
    free(yaxaKeyChunk);
    OPENSSL_cleanse(userPass, strlen(userPass));
    free(userPass);

    OPENSSL_cleanse(yaxaKeyArray, YAXA_KEYBUF_SIZE);

    free(yaxaSalt);
}
