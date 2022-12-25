void allocateBuffers(struct dataStruct *st)
{
    st->yaxaKey = calloc(st->keyBufSize, sizeof(*st->yaxaKey));
    if (st->yaxaKey == NULL) {
        printSysError(errno);
        printError("Could not allocate yaxaKey buffer");
        exit(EXIT_FAILURE);
    }

    st->yaxaKeyChunk = calloc(YAXA_KEY_CHUNK_SIZE, sizeof(*st->yaxaKeyChunk));
    if (st->yaxaKeyChunk == NULL) {
        printSysError(errno);
        printError("Could not allocate yaxaKeyChunk buffer");
        exit(EXIT_FAILURE);
    }

    st->yaxaSalt = calloc(st->yaxaSaltSize, sizeof(*st->yaxaSalt));
    if (st->yaxaSalt == NULL) {
        printSysError(errno);
        printError("Could not allocate yaxaSalt buffer");
        exit(EXIT_FAILURE);
    }

    st->hmacKey = calloc(HMAC_KEY_SIZE, sizeof(*st->hmacKey));
    if (st->hmacKey == NULL) {
        printSysError(errno);
        printError("Could not allocate hmacKey buffer");
        exit(EXIT_FAILURE);
    }
}

//void cleanUpBuffers()
//{
    //OPENSSL_cleanse(st->yaxaKey, st->keyBufSize);
    //free(st->yaxaKey);
    //OPENSSL_cleanse(st->hmacKey, HMAC_KEY_SIZE);
    //free(st->hmacKey);
    //OPENSSL_cleanse(st->yaxaKeyChunk, YAXA_KEY_CHUNK_SIZE);
    //free(st->yaxaKeyChunk);
    
    //OPENSSL_cleanse(st->userPass, strlen(st->userPass));
    //OPENSSL_cleanse(st->userPassToVerify, strlen(st->userPassToVerify));

    //free(st->yaxaSalt);
//}
