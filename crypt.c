void doCrypt(FILE *inFile, FILE *outFile, cryptint_t fileSize, FILE *otpInFile, FILE *otpOutFile, struct dataStruct *st)
{
    
    #ifdef gui
    *(st->progressFraction) = 0.0;
    #endif
    
    uint8_t *inBuffer = calloc(st->msgBufSize,sizeof(*inBuffer)), *outBuffer = calloc(st->msgBufSize,sizeof(*outBuffer));
    if (inBuffer == NULL || outBuffer == NULL) {
        printSysError(errno);
        printError("Could not allocate memory for doCrypt buffers");
        exit(EXIT_FAILURE);
    }
    
    
    if(otpInFile != NULL) {
        st->otpBuffer = calloc(st->msgBufSize,sizeof(*st->otpBuffer));
        if (st->otpBuffer == NULL) {
            printSysError(errno);
            printError("Could not allocate memory for doCrypt buffers");
            exit(EXIT_FAILURE);
        }
    }
    
    /*Initiate HMAC*/
    HMAC_CTX *ctx = HMAC_CTX_new();
    HMAC_Init_ex(ctx, st->hmacKey, HMAC_KEY_SIZE, EVP_sha512(), NULL);
    
    HMAC_Update(ctx, st->yaxaSalt, sizeof(*st->yaxaSalt) * st->yaxaSaltSize);
    HMAC_Update(ctx, st->passKeyedHash, sizeof(*st->passKeyedHash) * PASS_KEYED_HASH_SIZE);
    
    cryptint_t remainingBytes = fileSize;
    cryptint_t outInt, inInt;

    cryptint_t i;
    for (i = 0; remainingBytes; i += st->msgBufSize) {
        
        if(st->msgBufSize > remainingBytes) {
            st->msgBufSize = remainingBytes;
        }

        if (freadWErrCheck(inBuffer, sizeof(*inBuffer) * st->msgBufSize, 1, inFile, st) != 0) {
            printSysError(st->returnVal);
            printError("Could not read file for encryption/decryption");
            exit(EXIT_FAILURE);
        }
        
        if(otpInFile != NULL) {
            if (freadWErrCheck(st->otpBuffer, sizeof(*st->otpBuffer) * st->msgBufSize, 1, otpInFile, st) != 0) {
                printSysError(st->returnVal);
                printError("Could not read OTP file for encryption/decryption");
                exit(EXIT_FAILURE);
            }
        }

        for(uint32_t j = 0; j < st->msgBufSize; j += sizeof(inInt)) {
            memcpy(&inInt,inBuffer + j,sizeof(inInt));
            outInt = yaxa(inInt,st);
            memcpy(outBuffer + j,&outInt,sizeof(outInt));
        }

        if (fwriteWErrCheck(outBuffer, sizeof(*outBuffer) * st->msgBufSize, 1, outFile, st) != 0) {
            printSysError(st->returnVal);
            printError("Could not write file for encryption/decryption");
            exit(EXIT_FAILURE);
        }
        
        HMAC_Update(ctx, outBuffer, sizeof(*outBuffer) * st->msgBufSize);
        
        if(otpInFile != NULL && otpOutFile != NULL) {
            if (fwriteWErrCheck(st->otpBuffer, sizeof(*st->otpBuffer) * st->msgBufSize, 1, otpOutFile, st) != 0) {
                printSysError(st->returnVal);
                printError("Could not write file for encryption/decryption");
                exit(EXIT_FAILURE);
            }
        }
        
        #ifdef gui
        *(st->progressFraction) = (double)i / (double)fileSize;
        #endif
        remainingBytes -= st->msgBufSize;
    }
    
    i += st->yaxaSaltSize + PASS_KEYED_HASH_SIZE;
    HMAC_Final(ctx, st->generatedMAC, (unsigned int *)&i);
    HMAC_CTX_free(ctx);
    
    free(inBuffer);
    free(outBuffer);
}

void genHMAC(FILE *dataFile, cryptint_t fileSize, struct dataStruct *st)
{
    #ifdef gui
    *(st->progressFraction) = 0.0;
    #endif
    
    uint8_t *genHmacBuffer = malloc(st->genHmacBufSize * sizeof(*genHmacBuffer));
    if (genHmacBuffer == NULL) {
        printSysError(errno);
        printError("Could not allocate memory for genHmacBuffer");
        exit(EXIT_FAILURE);
    }
    cryptint_t remainingBytes = fileSize;

    /*Initiate HMAC*/
    HMAC_CTX *ctx = HMAC_CTX_new();
    HMAC_Init_ex(ctx, st->hmacKey, HMAC_KEY_SIZE, EVP_sha512(), NULL);

    /*HMAC the cipher-text, passtag and salt*/
    cryptint_t i; /*Declare i outside of for loop so it can be used in HMAC_Final as the size*/
    for (i = 0; remainingBytes; i += st->genHmacBufSize) {
        
        if(st->genHmacBufSize > remainingBytes) {
            st->genHmacBufSize = remainingBytes;
        }
        
        if (freadWErrCheck(genHmacBuffer, sizeof(*genHmacBuffer) * st->genHmacBufSize, 1, dataFile, st) != 0) {
            printSysError(st->returnVal);
            printError("Could not generate HMAC");
            exit(EXIT_FAILURE);
        }
        HMAC_Update(ctx, genHmacBuffer, sizeof(*genHmacBuffer) * st->genHmacBufSize);
        
        remainingBytes -= st->genHmacBufSize;
        #ifdef gui
        *(st->progressFraction) = (double)i/(double)fileSize;
        #endif
    }
    HMAC_Final(ctx, st->generatedMAC, (unsigned int *)&i);
    HMAC_CTX_free(ctx);
    free(genHmacBuffer);
}

void genHMACKey(struct dataStruct *st)
{
    
    #ifdef gui
    strcpy(st->statusMessage,"Deriving auth key...");
    #endif

    EVP_PKEY_CTX *pctx;
    size_t outlen = sizeof(*st->hmacKey) * HMAC_KEY_SIZE;
    pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
    
    if (EVP_PKEY_derive_init(pctx) <= 0) {
        printError("HKDF failed\n");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    if (EVP_PKEY_CTX_set_hkdf_md(pctx, EVP_sha512()) <= 0) {
        printError("HKDF failed\n");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    if (EVP_PKEY_CTX_set1_hkdf_key(pctx, st->yaxaKey, sizeof(*st->yaxaKey) * st->keyBufSize) <= 0) {
        printError("HKDF failed\n");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    if (EVP_PKEY_CTX_add1_hkdf_info(pctx, "authkey", strlen("authkey")) <= 0) {
        printError("HKDF failed\n");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    if (EVP_PKEY_derive(pctx, st->hmacKey, &outlen) <= 0) {
        printError("HKDF failed\n");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    
    EVP_PKEY_CTX_free(pctx);
}

void genPassTag(struct dataStruct *st)
{
    
    #ifdef gui
    *(st->progressFraction) = 0;
    #endif
    
    if (HMAC(EVP_sha512(), st->hmacKey, HMAC_KEY_SIZE, (const unsigned char *)st->userPass, strlen(st->userPass), st->passKeyedHash, st->HMACLengthPtr) == NULL) {
        printError("Password keyed-hash failure");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    
    #ifdef gui
    *(st->progressFraction) = 1;
    #endif
}

void genYaxaKey(struct dataStruct *st)
{
    #ifdef gui
    *(st->progressFraction) = 0;
    double keyChunkFloat = YAXA_KEY_CHUNK_SIZE;
    double keyBufFloat = st->keyBufSize;
    #endif
    
    /*Derive a 64-byte key to expand*/
    EVP_PKEY_CTX *pctx;

    size_t outlen = sizeof(*st->yaxaKeyChunk) * YAXA_KEY_CHUNK_SIZE;
    pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_SCRYPT, NULL);

    if (EVP_PKEY_derive_init(pctx) <= 0) {
        printError("scrypt failed\n");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    if (EVP_PKEY_CTX_set1_pbe_pass(pctx, st->userPass, strlen(st->userPass)) <= 0) {
        printError("scrypt failed\n");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    if (EVP_PKEY_CTX_set1_scrypt_salt(pctx, st->yaxaSalt, sizeof(*st->yaxaSalt) * st->yaxaSaltSize) <= 0) {
        printError("scrypt failed\n");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    if (EVP_PKEY_CTX_set_scrypt_N(pctx, st->nFactor) <= 0) {
        printError("scrypt failed\n");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    if (EVP_PKEY_CTX_set_scrypt_r(pctx, st->rFactor) <= 0) {
        printError("scrypt failed\n");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    if (EVP_PKEY_CTX_set_scrypt_p(pctx, st->pFactor) <= 0) {
        printError("scrypt failed\n");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    if (EVP_PKEY_derive(pctx, st->yaxaKeyChunk, &outlen) <= 0) {
        printError("scrypt failed\n");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    EVP_PKEY_CTX_free(pctx);
    
    /*Copy that first 64-byte chunk into the yaxaKeyArray*/
    memcpy(st->yaxaKey, st->yaxaKeyChunk, sizeof(*st->yaxaKeyChunk) * YAXA_KEY_CHUNK_SIZE);
    
    #ifdef gui
    *(st->progressFraction) = keyChunkFloat / keyBufFloat;
    #endif

    /*Expand that 64-byte key into keyBufSize key*/
    for (int i = 1; i < st->yaxaSaltSize; i++) {
                
        EVP_PKEY_CTX *pctx;
        size_t outlen = sizeof(*st->yaxaKeyChunk) * YAXA_KEY_CHUNK_SIZE;
        pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
        
        if (EVP_PKEY_derive_init(pctx) <= 0) {
            printError("HKDF failed\n");
            ERR_print_errors_fp(stderr);
            exit(EXIT_FAILURE);
        }
        if (EVP_PKEY_CTX_set_hkdf_md(pctx, EVP_sha512()) <= 0) {
            printError("HKDF failed\n");
            ERR_print_errors_fp(stderr);
            exit(EXIT_FAILURE);
        }
        if (EVP_PKEY_CTX_set1_hkdf_key(pctx, st->yaxaKey + ((i * YAXA_KEY_CHUNK_SIZE) - YAXA_KEY_CHUNK_SIZE), sizeof(*st->yaxaKeyChunk) * YAXA_KEY_CHUNK_SIZE) <= 0) {
            printError("HKDF failed\n");
            ERR_print_errors_fp(stderr);
            exit(EXIT_FAILURE);
        }
        if (EVP_PKEY_derive(pctx, st->yaxaKeyChunk, &outlen) <= 0) {
            printError("HKDF failed\n");
            ERR_print_errors_fp(stderr);
            exit(EXIT_FAILURE);
        }
        
        EVP_PKEY_CTX_free(pctx);

        /*Copy the 64-byte chunk into the yaxaKeyarray*/
        memcpy(st->yaxaKey + (i * YAXA_KEY_CHUNK_SIZE), st->yaxaKeyChunk, sizeof(*st->yaxaKeyChunk) * YAXA_KEY_CHUNK_SIZE);
        
        #ifdef gui
        *(st->progressFraction) = ((double)i * keyChunkFloat) / keyBufFloat;
        #endif
    }
    
    OPENSSL_cleanse(st->yaxaKeyChunk, sizeof(*st->yaxaKeyChunk ) * YAXA_KEY_CHUNK_SIZE);
}

void genCtrStart(struct dataStruct *st)
{	
	/*Use HKDF to derive bytes for counterBytes based on yaxaKey*/
	EVP_PKEY_CTX *pctx;
	size_t outlen = sizeof(st->counterInt);
	pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
	
	if (EVP_PKEY_derive_init(pctx) <= 0) {
		printError("HKDF failed\n");
		ERR_print_errors_fp(stderr);
		exit(EXIT_FAILURE);
	}
	if (EVP_PKEY_CTX_set_hkdf_md(pctx, EVP_sha512()) <= 0) {
		printError("HKDF failed\n");
		ERR_print_errors_fp(stderr);
		exit(EXIT_FAILURE);
	}
	if (EVP_PKEY_CTX_set1_hkdf_key(pctx, st->yaxaKey, sizeof(*st->yaxaKey) * st->keyBufSize) <= 0) {
		printError("HKDF failed\n");
		ERR_print_errors_fp(stderr);
		exit(EXIT_FAILURE);
	}
    if (EVP_PKEY_CTX_add1_hkdf_info(pctx, "counter", strlen("counter")) <= 0) {
        printError("HKDF failed\n");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
	if (EVP_PKEY_derive(pctx, st->counterBytes, &outlen) <= 0) {
		printError("HKDF failed\n");
		ERR_print_errors_fp(stderr);
		exit(EXIT_FAILURE);
	}
	
    memcpy(&st->counterInt,st->counterBytes,outlen);
    
	EVP_PKEY_CTX_free(pctx);
}

void genNonce(struct dataStruct *st)
{	
	/*Use HKDF to derive bytes for counterBytes based on yaxaKey*/
	EVP_PKEY_CTX *pctx;
	size_t outlen = sizeof(st->nonceInt);
	pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
	
	if (EVP_PKEY_derive_init(pctx) <= 0) {
		printError("HKDF failed\n");
		ERR_print_errors_fp(stderr);
		exit(EXIT_FAILURE);
	}
	if (EVP_PKEY_CTX_set_hkdf_md(pctx, EVP_sha512()) <= 0) {
		printError("HKDF failed\n");
		ERR_print_errors_fp(stderr);
		exit(EXIT_FAILURE);
	}
	if (EVP_PKEY_CTX_set1_hkdf_key(pctx, st->yaxaKey, sizeof(*st->yaxaKey) * st->keyBufSize) <= 0) {
		printError("HKDF failed\n");
		ERR_print_errors_fp(stderr);
		exit(EXIT_FAILURE);
	}
    if (EVP_PKEY_CTX_add1_hkdf_info(pctx, "nonce", strlen("nonce")) <= 0) {
        printError("HKDF failed\n");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
	if (EVP_PKEY_derive(pctx, st->nonceBytes, &outlen) <= 0) {
		printError("HKDF failed\n");
		ERR_print_errors_fp(stderr);
		exit(EXIT_FAILURE);
	}
	
    memcpy(&st->nonceInt,st->nonceBytes,outlen);
    
	EVP_PKEY_CTX_free(pctx);
}

void genYaxaSalt(struct dataStruct *st)
{

    #ifdef gui 
    double saltSizeFloat = st->yaxaSaltSize;
    *(st->progressFraction) = 0;
    #endif

    unsigned char b; /*Random byte*/

    for (int i = 0; i < st->yaxaSaltSize; i++) {
        if (!RAND_bytes(&b, 1)) {
            printError("Aborting: CSPRNG bytes may not be unpredictable");
            exit(EXIT_FAILURE);
        }
        st->yaxaSalt[i] = b;
        #ifdef gui
        *(st->progressFraction) = (double)i/saltSizeFloat;
        #endif
    }
}

cryptint_t yaxa(cryptint_t messageInt, struct dataStruct *st)
{
    if(st->otpBuffer != NULL) {
        /*Fill up 128-bit key integer with 16 8-bit bytes from yaxaKey*/
        for (uint8_t i = 0; i < sizeof(st->keyInt); i++) {
            /*Reset to the start of the key if reached the end*/
            if (st->k + 1 >= st->msgBufSize)
                st->k = 0;
            else
                st->k++;
            st->keyBytes[i] = st->otpBuffer[st->k];
        }
            
        memcpy(&st->keyInt,st->keyBytes,sizeof(st->keyInt));
    } else {
    /*Fill up 128-bit key integer with 16 8-bit bytes from yaxaKey*/
        for (uint8_t i = 0; i < sizeof(st->keyInt); i++) {
            /*Reset to the start of the key if reached the end*/
            if (st->k + 1 >= st->keyBufSize)
                st->k = 0;
            else
                st->k++;
            st->keyBytes[i] = st->yaxaKey[st->k];
        }
            
        memcpy(&st->keyInt,st->keyBytes,sizeof(st->keyInt));
    }
        
    /*Ctr ^ K ^ N ^ M*/
    /*All values are 128-bit*/

    return st->counterInt++ ^ st->keyInt ^ st->nonceInt ^ messageInt;
}
