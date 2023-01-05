void doCrypt(FILE *inFile, FILE *outFile, cryptint_t fileSize, FILE *otpInFile, FILE *otpOutFile, struct dataStruct *st)
{
    
    if(fileSize < sizeof(cryptint_t)) {
        printError("File size less than cryptint_t");
        exit(EXIT_FAILURE);
    }
    #ifdef gui
    *(st->guiSt.progressFraction) = 0.0;
    #endif
    
    uint8_t *inBuffer = calloc(st->cryptSt.msgBufSize,sizeof(*inBuffer)), *outBuffer = calloc(st->cryptSt.msgBufSize,sizeof(*outBuffer));
    if (inBuffer == NULL || outBuffer == NULL) {
        printSysError(errno);
        printError("Could not allocate memory for doCrypt buffers");
        exit(EXIT_FAILURE);
    }
    
    uint8_t *otpBuffer = NULL;
    if(otpInFile != NULL) {
        otpBuffer = calloc(st->cryptSt.msgBufSize,sizeof(*otpBuffer));
        if (otpBuffer == NULL) {
            printSysError(errno);
            printError("Could not allocate memory for doCrypt buffers");
            exit(EXIT_FAILURE);
        }
    }
    
    /*Initiate HMAC*/
    HMAC_CTX *ctx = HMAC_CTX_new();
    HMAC_Init_ex(ctx, st->cryptSt.hmacKey, HMAC_KEY_SIZE, EVP_sha512(), NULL);
    
    HMAC_Update(ctx, st->cryptSt.yaxaSalt, sizeof(*st->cryptSt.yaxaSalt) * st->cryptSt.yaxaSaltSize);
    HMAC_Update(ctx, st->cryptSt.passKeyedHash, sizeof(*st->cryptSt.passKeyedHash) * PASS_KEYED_HASH_SIZE);
    
    cryptint_t remainingBytes = fileSize;
    cryptint_t outInt, inInt;

    cryptint_t i;
    uint64_t loopIterations = 0;
    for (i = 0; remainingBytes; i += st->cryptSt.msgBufSize) {
        
        #ifdef gui
        st->guiSt.startLoop = clock();
        st->guiSt.startBytes = (fileSize - remainingBytes);
        #endif
        
        if(st->cryptSt.msgBufSize > remainingBytes) {
            st->cryptSt.msgBufSize = remainingBytes;
        }

        if (freadWErrCheck(inBuffer, sizeof(*inBuffer) * st->cryptSt.msgBufSize, 1, inFile, st) != 0) {
            printSysError(st->miscSt.returnVal);
            printError("Could not read file for encryption/decryption");
            exit(EXIT_FAILURE);
        }
        
        if(otpInFile != NULL) {
            if (freadWErrCheck(otpBuffer, sizeof(*otpBuffer) * st->cryptSt.msgBufSize, 1, otpInFile, st) != 0) {
                printSysError(st->miscSt.returnVal);
                printError("Could not read OTP file for encryption/decryption");
                exit(EXIT_FAILURE);
            }
        }

        for(uint32_t j = 0; j < st->cryptSt.msgBufSize; j += sizeof(inInt)) {
            memcpy(&inInt,inBuffer + j,sizeof(inInt));
            outInt = yaxa(inInt,otpBuffer,st);
            memcpy(outBuffer + j,&outInt,sizeof(outInt));
        }

        if (fwriteWErrCheck(outBuffer, sizeof(*outBuffer) * st->cryptSt.msgBufSize, 1, outFile, st) != 0) {
            printSysError(st->miscSt.returnVal);
            printError("Could not write file for encryption/decryption");
            exit(EXIT_FAILURE);
        }
        
        HMAC_Update(ctx, outBuffer, sizeof(*outBuffer) * st->cryptSt.msgBufSize);
        
        if(otpInFile != NULL && otpOutFile != NULL) {
            if (fwriteWErrCheck(otpBuffer, sizeof(*otpBuffer) * st->cryptSt.msgBufSize, 1, otpOutFile, st) != 0) {
                printSysError(st->miscSt.returnVal);
                printError("Could not write file for encryption/decryption");
                exit(EXIT_FAILURE);
            }
        }
        
        remainingBytes -= st->cryptSt.msgBufSize;
        
        #ifdef gui
        *(st->guiSt.progressFraction) = (double)i / (double)fileSize;
        
        st->guiSt.endLoop = clock();
        st->guiSt.endBytes = (fileSize - remainingBytes);
        
        st->guiSt.loopTime = (double)(st->guiSt.endLoop - st->guiSt.startLoop) / CLOCKS_PER_SEC;
        st->guiSt.totalTime = (double)(st->guiSt.endLoop - st->guiSt.startTime) / CLOCKS_PER_SEC;
        st->guiSt.totalBytes = st->guiSt.endBytes - st->guiSt.startBytes;
        
        double dataRate = (double)((double)st->guiSt.totalBytes/(double)st->guiSt.loopTime) / (1024*1024);
        sprintf(st->guiSt.statusMessage,"%s %0.0f Mb/s, %0.0fs elapsed", strcmp(st->guiSt.encryptOrDecrypt,"encrypt") ? "Decrypting..." : "Encrypting...", dataRate, st->guiSt.totalTime);
        st->guiSt.averageRate += dataRate;
        #endif
        loopIterations++;
    }
    #ifdef gui
    st->guiSt.averageRate /= loopIterations;
    #endif 
    
    i += st->cryptSt.yaxaSaltSize + PASS_KEYED_HASH_SIZE;
    HMAC_Final(ctx, st->cryptSt.generatedMAC, (unsigned int *)&i);
    HMAC_CTX_free(ctx);
    
    free(inBuffer);
    free(outBuffer);
}

void genHMAC(FILE *dataFile, cryptint_t fileSize, struct dataStruct *st)
{
    #ifdef gui
    *(st->guiSt.progressFraction) = 0.0;
    #endif
    
    uint8_t *genHmacBuffer = malloc(st->cryptSt.genHmacBufSize * sizeof(*genHmacBuffer));
    if (genHmacBuffer == NULL) {
        printSysError(errno);
        printError("Could not allocate memory for genHmacBuffer");
        exit(EXIT_FAILURE);
    }
    cryptint_t remainingBytes = fileSize;

    /*Initiate HMAC*/
    HMAC_CTX *ctx = HMAC_CTX_new();
    HMAC_Init_ex(ctx, st->cryptSt.hmacKey, HMAC_KEY_SIZE, EVP_sha512(), NULL);

    /*HMAC the cipher-text, passtag and salt*/
    cryptint_t i; /*Declare i outside of for loop so it can be used in HMAC_Final as the size*/
    for (i = 0; remainingBytes; i += st->cryptSt.genHmacBufSize) {
        
        #ifdef gui
        st->guiSt.startLoop = clock();
        st->guiSt.startBytes = (fileSize - remainingBytes);
        #endif
        
        if(st->cryptSt.genHmacBufSize > remainingBytes) {
            st->cryptSt.genHmacBufSize = remainingBytes;
        }
        
        if (freadWErrCheck(genHmacBuffer, sizeof(*genHmacBuffer) * st->cryptSt.genHmacBufSize, 1, dataFile, st) != 0) {
            printSysError(st->miscSt.returnVal);
            printError("Could not generate HMAC");
            exit(EXIT_FAILURE);
        }
        HMAC_Update(ctx, genHmacBuffer, sizeof(*genHmacBuffer) * st->cryptSt.genHmacBufSize);
        
        remainingBytes -= st->cryptSt.genHmacBufSize;
        #ifdef gui
        *(st->guiSt.progressFraction) = (double)i/(double)fileSize;
        
        st->guiSt.endLoop = clock();
        st->guiSt.endBytes = (fileSize - remainingBytes);
        
        st->guiSt.loopTime = (double)(st->guiSt.endLoop - st->guiSt.startLoop) / CLOCKS_PER_SEC;
        st->guiSt.totalTime = (double)(st->guiSt.endLoop - st->guiSt.startTime) / CLOCKS_PER_SEC;
        st->guiSt.totalBytes = st->guiSt.endBytes - st->guiSt.startBytes;
        
        double dataRate = (double)((double)st->guiSt.totalBytes/(double)st->guiSt.loopTime) / (1024*1024);
        sprintf(st->guiSt.statusMessage,"%s %0.0f Mb/s, %0.0fs elapsed", "Authenticating data...", dataRate, st->guiSt.totalTime);
        #endif
    }
    HMAC_Final(ctx, st->cryptSt.generatedMAC, (unsigned int *)&i);
    HMAC_CTX_free(ctx);
    free(genHmacBuffer);
}

void genHMACKey(struct dataStruct *st)
{
    
    #ifdef gui
    strcpy(st->guiSt.statusMessage,"Deriving auth key...");
    #endif

    EVP_PKEY_CTX *pctx;
    size_t outlen = sizeof(*st->cryptSt.hmacKey) * HMAC_KEY_SIZE;
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
    if (EVP_PKEY_CTX_set1_hkdf_key(pctx, st->cryptSt.yaxaKey, sizeof(*st->cryptSt.yaxaKey) * st->cryptSt.keyBufSize) <= 0) {
        printError("HKDF failed\n");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    if (EVP_PKEY_CTX_add1_hkdf_info(pctx, "authkey", strlen("authkey")) <= 0) {
        printError("HKDF failed\n");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    if (EVP_PKEY_derive(pctx, st->cryptSt.hmacKey, &outlen) <= 0) {
        printError("HKDF failed\n");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    
    EVP_PKEY_CTX_free(pctx);
}

void genPassTag(struct dataStruct *st)
{
    
    #ifdef gui
    *(st->guiSt.progressFraction) = 0;
    #endif
    
    if (HMAC(EVP_sha512(), st->cryptSt.hmacKey, HMAC_KEY_SIZE, (const unsigned char *)st->cryptSt.userPass, strlen(st->cryptSt.userPass), st->cryptSt.passKeyedHash, st->cryptSt.HMACLengthPtr) == NULL) {
        printError("Password keyed-hash failure");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    
    #ifdef gui
    *(st->guiSt.progressFraction) = 1;
    #endif
}

void genYaxaKey(struct dataStruct *st)
{
    #ifdef gui
    *(st->guiSt.progressFraction) = 0;
    double keyChunkFloat = YAXA_KEY_CHUNK_SIZE;
    double keyBufFloat = st->cryptSt.keyBufSize;
    #endif
    
    /*Derive a 64-byte key to expand*/
    EVP_PKEY_CTX *pctx;

    size_t outlen = sizeof(*st->cryptSt.yaxaKeyChunk) * YAXA_KEY_CHUNK_SIZE;
    pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_SCRYPT, NULL);

    if (EVP_PKEY_derive_init(pctx) <= 0) {
        printError("scrypt failed\n");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    if (EVP_PKEY_CTX_set1_pbe_pass(pctx, st->cryptSt.userPass, strlen(st->cryptSt.userPass)) <= 0) {
        printError("scrypt failed\n");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    if (EVP_PKEY_CTX_set1_scrypt_salt(pctx, st->cryptSt.yaxaSalt, sizeof(*st->cryptSt.yaxaSalt) * st->cryptSt.yaxaSaltSize) <= 0) {
        printError("scrypt failed\n");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    if (EVP_PKEY_CTX_set_scrypt_N(pctx, st->cryptSt.nFactor) <= 0) {
        printError("scrypt failed\n");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    if (EVP_PKEY_CTX_set_scrypt_r(pctx, st->cryptSt.rFactor) <= 0) {
        printError("scrypt failed\n");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    if (EVP_PKEY_CTX_set_scrypt_p(pctx, st->cryptSt.pFactor) <= 0) {
        printError("scrypt failed\n");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    if (EVP_PKEY_derive(pctx, st->cryptSt.yaxaKeyChunk, &outlen) <= 0) {
        printError("scrypt failed\n");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    EVP_PKEY_CTX_free(pctx);
    
    /*Copy that first 64-byte chunk into the yaxaKeyArray*/
    memcpy(st->cryptSt.yaxaKey, st->cryptSt.yaxaKeyChunk, sizeof(*st->cryptSt.yaxaKeyChunk) * YAXA_KEY_CHUNK_SIZE);
    
    #ifdef gui
    *(st->guiSt.progressFraction) = keyChunkFloat / keyBufFloat;
    #endif

    /*Expand that 64-byte key into keyBufSize key*/
    for (int i = 1; i < st->cryptSt.yaxaSaltSize; i++) {
                
        EVP_PKEY_CTX *pctx;
        size_t outlen = sizeof(*st->cryptSt.yaxaKeyChunk) * YAXA_KEY_CHUNK_SIZE;
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
        if (EVP_PKEY_CTX_set1_hkdf_key(pctx, st->cryptSt.yaxaKey + ((i * YAXA_KEY_CHUNK_SIZE) - YAXA_KEY_CHUNK_SIZE), sizeof(*st->cryptSt.yaxaKeyChunk) * YAXA_KEY_CHUNK_SIZE) <= 0) {
            printError("HKDF failed\n");
            ERR_print_errors_fp(stderr);
            exit(EXIT_FAILURE);
        }
        if (EVP_PKEY_derive(pctx, st->cryptSt.yaxaKeyChunk, &outlen) <= 0) {
            printError("HKDF failed\n");
            ERR_print_errors_fp(stderr);
            exit(EXIT_FAILURE);
        }
        
        EVP_PKEY_CTX_free(pctx);

        /*Copy the 64-byte chunk into the yaxaKeyarray*/
        memcpy(st->cryptSt.yaxaKey + (i * YAXA_KEY_CHUNK_SIZE), st->cryptSt.yaxaKeyChunk, sizeof(*st->cryptSt.yaxaKeyChunk) * YAXA_KEY_CHUNK_SIZE);
        
        #ifdef gui
        *(st->guiSt.progressFraction) = ((double)i * keyChunkFloat) / keyBufFloat;
        #endif
    }
    
    OPENSSL_cleanse(st->cryptSt.yaxaKeyChunk, sizeof(*st->cryptSt.yaxaKeyChunk ) * YAXA_KEY_CHUNK_SIZE);
}

void genCtrStart(struct dataStruct *st)
{	
	/*Use HKDF to derive bytes for counterBytes based on yaxaKey*/
	EVP_PKEY_CTX *pctx;
	size_t outlen = sizeof(st->cryptSt.counterInt);
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
	if (EVP_PKEY_CTX_set1_hkdf_key(pctx, st->cryptSt.yaxaKey, sizeof(*st->cryptSt.yaxaKey) * st->cryptSt.keyBufSize) <= 0) {
		printError("HKDF failed\n");
		ERR_print_errors_fp(stderr);
		exit(EXIT_FAILURE);
	}
    if (EVP_PKEY_CTX_add1_hkdf_info(pctx, "counter", strlen("counter")) <= 0) {
        printError("HKDF failed\n");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
	if (EVP_PKEY_derive(pctx, st->cryptSt.counterBytes, &outlen) <= 0) {
		printError("HKDF failed\n");
		ERR_print_errors_fp(stderr);
		exit(EXIT_FAILURE);
	}
	
    memcpy(&st->cryptSt.counterInt,st->cryptSt.counterBytes,outlen);
    
	EVP_PKEY_CTX_free(pctx);
}

void genNonce(struct dataStruct *st)
{	
	/*Use HKDF to derive bytes for counterBytes based on yaxaKey*/
	EVP_PKEY_CTX *pctx;
	size_t outlen = sizeof(st->cryptSt.nonceInt);
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
	if (EVP_PKEY_CTX_set1_hkdf_key(pctx, st->cryptSt.yaxaKey, sizeof(*st->cryptSt.yaxaKey) * st->cryptSt.keyBufSize) <= 0) {
		printError("HKDF failed\n");
		ERR_print_errors_fp(stderr);
		exit(EXIT_FAILURE);
	}
    if (EVP_PKEY_CTX_add1_hkdf_info(pctx, "nonce", strlen("nonce")) <= 0) {
        printError("HKDF failed\n");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
	if (EVP_PKEY_derive(pctx, st->cryptSt.nonceBytes, &outlen) <= 0) {
		printError("HKDF failed\n");
		ERR_print_errors_fp(stderr);
		exit(EXIT_FAILURE);
	}
	
    memcpy(&st->cryptSt.nonceInt,st->cryptSt.nonceBytes,outlen);
    
	EVP_PKEY_CTX_free(pctx);
}

void genYaxaSalt(struct dataStruct *st)
{

    #ifdef gui 
    double saltSizeFloat = st->cryptSt.yaxaSaltSize;
    *(st->guiSt.progressFraction) = 0;
    #endif

    unsigned char b; /*Random byte*/

    for (int i = 0; i < st->cryptSt.yaxaSaltSize; i++) {
        if (!RAND_bytes(&b, 1)) {
            printError("Aborting: CSPRNG bytes may not be unpredictable");
            exit(EXIT_FAILURE);
        }
        st->cryptSt.yaxaSalt[i] = b;
        #ifdef gui
        *(st->guiSt.progressFraction) = (double)i/saltSizeFloat;
        #endif
    }
}

cryptint_t yaxa(cryptint_t messageInt, uint8_t *otpBuffer, struct dataStruct *st)
{
    if(otpBuffer != NULL) {
        /*Fill up 128-bit key integer with 16 8-bit bytes from yaxaKey*/
        for (uint8_t i = 0; i < sizeof(st->cryptSt.keyInt); i++) {
            /*Reset to the start of the key if reached the end*/
            if (st->cryptSt.k + 1 >= st->cryptSt.msgBufSize)
                st->cryptSt.k = 0;
            else
                st->cryptSt.k++;
            st->cryptSt.keyBytes[i] = otpBuffer[st->cryptSt.k];
        }
            
        memcpy(&st->cryptSt.keyInt,st->cryptSt.keyBytes,sizeof(st->cryptSt.keyInt));
    } else {
    /*Fill up 128-bit key integer with 16 8-bit bytes from yaxaKey*/
        for (uint8_t i = 0; i < sizeof(st->cryptSt.keyInt); i++) {
            /*Reset to the start of the key if reached the end*/
            if (st->cryptSt.k + 1 >= st->cryptSt.keyBufSize)
                st->cryptSt.k = 0;
            else
                st->cryptSt.k++;
            st->cryptSt.keyBytes[i] = st->cryptSt.yaxaKey[st->cryptSt.k];
        }
            
        memcpy(&st->cryptSt.keyInt,st->cryptSt.keyBytes,sizeof(st->cryptSt.keyInt));
    }
        
    /*Ctr ^ K ^ N ^ M*/
    /*All values are 128-bit*/

    return st->cryptSt.counterInt++ ^ st->cryptSt.keyInt ^ st->cryptSt.nonceInt ^ messageInt;
}
