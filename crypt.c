void doCrypt(FILE *inFile, FILE *outFile, cryptint_t fileSize, FILE *otpInFile, FILE *otpOutFile)
{
    
    #ifdef gui
    *progressSt.progressFraction = 0.0;
    #endif
    
    uint8_t *inBuffer = calloc(sizesSt.msgBufSize,sizeof(*inBuffer)), *outBuffer = calloc(sizesSt.msgBufSize,sizeof(*outBuffer));
    if (inBuffer == NULL || outBuffer == NULL) {
        printSysError(errno);
        printError("Could not allocate memory for doCrypt buffers");
        exit(EXIT_FAILURE);
    }
    
    
    if(otpInFile != NULL) {
        miscSt.otpBuffer = calloc(sizesSt.msgBufSize,sizeof(*miscSt.otpBuffer));
        if (miscSt.otpBuffer == NULL) {
            printSysError(errno);
            printError("Could not allocate memory for doCrypt buffers");
            exit(EXIT_FAILURE);
        }
    }
    
    /*Initiate HMAC*/
    HMAC_CTX *ctx = HMAC_CTX_new();
    HMAC_Init_ex(ctx, cryptSt.hmacKey, HMAC_KEY_SIZE, EVP_sha512(), NULL);
    
    HMAC_Update(ctx, cryptSt.yaxaSalt, sizeof(*cryptSt.yaxaSalt) * sizesSt.yaxaSaltSize);
    HMAC_Update(ctx, cryptSt.passKeyedHash, sizeof(*cryptSt.passKeyedHash) * PASS_KEYED_HASH_SIZE);
    
    cryptint_t remainingBytes = fileSize;
    cryptint_t outInt, inInt;

    cryptint_t i;
    for (i = 0; remainingBytes; i += sizesSt.msgBufSize) {
        
        if(sizesSt.msgBufSize > remainingBytes) {
            sizesSt.msgBufSize = remainingBytes;
        }

        if (freadWErrCheck(inBuffer, sizeof(*inBuffer) * sizesSt.msgBufSize, 1, inFile) != 0) {
            printSysError(miscSt.returnVal);
            printError("Could not read file for encryption/decryption");
            exit(EXIT_FAILURE);
        }
        
        if(otpInFile != NULL) {
            if (freadWErrCheck(miscSt.otpBuffer, sizeof(*miscSt.otpBuffer) * sizesSt.msgBufSize, 1, otpInFile) != 0) {
                printSysError(miscSt.returnVal);
                printError("Could not read OTP file for encryption/decryption");
                exit(EXIT_FAILURE);
            }
        }

        for(uint32_t j = 0; j < sizesSt.msgBufSize; j += sizeof(inInt)) {
            memcpy(&inInt,inBuffer + j,sizeof(inInt));
            outInt = yaxa(inInt);
            memcpy(outBuffer + j,&outInt,sizeof(outInt));
        }

        if (fwriteWErrCheck(outBuffer, sizeof(*outBuffer) * sizesSt.msgBufSize, 1, outFile) != 0) {
            printSysError(miscSt.returnVal);
            printError("Could not write file for encryption/decryption");
            exit(EXIT_FAILURE);
        }
        
        HMAC_Update(ctx, outBuffer, sizeof(*outBuffer) * sizesSt.msgBufSize);
        
        if(otpInFile != NULL && otpOutFile != NULL) {
            if (fwriteWErrCheck(miscSt.otpBuffer, sizeof(*miscSt.otpBuffer) * sizesSt.msgBufSize, 1, otpOutFile) != 0) {
                printSysError(miscSt.returnVal);
                printError("Could not write file for encryption/decryption");
                exit(EXIT_FAILURE);
            }
        }
        
        #ifdef gui
        *progressSt.progressFraction = (double)i / (double)fileSize;
        #endif
        remainingBytes -= sizesSt.msgBufSize;
    }
    
    i += sizesSt.yaxaSaltSize + PASS_KEYED_HASH_SIZE;
    HMAC_Final(ctx, cryptSt.generatedMAC, (unsigned int *)&i);
    HMAC_CTX_free(ctx);
    
    free(inBuffer);
    free(outBuffer);
}

void genHMAC(FILE *dataFile, cryptint_t fileSize)
{
    #ifdef gui
    *progressSt.progressFraction = 0.0;
    #endif
    
    uint8_t *genHmacBuffer = malloc(sizesSt.genHmacBufSize * sizeof(*genHmacBuffer));
    if (genHmacBuffer == NULL) {
        printSysError(errno);
        printError("Could not allocate memory for genHmacBuffer");
        exit(EXIT_FAILURE);
    }
    cryptint_t remainingBytes = fileSize;

    /*Initiate HMAC*/
    HMAC_CTX *ctx = HMAC_CTX_new();
    HMAC_Init_ex(ctx, cryptSt.hmacKey, HMAC_KEY_SIZE, EVP_sha512(), NULL);

    /*HMAC the cipher-text, passtag and salt*/
    cryptint_t i; /*Declare i outside of for loop so it can be used in HMAC_Final as the size*/
    for (i = 0; remainingBytes; i += sizesSt.genHmacBufSize) {
        
        if(sizesSt.genHmacBufSize > remainingBytes) {
            sizesSt.genHmacBufSize = remainingBytes;
        }
        
        if (freadWErrCheck(genHmacBuffer, sizeof(*genHmacBuffer) * sizesSt.genHmacBufSize, 1, dataFile) != 0) {
            printSysError(miscSt.returnVal);
            printError("Could not generate HMAC");
            exit(EXIT_FAILURE);
        }
        HMAC_Update(ctx, genHmacBuffer, sizeof(*genHmacBuffer) * sizesSt.genHmacBufSize);
        
        remainingBytes -= sizesSt.genHmacBufSize;
        #ifdef gui
        *progressSt.progressFraction = (double)i/(double)fileSize;
        #endif
    }
    HMAC_Final(ctx, cryptSt.generatedMAC, (unsigned int *)&i);
    HMAC_CTX_free(ctx);
    free(genHmacBuffer);
}

void genHMACKey()
{
    
    #ifdef gui
    strcpy(progressSt.statusMessage,"Deriving auth key...");
    #endif

    EVP_PKEY_CTX *pctx;
    size_t outlen = sizeof(*cryptSt.hmacKey) * HMAC_KEY_SIZE;
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
    if (EVP_PKEY_CTX_set1_hkdf_key(pctx, cryptSt.yaxaKey, sizeof(*cryptSt.yaxaKey) * sizesSt.keyBufSize) <= 0) {
        printError("HKDF failed\n");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    if (EVP_PKEY_CTX_add1_hkdf_info(pctx, "authkey", strlen("authkey")) <= 0) {
        printError("HKDF failed\n");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    if (EVP_PKEY_derive(pctx, cryptSt.hmacKey, &outlen) <= 0) {
        printError("HKDF failed\n");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    
    EVP_PKEY_CTX_free(pctx);
}

void genPassTag()
{
    
    #ifdef gui
    *progressSt.progressFraction = 0;
    #endif
    
    if (HMAC(EVP_sha512(), cryptSt.hmacKey, HMAC_KEY_SIZE, (const unsigned char *)cryptSt.userPass, strlen(cryptSt.userPass), cryptSt.passKeyedHash, cryptSt.HMACLengthPtr) == NULL) {
        printError("Password keyed-hash failure");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    
    #ifdef gui
    *progressSt.progressFraction = 1;
    #endif
}

void genYaxaKey()
{
    #ifdef gui
    *progressSt.progressFraction = 0;
    double keyChunkFloat = YAXA_KEY_CHUNK_SIZE;
    double keyBufFloat = sizesSt.keyBufSize;
    #endif
    
    /*Derive a 64-byte key to expand*/
    EVP_PKEY_CTX *pctx;

    size_t outlen = sizeof(*cryptSt.yaxaKeyChunk) * YAXA_KEY_CHUNK_SIZE;
    pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_SCRYPT, NULL);

    if (EVP_PKEY_derive_init(pctx) <= 0) {
        printError("scrypt failed\n");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    if (EVP_PKEY_CTX_set1_pbe_pass(pctx, cryptSt.userPass, strlen(cryptSt.userPass)) <= 0) {
        printError("scrypt failed\n");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    if (EVP_PKEY_CTX_set1_scrypt_salt(pctx, cryptSt.yaxaSalt, sizeof(*cryptSt.yaxaSalt) * sizesSt.yaxaSaltSize) <= 0) {
        printError("scrypt failed\n");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    if (EVP_PKEY_CTX_set_scrypt_N(pctx, cryptSt.nFactor) <= 0) {
        printError("scrypt failed\n");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    if (EVP_PKEY_CTX_set_scrypt_r(pctx, cryptSt.rFactor) <= 0) {
        printError("scrypt failed\n");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    if (EVP_PKEY_CTX_set_scrypt_p(pctx, cryptSt.pFactor) <= 0) {
        printError("scrypt failed\n");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    if (EVP_PKEY_derive(pctx, cryptSt.yaxaKeyChunk, &outlen) <= 0) {
        printError("scrypt failed\n");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    EVP_PKEY_CTX_free(pctx);
    
    /*Copy that first 64-byte chunk into the yaxaKeyArray*/
    memcpy(cryptSt.yaxaKey, cryptSt.yaxaKeyChunk, sizeof(*cryptSt.yaxaKeyChunk) * YAXA_KEY_CHUNK_SIZE);
    
    #ifdef gui
    *progressSt.progressFraction = keyChunkFloat / keyBufFloat;
    #endif

    /*Expand that 64-byte key into keyBufSize key*/
    for (int i = 1; i < sizesSt.yaxaSaltSize; i++) {
                
        EVP_PKEY_CTX *pctx;
        size_t outlen = sizeof(*cryptSt.yaxaKeyChunk) * YAXA_KEY_CHUNK_SIZE;
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
        if (EVP_PKEY_CTX_set1_hkdf_key(pctx, cryptSt.yaxaKey + ((i * YAXA_KEY_CHUNK_SIZE) - YAXA_KEY_CHUNK_SIZE), sizeof(*cryptSt.yaxaKeyChunk) * YAXA_KEY_CHUNK_SIZE) <= 0) {
            printError("HKDF failed\n");
            ERR_print_errors_fp(stderr);
            exit(EXIT_FAILURE);
        }
        if (EVP_PKEY_derive(pctx, cryptSt.yaxaKeyChunk, &outlen) <= 0) {
            printError("HKDF failed\n");
            ERR_print_errors_fp(stderr);
            exit(EXIT_FAILURE);
        }
        
        EVP_PKEY_CTX_free(pctx);

        /*Copy the 64-byte chunk into the yaxaKeyarray*/
        memcpy(cryptSt.yaxaKey + (i * YAXA_KEY_CHUNK_SIZE), cryptSt.yaxaKeyChunk, sizeof(*cryptSt.yaxaKeyChunk) * YAXA_KEY_CHUNK_SIZE);
        
        #ifdef gui
        *progressSt.progressFraction = ((double)i * keyChunkFloat) / keyBufFloat;
        #endif
    }
    
    OPENSSL_cleanse(cryptSt.yaxaKeyChunk, sizeof(*cryptSt.yaxaKeyChunk ) * YAXA_KEY_CHUNK_SIZE);
}

void genCtrStart()
{	
	/*Use HKDF to derive bytes for counterBytes based on yaxaKey*/
	EVP_PKEY_CTX *pctx;
	size_t outlen = sizeof(cryptSt.counterInt);
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
	if (EVP_PKEY_CTX_set1_hkdf_key(pctx, cryptSt.yaxaKey, sizeof(*cryptSt.yaxaKey) * sizesSt.keyBufSize) <= 0) {
		printError("HKDF failed\n");
		ERR_print_errors_fp(stderr);
		exit(EXIT_FAILURE);
	}
    if (EVP_PKEY_CTX_add1_hkdf_info(pctx, "counter", strlen("counter")) <= 0) {
        printError("HKDF failed\n");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
	if (EVP_PKEY_derive(pctx, cryptSt.counterBytes, &outlen) <= 0) {
		printError("HKDF failed\n");
		ERR_print_errors_fp(stderr);
		exit(EXIT_FAILURE);
	}
	
    memcpy(&cryptSt.counterInt,cryptSt.counterBytes,outlen);
    
	EVP_PKEY_CTX_free(pctx);
}

void genNonce()
{	
	/*Use HKDF to derive bytes for counterBytes based on yaxaKey*/
	EVP_PKEY_CTX *pctx;
	size_t outlen = sizeof(cryptSt.nonceInt);
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
	if (EVP_PKEY_CTX_set1_hkdf_key(pctx, cryptSt.yaxaKey, sizeof(*cryptSt.yaxaKey) * sizesSt.keyBufSize) <= 0) {
		printError("HKDF failed\n");
		ERR_print_errors_fp(stderr);
		exit(EXIT_FAILURE);
	}
    if (EVP_PKEY_CTX_add1_hkdf_info(pctx, "nonce", strlen("nonce")) <= 0) {
        printError("HKDF failed\n");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
	if (EVP_PKEY_derive(pctx, cryptSt.nonceBytes, &outlen) <= 0) {
		printError("HKDF failed\n");
		ERR_print_errors_fp(stderr);
		exit(EXIT_FAILURE);
	}
	
    memcpy(&cryptSt.nonceInt,cryptSt.nonceBytes,outlen);
    
	EVP_PKEY_CTX_free(pctx);
}

void genYaxaSalt()
{

    #ifdef gui 
    double saltSizeFloat = sizesSt.yaxaSaltSize;
    *progressSt.progressFraction = 0;
    #endif

    unsigned char b; /*Random byte*/

    for (int i = 0; i < sizesSt.yaxaSaltSize; i++) {
        if (!RAND_bytes(&b, 1)) {
            printError("Aborting: CSPRNG bytes may not be unpredictable");
            exit(EXIT_FAILURE);
        }
        cryptSt.yaxaSalt[i] = b;
        #ifdef gui
        *progressSt.progressFraction = (double)i/saltSizeFloat;
        #endif
    }
}

cryptint_t yaxa(cryptint_t messageInt)
{
    if(miscSt.otpBuffer != NULL) {
        /*Fill up 128-bit key integer with 16 8-bit bytes from yaxaKey*/
        for (uint8_t i = 0; i < sizeof(cryptSt.keyInt); i++) {
            /*Reset to the start of the key if reached the end*/
            if (cryptSt.k + 1 >= sizesSt.msgBufSize)
                cryptSt.k = 0;
            else
                cryptSt.k++;
            cryptSt.keyBytes[i] = miscSt.otpBuffer[cryptSt.k];
        }
            
        memcpy(&cryptSt.keyInt,cryptSt.keyBytes,sizeof(cryptSt.keyInt));
    } else {
    /*Fill up 128-bit key integer with 16 8-bit bytes from yaxaKey*/
        for (uint8_t i = 0; i < sizeof(cryptSt.keyInt); i++) {
            /*Reset to the start of the key if reached the end*/
            if (cryptSt.k + 1 >= sizesSt.keyBufSize)
                cryptSt.k = 0;
            else
                cryptSt.k++;
            cryptSt.keyBytes[i] = cryptSt.yaxaKey[cryptSt.k];
        }
            
        memcpy(&cryptSt.keyInt,cryptSt.keyBytes,sizeof(cryptSt.keyInt));
    }
        
    /*Ctr ^ K ^ N ^ M*/
    /*All values are 128-bit*/

    return cryptSt.counterInt++ ^ cryptSt.keyInt ^ cryptSt.nonceInt ^ messageInt;
}
