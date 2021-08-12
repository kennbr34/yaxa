void doCrypt(FILE *inFile, FILE *outFile, cryptint_t fileSize)
{
    
    #ifdef gui
    *progressFraction = 0.0;
    #endif
    
    uint8_t *inBuffer = calloc(msgBufSize,sizeof(*inBuffer)), *outBuffer = calloc(msgBufSize,sizeof(*outBuffer));
    if (inBuffer == NULL || outBuffer == NULL) {
        printSysError(errno);
        printError("Could not allocate memory for doCrypt buffers");
        exit(EXIT_FAILURE);
    }
    cryptint_t remainingBytes = fileSize;
    cryptint_t outInt, inInt;

    for (cryptint_t i = 0; remainingBytes; i += msgBufSize) {
        
        if(msgBufSize > remainingBytes) {
            msgBufSize = remainingBytes;
        }

        if (freadWErrCheck(inBuffer, sizeof(*inBuffer) * msgBufSize, 1, inFile) != 0) {
            printSysError(returnVal);
            printError("Could not read file for encryption/decryption");
            exit(EXIT_FAILURE);
        }

        for(uint32_t j = 0; j < msgBufSize; j += sizeof(inInt)) {
            memcpy(&inInt,inBuffer + j,sizeof(inInt));
            outInt = yaxa(inInt);
            memcpy(outBuffer + j,&outInt,sizeof(outInt));
        }

        if (fwriteWErrCheck(outBuffer, sizeof(*outBuffer) * msgBufSize, 1, outFile) != 0) {
            printSysError(returnVal);
            printError("Could not write file for encryption/decryption");
            exit(EXIT_FAILURE);
        }
        #ifdef gui
        *progressFraction = (double)i / (double)fileSize;
        #endif
        remainingBytes -= msgBufSize;
    }
    
    free(inBuffer);
    free(outBuffer);
}

void genHMAC(FILE *dataFile, cryptint_t fileSize)
{
    #ifdef gui
    *progressFraction = 0.0;
    #endif
    
    uint8_t *genHmacBuffer = malloc(genHmacBufSize * sizeof(*genHmacBuffer));
    if (genHmacBuffer == NULL) {
        printSysError(errno);
        printError("Could not allocate memory for genHmacBuffer");
        exit(EXIT_FAILURE);
    }
    cryptint_t remainingBytes = fileSize;

    /*Initiate HMAC*/
    HMAC_CTX *ctx = HMAC_CTX_new();
    HMAC_Init_ex(ctx, hmacKey, HMAC_KEY_SIZE, EVP_sha512(), NULL);

    /*HMAC the cipher-text, passtag and salt*/
    cryptint_t i; /*Declare i outside of for loop so it can be used in HMAC_Final as the size*/
    for (i = 0; remainingBytes; i += genHmacBufSize) {
        
        if(genHmacBufSize > remainingBytes) {
            genHmacBufSize = remainingBytes;
        }
        
        if (freadWErrCheck(genHmacBuffer, sizeof(*genHmacBuffer) * genHmacBufSize, 1, dataFile) != 0) {
            printSysError(returnVal);
            printError("Could not generate HMAC");
            exit(EXIT_FAILURE);
        }
        HMAC_Update(ctx, genHmacBuffer, sizeof(*genHmacBuffer) * genHmacBufSize);
        
        remainingBytes -= genHmacBufSize;
        #ifdef gui
        *progressFraction = (double)i/(double)fileSize;
        #endif
    }
    HMAC_Final(ctx, generatedMAC, (unsigned int *)&i);
    HMAC_CTX_free(ctx);
    free(genHmacBuffer);
}

void genHMACKey()
{
    
    #ifdef gui
    strcpy(statusMessage,"Deriving auth key...");
    #endif

    EVP_PKEY_CTX *pctx;
    size_t outlen = sizeof(*hmacKey) * HMAC_KEY_SIZE;
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
    if (EVP_PKEY_CTX_set1_hkdf_key(pctx, yaxaKey, sizeof(*yaxaKey) * keyBufSize) <= 0) {
        printError("HKDF failed\n");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    if (EVP_PKEY_CTX_add1_hkdf_info(pctx, "authkey", strlen("authkey")) <= 0) {
        printError("HKDF failed\n");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    if (EVP_PKEY_derive(pctx, hmacKey, &outlen) <= 0) {
        printError("HKDF failed\n");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    
    EVP_PKEY_CTX_free(pctx);
}

void genPassTag()
{
    
    #ifdef gui
    *progressFraction = 0;
    #endif
    
    if (HMAC(EVP_sha512(), hmacKey, HMAC_KEY_SIZE, (const unsigned char *)userPass, strlen(userPass), passKeyedHash, HMACLengthPtr) == NULL) {
        printError("Password keyed-hash failure");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    
    #ifdef gui
    *progressFraction = 1;
    #endif
}

void genYaxaKey()
{
    
    #ifdef gui
    *progressFraction = 0;
    double keyChunkFloat = YAXA_KEY_CHUNK_SIZE;
    double keyBufFloat = keyBufSize;
    #endif
    
    /*Derive a 64-byte key to expand*/
    EVP_PKEY_CTX *pctx;

    size_t outlen = sizeof(*yaxaKeyChunk) * YAXA_KEY_CHUNK_SIZE;
    pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_SCRYPT, NULL);

    if (EVP_PKEY_derive_init(pctx) <= 0) {
        printError("scrypt failed\n");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    if (EVP_PKEY_CTX_set1_pbe_pass(pctx, userPass, strlen(userPass)) <= 0) {
        printError("scrypt failed\n");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    if (EVP_PKEY_CTX_set1_scrypt_salt(pctx, yaxaSalt, sizeof(*yaxaSalt) * yaxaSaltSize) <= 0) {
        printError("scrypt failed\n");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    if (EVP_PKEY_CTX_set_scrypt_N(pctx, DEFAULT_SCRYPT_N) <= 0) {
        printError("scrypt failed\n");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    if (EVP_PKEY_CTX_set_scrypt_r(pctx, DEFAULT_SCRYPT_R) <= 0) {
        printError("scrypt failed\n");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    if (EVP_PKEY_CTX_set_scrypt_p(pctx, DEFAULT_SCRYPT_P) <= 0) {
        printError("scrypt failed\n");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    if (EVP_PKEY_derive(pctx, yaxaKeyChunk, &outlen) <= 0) {
        printError("scrypt failed\n");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    EVP_PKEY_CTX_free(pctx);
    
    /*Copy that first 64-byte chunk into the yaxaKeyArray*/
    memcpy(yaxaKey, yaxaKeyChunk, sizeof(*yaxaKeyChunk) * YAXA_KEY_CHUNK_SIZE);
    
    #ifdef gui
    *progressFraction = keyChunkFloat / keyBufFloat;
    #endif

    /*Expand that 64-byte key into keyBufSize key*/
    for (int i = 1; i < yaxaSaltSize; i++) {
                
        EVP_PKEY_CTX *pctx;
        size_t outlen = sizeof(*yaxaKeyChunk) * YAXA_KEY_CHUNK_SIZE;
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
        if (EVP_PKEY_CTX_set1_hkdf_key(pctx, yaxaKey + ((i * YAXA_KEY_CHUNK_SIZE) - YAXA_KEY_CHUNK_SIZE), sizeof(*yaxaKeyChunk) * YAXA_KEY_CHUNK_SIZE) <= 0) {
            printError("HKDF failed\n");
            ERR_print_errors_fp(stderr);
            exit(EXIT_FAILURE);
        }
        if (EVP_PKEY_derive(pctx, yaxaKeyChunk, &outlen) <= 0) {
            printError("HKDF failed\n");
            ERR_print_errors_fp(stderr);
            exit(EXIT_FAILURE);
        }
        
        EVP_PKEY_CTX_free(pctx);

        /*Copy the 64-byte chunk into the yaxaKeyarray*/
        memcpy(yaxaKey + (i * YAXA_KEY_CHUNK_SIZE), yaxaKeyChunk, sizeof(*yaxaKeyChunk) * YAXA_KEY_CHUNK_SIZE);
        
        #ifdef gui
        *progressFraction = ((double)i * keyChunkFloat) / keyBufFloat;
        #endif
    }
    
    OPENSSL_cleanse(yaxaKeyChunk, sizeof(*yaxaKeyChunk ) * YAXA_KEY_CHUNK_SIZE);
}

void genCtrStart()
{	
	/*Use HKDF to derive bytes for counterBytes based on yaxaKey*/
	EVP_PKEY_CTX *pctx;
	size_t outlen = sizeof(counterInt);
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
	if (EVP_PKEY_CTX_set1_hkdf_key(pctx, yaxaKey, sizeof(*yaxaKey) * keyBufSize) <= 0) {
		printError("HKDF failed\n");
		ERR_print_errors_fp(stderr);
		exit(EXIT_FAILURE);
	}
    if (EVP_PKEY_CTX_add1_hkdf_info(pctx, "counter", strlen("counter")) <= 0) {
        printError("HKDF failed\n");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
	if (EVP_PKEY_derive(pctx, counterBytes, &outlen) <= 0) {
		printError("HKDF failed\n");
		ERR_print_errors_fp(stderr);
		exit(EXIT_FAILURE);
	}
	
    memcpy(&counterInt,counterBytes,outlen);
    
	EVP_PKEY_CTX_free(pctx);
}

void genNonce()
{	
	/*Use HKDF to derive bytes for counterBytes based on yaxaKey*/
	EVP_PKEY_CTX *pctx;
	size_t outlen = sizeof(counterInt);
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
	if (EVP_PKEY_CTX_set1_hkdf_key(pctx, yaxaKey, sizeof(*yaxaKey) * keyBufSize) <= 0) {
		printError("HKDF failed\n");
		ERR_print_errors_fp(stderr);
		exit(EXIT_FAILURE);
	}
    if (EVP_PKEY_CTX_add1_hkdf_info(pctx, "nonce", strlen("nonce")) <= 0) {
        printError("HKDF failed\n");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
	if (EVP_PKEY_derive(pctx, counterBytes, &outlen) <= 0) {
		printError("HKDF failed\n");
		ERR_print_errors_fp(stderr);
		exit(EXIT_FAILURE);
	}
	
    memcpy(&nonceInt,nonceBytes,outlen);
    
	EVP_PKEY_CTX_free(pctx);
}

void genYaxaSalt()
{

    #ifdef gui 
    double saltSizeFloat = yaxaSaltSize;
    *progressFraction = 0;
    #endif

    unsigned char b; /*Random byte*/

    for (int i = 0; i < yaxaSaltSize; i++) {
        if (!RAND_bytes(&b, 1)) {
            printError("Aborting: CSPRNG bytes may not be unpredictable");
            exit(EXIT_FAILURE);
        }
        yaxaSalt[i] = b;
        #ifdef gui
        *progressFraction = (double)i/saltSizeFloat;
        #endif
    }
}

cryptint_t yaxa(cryptint_t messageInt)
{
    /*Fill up 128-bit key integer with 16 8-bit bytes from yaxaKey*/
    for (uint8_t i = 0; i < sizeof(keyInt); i++)
        keyBytes[i] = yaxaKey[k++];
        
    memcpy(&keyInt,keyBytes,sizeof(keyInt));

    /*Reset to the start of the key if reached the end*/
    if (k + 1 >= keyBufSize)
        k = 0;
        
    /*Ctr ^ K ^ N ^ M*/
    /*All values are 128-bit*/
            
    return counterInt++ ^ keyInt ^ nonceInt ^ messageInt;
}
