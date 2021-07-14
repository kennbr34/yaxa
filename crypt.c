void doCrypt(FILE *inFile, FILE *outFile, unsigned __int128 fileSize)
{
    
    #ifdef gui
    *progressFraction = 0.0;
    #endif
    
    unsigned int bufferSize = 1024*1024;
    unsigned char *inBuffer = malloc(bufferSize * sizeof(uint8_t)), *outBuffer = malloc(bufferSize * sizeof(uint8_t));
    unsigned __int128 remainingBytes = fileSize;
    unsigned __int128 outInt, inInt;

    for (unsigned __int128 i = 0; remainingBytes; i += bufferSize) {
        
        if(bufferSize > remainingBytes) {
            bufferSize = remainingBytes;
        }

        if (freadWErrCheck(inBuffer, sizeof(uint8_t) * bufferSize, 1, inFile) != 0) {
            printSysError(returnVal);
            printError("Could not read file for encryption/decryption");
            exit(EXIT_FAILURE);
        }

        for(unsigned int j = 0; j < bufferSize; j += sizeof(unsigned __int128)) {
            memcpy(&inInt,inBuffer + j,sizeof(inInt));
            outInt = yaxa(inInt);
            memcpy(outBuffer + j,&outInt,sizeof(outInt));
        }

        if (fwriteWErrCheck(outBuffer, sizeof(uint8_t) * bufferSize, 1, outFile) != 0) {
            printSysError(returnVal);
            printError("Could not write file for encryption/decryption");
            exit(EXIT_FAILURE);
        }
        #ifdef gui
        *progressFraction = (double)i / (double)fileSize;
        #endif
        remainingBytes -= bufferSize;
    }
    
    free(inBuffer);
    free(outBuffer);
}

void genHMAC(FILE *dataFile, unsigned __int128 fileSize)
{
    #ifdef gui
    *progressFraction = 0.0;
    #endif
    
    unsigned int bufferSize = 1024*1024;
    unsigned char *buffer = malloc(bufferSize * sizeof(uint8_t));
    unsigned __int128 remainingBytes = fileSize;
    unsigned char inByte;

    /*Initiate HMAC*/
    HMAC_CTX *ctx = HMAC_CTX_new();
    HMAC_Init_ex(ctx, hmacKey, HMAC_KEY_SIZE, EVP_sha512(), NULL);

    /*HMAC the cipher-text, passtag and salt*/
    unsigned __int128 i; /*Declare i outside of for loop so it can be used in HMAC_Final as the size*/
    for (i = 0; remainingBytes; i += bufferSize) {
        
        if(bufferSize > remainingBytes) {
            bufferSize = remainingBytes;
        }
        
        if (freadWErrCheck(buffer, sizeof(uint8_t) * bufferSize, 1, dataFile) != 0) {
            printSysError(returnVal);
            printError("Could not generate HMAC");
            exit(EXIT_FAILURE);
        }
        HMAC_Update(ctx, buffer, sizeof(uint8_t) * bufferSize);
        
        remainingBytes -= bufferSize;
        #ifdef gui
        *progressFraction = (double)i/(double)fileSize;
        #endif
    }
    HMAC_Final(ctx, generatedMAC, (unsigned int *)&i);
    HMAC_CTX_free(ctx);
    free(buffer);
}

void genHMACKey()
{
    
    #ifdef gui
    strcpy(statusMessage,"Deriving auth key...");
    #endif

    EVP_PKEY_CTX *pctx;
    size_t outlen = sizeof(unsigned char) * HMAC_KEY_SIZE;
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
    if (EVP_PKEY_CTX_set1_hkdf_key(pctx, yaxaKey, YAXA_KEYBUF_SIZE) <= 0) {
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
    
    if (HMAC(EVP_sha512(), hmacKey, HMAC_KEY_SIZE, userPass, strlen(userPass), passKeyedHash, HMACLengthPtr) == NULL) {
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
    double keyBufFloat = YAXA_KEYBUF_SIZE;
    #endif
    
    /*Derive a 64-byte key to expand*/
    EVP_PKEY_CTX *pctx;

    size_t outlen = YAXA_KEY_CHUNK_SIZE;
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
    if (EVP_PKEY_CTX_set1_scrypt_salt(pctx, yaxaSalt, YAXA_SALT_SIZE) <= 0) {
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
    memcpy(yaxaKeyArray[0], yaxaKeyChunk, YAXA_KEY_CHUNK_SIZE);
    
    #ifdef gui
    *progressFraction = keyChunkFloat / keyBufFloat;
    #endif

    /*Expand that 64-byte key into YAXA_KEYBUF_SIZE key*/
    for (int i = 1; i < YAXA_SALT_SIZE; i++) {
                
        EVP_PKEY_CTX *pctx;
        size_t outlen = sizeof(unsigned char) * YAXA_KEY_CHUNK_SIZE;
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
        if (EVP_PKEY_CTX_set1_hkdf_key(pctx, yaxaKeyArray[i - 1], YAXA_KEY_CHUNK_SIZE) <= 0) {
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
        memcpy(yaxaKeyArray[i], yaxaKeyChunk, YAXA_KEY_CHUNK_SIZE);
        
        #ifdef gui
        *progressFraction = ((double)i * keyChunkFloat) / keyBufFloat;
        #endif
    }

    memcpy(yaxaKey, yaxaKeyArray, YAXA_KEYBUF_SIZE);

    OPENSSL_cleanse(yaxaKeyArray, YAXA_KEYBUF_SIZE);
    OPENSSL_cleanse(yaxaKeyChunk, YAXA_KEY_CHUNK_SIZE);
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
	if (EVP_PKEY_CTX_set1_hkdf_key(pctx, yaxaKey, YAXA_KEY_LENGTH) <= 0) {
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

void genYaxaSalt()
{

    #ifdef gui 
    double saltSizeFloat = YAXA_SALT_SIZE;
    *progressFraction = 0;
    #endif

    unsigned char b; /*Random byte*/

    for (int i = 0; i < YAXA_SALT_SIZE; i++) {
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

unsigned __int128 yaxa(unsigned __int128 messageInt)
{
    /*Fill up 128-bit key integer with 16 8-bit bytes from yaxaKey*/
    for (uint8_t i = 0; i < sizeof(unsigned __int128); i++)
        keyBytes[i] = yaxaKey[k++];
        
    memcpy(&keyInt,keyBytes,sizeof(unsigned __int128));

    /*Reset to the start of the key if reached the end*/
    if (k + 1 >= YAXA_KEY_LENGTH)
        k = 0;
        
    /*Ctr ^ K ^ M*/
    /*All values are 128-bit*/
    
    return (counterInt *= keyInt) ^ keyInt ^ messageInt;
}
