int workThread(char action, struct dataStruct *st)
{
    pid_t p = fork();
    if(p) return 0;
            
    FILE *inFile = fopen(st->inputFileName, "rb");
    if (inFile == NULL) {
        printFileError(st->inputFileName, errno);
        exit(EXIT_FAILURE);
    }
    FILE *outFile = fopen(st->outputFileName, "wb+");
    if (outFile == NULL) {
        printFileError(st->outputFileName, errno);
        exit(EXIT_FAILURE);
    }
    
    FILE *otpInFile = NULL;
    FILE *otpOutFile = NULL;
    
    cryptint_t fileSize;
    
    st->counterInt = 0;
    st->keyInt = 0;
    st->k = 0;

    if(action == 'e') {
        #ifdef gui
        strcpy(st->statusMessage,"Generating salt...");
        *(st->overallProgressFraction) = .1;
        #endif
        genYaxaSalt(st);
    } else if(action == 'd') {
        #ifdef gui
        strcpy(st->statusMessage,"Reading salt...");
        *(st->overallProgressFraction) = .1;
        #endif
        /*Read yaxaSalt from head of cipher-text*/
        if (freadWErrCheck(st->yaxaSalt, sizeof(*st->yaxaSalt), st->yaxaSaltSize, inFile, st) != 0) {
            printSysError(st->returnVal);
            printError("Could not read salt");
            exit(EXIT_FAILURE);
        }
    }
        
    if(action == 'd') {
        #ifdef gui
        strcpy(st->statusMessage,"Reading pass keyed-hash...");
        *(st->overallProgressFraction) = .2;
        #endif
        /*Get passKeyedHashFromFile*/
        if (freadWErrCheck(st->passKeyedHashFromFile, sizeof(*st->passKeyedHashFromFile), PASS_KEYED_HASH_SIZE, inFile, st) != 0) {
            printSysError(st->returnVal);
            printError("Could not read password hash");
            exit(EXIT_FAILURE);
        }
    }
        
    if(st->keyFileGiven) {
        
        FILE *keyFile = fopen(st->keyFileName,"rb");
        if (keyFile == NULL) {
            printFileError(st->keyFileName, errno);
            exit(EXIT_FAILURE);
        }
        
        if(!st->passWordGiven) {
            if(freadWErrCheck(st->yaxaKey,1,sizeof(*st->yaxaKey) * st->keyBufSize,keyFile, st) != 0) {
                printSysError(st->returnVal);
                exit(EXIT_FAILURE);
            }
            fclose(keyFile);
        } else {
            if(freadWErrCheck(st->yaxaKey,1,sizeof(*st->yaxaKey) * (st->keyFileSize),keyFile, st) != 0) {
                printSysError(st->returnVal);
                exit(EXIT_FAILURE);
            }
            fclose(keyFile);
            st->keyBufSize = HMAC_KEY_SIZE;
            #ifdef gui
            strcpy(st->statusMessage,"Generating encryption key...");
            *(st->overallProgressFraction) = .2;
            #endif
            genYaxaKey(st);
            st->keyBufSize = st->keyFileSize;
        }
        
    } else if(st->oneTimePad) {
        
        st->keyBufSize = HMAC_KEY_SIZE;
        
        otpInFile = fopen(st->otpInFileName,"rb");
        if (otpInFile == NULL) {
            printFileError(st->otpInFileName, errno);
            exit(EXIT_FAILURE);
        }
        
        if(action == 'e') {
            otpOutFile = fopen(st->otpOutFileName,"wb");
        }
        
        if(st->passWordGiven) {
            #ifdef gui
            strcpy(st->statusMessage,"Generating encryption key...");
            *(st->overallProgressFraction) = .2;
            #endif
            genYaxaKey(st);
        } else {
            if(freadWErrCheck(st->yaxaKey,sizeof(*st->yaxaKey),HMAC_KEY_SIZE,otpInFile,st) != 0) {
                printSysError(st->returnVal);
                exit(EXIT_FAILURE);
            }
            if(action == 'e') {
                if(fwriteWErrCheck(st->yaxaKey,sizeof(*st->yaxaKey),HMAC_KEY_SIZE,otpOutFile,st) != 0) {
                    printSysError(st->returnVal);
                    exit(EXIT_FAILURE);
                }
            }
        }
        
    } else {
        #ifdef gui
        strcpy(st->statusMessage,"Generating encryption key...");
        *(st->overallProgressFraction) = .2;
        #endif
        genYaxaKey(st);
    }
    
    #ifdef gui
    strcpy(st->statusMessage,"Generating counter start...");
    #endif
    genCtrStart(st);
    
    #ifdef gui
    strcpy(st->statusMessage,"Generating nonce...");
    #endif
    genNonce(st);
    
    #ifdef gui
    strcpy(st->statusMessage,"Generation auth key...");
    *(st->overallProgressFraction) = .3;
    #endif
    genHMACKey(st);
    
    #ifdef gui
    strcpy(st->statusMessage,"Password keyed-hash...");
    *(st->overallProgressFraction) = .4;
    #endif
    genPassTag(st);
    
    if(action == 'd') {
        #ifdef gui
        strcpy(st->statusMessage,"Verifying password...");
        *(st->overallProgressFraction) = .6;
        #endif
        if (CRYPTO_memcmp(st->passKeyedHash, st->passKeyedHashFromFile, sizeof(*st->passKeyedHashFromFile) * PASS_KEYED_HASH_SIZE) != 0) {
            printf("Wrong password\n");
            #ifdef gui
            strcpy(st->statusMessage,"Wrong password");
            #endif
            exit(EXIT_FAILURE);
        }
    }

    if(action == 'e') {
        fileSize = getFileSize(st->inputFileName);
        
        #ifdef gui
        strcpy(st->statusMessage,"Writing salt...");
        *(st->overallProgressFraction) = .5;
        #endif
        /*Prepend salt to head of file*/
        if (fwriteWErrCheck(st->yaxaSalt, sizeof(*st->yaxaSalt), st->yaxaSaltSize, outFile, st) != 0) {
            printSysError(st->returnVal);
            printError("Could not write salt");
            exit(EXIT_FAILURE);
        }

        #ifdef gui
        strcpy(st->statusMessage,"Writing password keyed-hash...");
        *(st->overallProgressFraction) = .6;
        #endif
        /*Write passKeyedHash to head of file next to salt*/
        if (fwriteWErrCheck(st->passKeyedHash, sizeof(*st->passKeyedHash), PASS_KEYED_HASH_SIZE, outFile, st) != 0) {
            printSysError(st->returnVal);
            printError("Could not write password hash");
            exit(EXIT_FAILURE);
        }

        #ifdef gui
        strcpy(st->statusMessage,"Encrypting...");
        *(st->overallProgressFraction) = .7;
        #endif
    } else if(action == 'd') {
        /*Get filesize, discounting the salt and passKeyedHash*/
        fileSize = getFileSize(st->inputFileName) - (st->yaxaSaltSize + PASS_KEYED_HASH_SIZE);

        /*Move file position to the start of the MAC*/
        fseek(inFile, (fileSize + st->yaxaSaltSize + PASS_KEYED_HASH_SIZE) - MAC_SIZE, SEEK_SET);

        if (freadWErrCheck(st->fileMAC, sizeof(*st->fileMAC), MAC_SIZE, inFile,st) != 0) {
            printSysError(st->returnVal);
            printError("Could not read MAC");
            exit(EXIT_FAILURE);
        }

        /*Reset file position to beginning of file*/
        rewind(inFile);

        #ifdef gui
        strcpy(st->statusMessage,"Authenticating data...");
        *(st->overallProgressFraction) = .7;
        #endif
        genHMAC(inFile, (fileSize + (st->yaxaSaltSize + PASS_KEYED_HASH_SIZE)) - MAC_SIZE, st);

        /*Verify MAC*/
        if (CRYPTO_memcmp(st->fileMAC, st->generatedMAC, sizeof(*st->generatedMAC) * MAC_SIZE) != 0) {
            printf("Message authentication failed\n");
            #ifdef gui
            strcpy(st->statusMessage,"Authentication failure");
            #endif
            exit(EXIT_FAILURE);
        }

        OPENSSL_cleanse(st->hmacKey, sizeof(*st->hmacKey) * HMAC_KEY_SIZE);

        /*Reset file posiiton to beginning of cipher-text after the salt and pass tag*/
        fseek(inFile, st->yaxaSaltSize + PASS_KEYED_HASH_SIZE, SEEK_SET);
        
        #ifdef gui
        strcpy(st->statusMessage,"Decrypting...");
        *(st->overallProgressFraction) = .8;
        #endif
    }
    
    if(action == 'e') {
        /*Encrypt file and write it out*/
        if(st->oneTimePad) {
            doCrypt(inFile, outFile, fileSize, otpInFile, otpOutFile,st);
        } else {
            doCrypt(inFile, outFile, fileSize, NULL, NULL,st);
        }
    } else if (action == 'd') {
        /*Now decrypt the cipher-text, disocounting the size of the MAC*/        
        if(st->oneTimePad) {
            doCrypt(inFile, outFile, fileSize - MAC_SIZE, otpInFile, NULL,st);
        } else {
            doCrypt(inFile, outFile, fileSize - MAC_SIZE, NULL, NULL,st);
        }
    }

    if(fclose(inFile) != 0) {
        printSysError(errno);
        printError("Error closing file");
        exit(EXIT_FAILURE);
    }

    OPENSSL_cleanse(st->hmacKey, sizeof(*st->hmacKey) * HMAC_KEY_SIZE);

    if(action == 'e') {
        /*Write the MAC to the end of the file*/
        if (fwriteWErrCheck(st->generatedMAC, sizeof(*st->generatedMAC), MAC_SIZE, outFile, st) != 0) {
            printSysError(st->returnVal);
            printError("Could not write MAC");
            exit(EXIT_FAILURE);
        }
    }

    #ifdef gui
    strcpy(st->statusMessage,"Saving file...");
    *(st->overallProgressFraction) = .9;
    #endif
    
    if(fclose(outFile) != 0) {
        printSysError(errno);
        printError("Could not close file");
        exit(EXIT_FAILURE);
    }
    
    #ifdef gui
    if(action == 'e') {
        strcpy(st->statusMessage,"File encrypted");
        *(st->overallProgressFraction) = 1;
    } else if (action == 'd') {
        strcpy(st->statusMessage,"File decrypted");
        *(st->overallProgressFraction) = 1;
    }
    #endif
    
    exit(EXIT_SUCCESS);
    
    return 0;
}
