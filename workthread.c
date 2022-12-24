int workThread(char action, struct optionsStruct optSt)
{
    pid_t p = fork();
    if(p) return 0;
            
    FILE *inFile = fopen(inputFileName, "rb");
    if (inFile == NULL) {
        printFileError(inputFileName, errno);
        exit(EXIT_FAILURE);
    }
    FILE *outFile = fopen(outputFileName, "wb+");
    if (outFile == NULL) {
        printFileError(outputFileName, errno);
        exit(EXIT_FAILURE);
    }
    
    FILE *otpInFile = NULL;
    FILE *otpOutFile = NULL;

    cryptint_t fileSize;
    
    counterInt = 0;
    keyInt = 0;
    k = 0;

    if(action == 'e') {
        #ifdef gui
        strcpy(statusMessage,"Generating salt...");
        *overallProgressFraction = .1;
        #endif
        genYaxaSalt();
    } else if(action == 'd') {
        #ifdef gui
        strcpy(statusMessage,"Reading salt...");
        *overallProgressFraction = .1;
        #endif
        /*Read yaxaSalt from head of cipher-text*/
        if (freadWErrCheck(yaxaSalt, sizeof(*yaxaSalt), yaxaSaltSize, inFile) != 0) {
            printSysError(returnVal);
            printError("Could not read salt");
            exit(EXIT_FAILURE);
        }
    }
        
    if(action == 'd') {
        #ifdef gui
        strcpy(statusMessage,"Reading pass keyed-hash...");
        *overallProgressFraction = .2;
        #endif
        /*Get passKeyedHashFromFile*/
        if (freadWErrCheck(passKeyedHashFromFile, sizeof(*passKeyedHashFromFile), PASS_KEYED_HASH_SIZE, inFile) != 0) {
            printSysError(returnVal);
            printError("Could not read password hash");
            exit(EXIT_FAILURE);
        }
    }
        
    if(optSt.keyFileGiven) {
        
        FILE *keyFile = fopen(keyFileName,"rb");
        if (keyFile == NULL) {
            printFileError(keyFileName, errno);
            exit(EXIT_FAILURE);
        }
        
        if(!optSt.passWordGiven) {
            if(freadWErrCheck(yaxaKey,1,sizeof(*yaxaKey) * keyBufSize,keyFile) != 0) {
                printSysError(returnVal);
                exit(EXIT_FAILURE);
            }
            fclose(keyFile);
        } else {
            if(freadWErrCheck(yaxaKey,1,sizeof(*yaxaKey) * (keyFileSize),keyFile) != 0) {
                printSysError(returnVal);
                exit(EXIT_FAILURE);
            }
            fclose(keyFile);
            keyBufSize = HMAC_KEY_SIZE;
            #ifdef gui
            strcpy(statusMessage,"Generating encryption key...");
            *overallProgressFraction = .2;
            #endif
            genYaxaKey();
            keyBufSize = keyFileSize;
        }
        
    } else if(optSt.oneTimePad) {
        
        keyBufSize = HMAC_KEY_SIZE;
        
        otpInFile = fopen(otpInFileName,"rb");
        if (otpInFile == NULL) {
            printFileError(otpInFileName, errno);
            exit(EXIT_FAILURE);
        }
        
        if(action == 'e') {
            otpOutFile = fopen(otpOutFileName,"wb");
        }
        
        if(optSt.passWordGiven) {
            #ifdef gui
            strcpy(statusMessage,"Generating encryption key...");
            *overallProgressFraction = .2;
            #endif
            genYaxaKey();
        } else {
            if(freadWErrCheck(yaxaKey,sizeof(*yaxaKey),HMAC_KEY_SIZE,otpInFile) != 0) {
                printSysError(returnVal);
                exit(EXIT_FAILURE);
            }
            if(action == 'e') {
                if(fwriteWErrCheck(yaxaKey,sizeof(*yaxaKey),HMAC_KEY_SIZE,otpOutFile) != 0) {
                    printSysError(returnVal);
                    exit(EXIT_FAILURE);
                }
            }
        }
        
    } else {
        #ifdef gui
        strcpy(statusMessage,"Generating encryption key...");
        *overallProgressFraction = .2;
        #endif
        genYaxaKey();
    }
    
    #ifdef gui
    strcpy(statusMessage,"Generating counter start...");
    #endif
    genCtrStart();
    
    #ifdef gui
    strcpy(statusMessage,"Generating nonce...");
    #endif
    genNonce();
    
    #ifdef gui
    strcpy(statusMessage,"Generation auth key...");
    *overallProgressFraction = .3;
    #endif
    genHMACKey();
    
    #ifdef gui
    strcpy(statusMessage,"Password keyed-hash...");
    *overallProgressFraction = .4;
    #endif
    genPassTag();
    
    if(action == 'd') {
        #ifdef gui
        strcpy(statusMessage,"Verifying password...");
        *overallProgressFraction = .6;
        #endif
        if (CRYPTO_memcmp(passKeyedHash, passKeyedHashFromFile, sizeof(*passKeyedHashFromFile) * PASS_KEYED_HASH_SIZE) != 0) {
            printf("Wrong password\n");
            #ifdef gui
            strcpy(statusMessage,"Wrong password");
            #endif
            exit(EXIT_FAILURE);
        }
    }

    if(action == 'e') {
        fileSize = getFileSize(inputFileName);
        
        #ifdef gui
        strcpy(statusMessage,"Writing salt...");
        *overallProgressFraction = .5;
        #endif
        /*Prepend salt to head of file*/
        if (fwriteWErrCheck(yaxaSalt, sizeof(*yaxaSalt), yaxaSaltSize, outFile) != 0) {
            printSysError(returnVal);
            printError("Could not write salt");
            exit(EXIT_FAILURE);
        }

        #ifdef gui
        strcpy(statusMessage,"Writing password keyed-hash...");
        *overallProgressFraction = .6;
        #endif
        /*Write passKeyedHash to head of file next to salt*/
        if (fwriteWErrCheck(passKeyedHash, sizeof(*passKeyedHash), PASS_KEYED_HASH_SIZE, outFile) != 0) {
            printSysError(returnVal);
            printError("Could not write password hash");
            exit(EXIT_FAILURE);
        }

        #ifdef gui
        strcpy(statusMessage,"Encrypting...");
        *overallProgressFraction = .7;
        #endif
    } else if(action == 'd') {
        /*Get filesize, discounting the salt and passKeyedHash*/
        fileSize = getFileSize(inputFileName) - (yaxaSaltSize + PASS_KEYED_HASH_SIZE);

        /*Move file position to the start of the MAC*/
        fseek(inFile, (fileSize + yaxaSaltSize + PASS_KEYED_HASH_SIZE) - MAC_SIZE, SEEK_SET);

        if (freadWErrCheck(fileMAC, sizeof(*fileMAC), MAC_SIZE, inFile) != 0) {
            printSysError(returnVal);
            printError("Could not read MAC");
            exit(EXIT_FAILURE);
        }

        /*Reset file position to beginning of file*/
        rewind(inFile);

        #ifdef gui
        strcpy(statusMessage,"Authenticating data...");
        *overallProgressFraction = .7;
        #endif
        genHMAC(inFile, (fileSize + (yaxaSaltSize + PASS_KEYED_HASH_SIZE)) - MAC_SIZE);

        /*Verify MAC*/
        if (CRYPTO_memcmp(fileMAC, generatedMAC, sizeof(*generatedMAC) * MAC_SIZE) != 0) {
            printf("Message authentication failed\n");
            #ifdef gui
            strcpy(statusMessage,"Authentication failure");
            #endif
            exit(EXIT_FAILURE);
        }

        OPENSSL_cleanse(hmacKey, sizeof(*hmacKey) * HMAC_KEY_SIZE);

        /*Reset file posiiton to beginning of cipher-text after the salt and pass tag*/
        fseek(inFile, yaxaSaltSize + PASS_KEYED_HASH_SIZE, SEEK_SET);
        
        #ifdef gui
        strcpy(statusMessage,"Decrypting...");
        *overallProgressFraction = .8;
        #endif
    }
    
    if(action == 'e') {
        /*Encrypt file and write it out*/
        if(optSt.oneTimePad) {
            doCrypt(inFile, outFile, fileSize, otpInFile, otpOutFile);
        } else {
            doCrypt(inFile, outFile, fileSize, NULL, NULL);
        }
    } else if (action == 'd') {
        /*Now decrypt the cipher-text, disocounting the size of the MAC*/        
        if(optSt.oneTimePad) {
            doCrypt(inFile, outFile, fileSize - MAC_SIZE, otpInFile, NULL);
        } else {
            doCrypt(inFile, outFile, fileSize - MAC_SIZE, NULL, NULL);
        }
    }

    if(fclose(inFile) != 0) {
        printSysError(errno);
        printError("Error closing file");
        exit(EXIT_FAILURE);
    }

    OPENSSL_cleanse(hmacKey, sizeof(*hmacKey) * HMAC_KEY_SIZE);

    if(action == 'e') {
        /*Write the MAC to the end of the file*/
        if (fwriteWErrCheck(generatedMAC, sizeof(*generatedMAC), MAC_SIZE, outFile) != 0) {
            printSysError(returnVal);
            printError("Could not write MAC");
            exit(EXIT_FAILURE);
        }
    }

    #ifdef gui
    strcpy(statusMessage,"Saving file...");
    *overallProgressFraction = .9;
    #endif
    
    if(fclose(outFile) != 0) {
        printSysError(errno);
        printError("Could not close file");
        exit(EXIT_FAILURE);
    }
    
    #ifdef gui
    if(action == 'e') {
        strcpy(statusMessage,"File encrypted");
        *overallProgressFraction = 1;
    } else if (action == 'd') {
        strcpy(statusMessage,"File decrypted");
        *overallProgressFraction = 1;
    }
    #endif
    
    exit(EXIT_SUCCESS);
    
    return 0;
}
