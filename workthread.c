int workThread(char action, struct optionsStruct optSt)
{
    pid_t p = fork();
    if(p) return 0;
            
    FILE *inFile = fopen(fileSt.inputFileName, "rb");
    if (inFile == NULL) {
        printFileError(fileSt.inputFileName, errno);
        exit(EXIT_FAILURE);
    }
    FILE *outFile = fopen(fileSt.outputFileName, "wb+");
    if (outFile == NULL) {
        printFileError(fileSt.outputFileName, errno);
        exit(EXIT_FAILURE);
    }
    
    FILE *otpInFile = NULL;
    FILE *otpOutFile = NULL;

    cryptint_t fileSize;
    
    cryptSt.counterInt = 0;
    cryptSt.keyInt = 0;
    cryptSt.k = 0;

    if(action == 'e') {
        #ifdef gui
        strcpy(progressSt.statusMessage,"Generating salt...");
        *progressSt.overallProgressFraction = .1;
        #endif
        genYaxaSalt();
    } else if(action == 'd') {
        #ifdef gui
        strcpy(progressSt.statusMessage,"Reading salt...");
        *progressSt.overallProgressFraction = .1;
        #endif
        /*Read yaxaSalt from head of cipher-text*/
        if (freadWErrCheck(cryptSt.yaxaSalt, sizeof(*cryptSt.yaxaSalt), sizesSt.yaxaSaltSize, inFile) != 0) {
            printSysError(miscSt.returnVal);
            printError("Could not read salt");
            exit(EXIT_FAILURE);
        }
    }
        
    if(action == 'd') {
        #ifdef gui
        strcpy(progressSt.statusMessage,"Reading pass keyed-hash...");
        *progressSt.overallProgressFraction = .2;
        #endif
        /*Get passKeyedHashFromFile*/
        if (freadWErrCheck(cryptSt.passKeyedHashFromFile, sizeof(*cryptSt.passKeyedHashFromFile), PASS_KEYED_HASH_SIZE, inFile) != 0) {
            printSysError(miscSt.returnVal);
            printError("Could not read password hash");
            exit(EXIT_FAILURE);
        }
    }
        
    if(optSt.keyFileGiven) {
        
        FILE *keyFile = fopen(fileSt.keyFileName,"rb");
        if (keyFile == NULL) {
            printFileError(fileSt.keyFileName, errno);
            exit(EXIT_FAILURE);
        }
        
        if(!optSt.passWordGiven) {
            if(freadWErrCheck(cryptSt.yaxaKey,1,sizeof(*cryptSt.yaxaKey) * sizesSt.keyBufSize,keyFile) != 0) {
                printSysError(miscSt.returnVal);
                exit(EXIT_FAILURE);
            }
            fclose(keyFile);
        } else {
            if(freadWErrCheck(cryptSt.yaxaKey,1,sizeof(*cryptSt.yaxaKey) * (sizesSt.keyFileSize),keyFile) != 0) {
                printSysError(miscSt.returnVal);
                exit(EXIT_FAILURE);
            }
            fclose(keyFile);
            sizesSt.keyBufSize = HMAC_KEY_SIZE;
            #ifdef gui
            strcpy(progressSt.statusMessage,"Generating encryption key...");
            *progressSt.overallProgressFraction = .2;
            #endif
            genYaxaKey();
            sizesSt.keyBufSize = sizesSt.keyFileSize;
        }
        
    } else if(optSt.oneTimePad) {
        
        sizesSt.keyBufSize = HMAC_KEY_SIZE;
        
        otpInFile = fopen(fileSt.otpInFileName,"rb");
        if (otpInFile == NULL) {
            printFileError(fileSt.otpInFileName, errno);
            exit(EXIT_FAILURE);
        }
        
        if(action == 'e') {
            otpOutFile = fopen(fileSt.otpOutFileName,"wb");
        }
        
        if(optSt.passWordGiven) {
            #ifdef gui
            strcpy(progressSt.statusMessage,"Generating encryption key...");
            *progressSt.overallProgressFraction = .2;
            #endif
            genYaxaKey();
        } else {
            if(freadWErrCheck(cryptSt.yaxaKey,sizeof(*cryptSt.yaxaKey),HMAC_KEY_SIZE,otpInFile) != 0) {
                printSysError(miscSt.returnVal);
                exit(EXIT_FAILURE);
            }
            if(action == 'e') {
                if(fwriteWErrCheck(cryptSt.yaxaKey,sizeof(*cryptSt.yaxaKey),HMAC_KEY_SIZE,otpOutFile) != 0) {
                    printSysError(miscSt.returnVal);
                    exit(EXIT_FAILURE);
                }
            }
        }
        
    } else {
        #ifdef gui
        strcpy(progressSt.statusMessage,"Generating encryption key...");
        *progressSt.overallProgressFraction = .2;
        #endif
        genYaxaKey();
    }
    
    #ifdef gui
    strcpy(progressSt.statusMessage,"Generating counter start...");
    #endif
    genCtrStart();
    
    #ifdef gui
    strcpy(progressSt.statusMessage,"Generating nonce...");
    #endif
    genNonce();
    
    #ifdef gui
    strcpy(progressSt.statusMessage,"Generation auth key...");
    *progressSt.overallProgressFraction = .3;
    #endif
    genHMACKey();
    
    #ifdef gui
    strcpy(progressSt.statusMessage,"Password keyed-hash...");
    *progressSt.overallProgressFraction = .4;
    #endif
    genPassTag();
    
    if(action == 'd') {
        #ifdef gui
        strcpy(progressSt.statusMessage,"Verifying password...");
        *progressSt.overallProgressFraction = .6;
        #endif
        if (CRYPTO_memcmp(cryptSt.passKeyedHash, cryptSt.passKeyedHashFromFile, sizeof(*cryptSt.passKeyedHashFromFile) * PASS_KEYED_HASH_SIZE) != 0) {
            printf("Wrong password\n");
            #ifdef gui
            strcpy(progressSt.statusMessage,"Wrong password");
            #endif
            exit(EXIT_FAILURE);
        }
    }

    if(action == 'e') {
        fileSize = getFileSize(fileSt.inputFileName);
        
        #ifdef gui
        strcpy(progressSt.statusMessage,"Writing salt...");
        *progressSt.overallProgressFraction = .5;
        #endif
        /*Prepend salt to head of file*/
        if (fwriteWErrCheck(cryptSt.yaxaSalt, sizeof(*cryptSt.yaxaSalt), sizesSt.yaxaSaltSize, outFile) != 0) {
            printSysError(miscSt.returnVal);
            printError("Could not write salt");
            exit(EXIT_FAILURE);
        }

        #ifdef gui
        strcpy(progressSt.statusMessage,"Writing password keyed-hash...");
        *progressSt.overallProgressFraction = .6;
        #endif
        /*Write passKeyedHash to head of file next to salt*/
        if (fwriteWErrCheck(cryptSt.passKeyedHash, sizeof(*cryptSt.passKeyedHash), PASS_KEYED_HASH_SIZE, outFile) != 0) {
            printSysError(miscSt.returnVal);
            printError("Could not write password hash");
            exit(EXIT_FAILURE);
        }

        #ifdef gui
        strcpy(progressSt.statusMessage,"Encrypting...");
        *progressSt.overallProgressFraction = .7;
        #endif
    } else if(action == 'd') {
        /*Get filesize, discounting the salt and passKeyedHash*/
        fileSize = getFileSize(fileSt.inputFileName) - (sizesSt.yaxaSaltSize + PASS_KEYED_HASH_SIZE);

        /*Move file position to the start of the MAC*/
        fseek(inFile, (fileSize + sizesSt.yaxaSaltSize + PASS_KEYED_HASH_SIZE) - MAC_SIZE, SEEK_SET);

        if (freadWErrCheck(cryptSt.fileMAC, sizeof(*cryptSt.fileMAC), MAC_SIZE, inFile) != 0) {
            printSysError(miscSt.returnVal);
            printError("Could not read MAC");
            exit(EXIT_FAILURE);
        }

        /*Reset file position to beginning of file*/
        rewind(inFile);

        #ifdef gui
        strcpy(progressSt.statusMessage,"Authenticating data...");
        *progressSt.overallProgressFraction = .7;
        #endif
        genHMAC(inFile, (fileSize + (sizesSt.yaxaSaltSize + PASS_KEYED_HASH_SIZE)) - MAC_SIZE);

        /*Verify MAC*/
        if (CRYPTO_memcmp(cryptSt.fileMAC, cryptSt.generatedMAC, sizeof(*cryptSt.generatedMAC) * MAC_SIZE) != 0) {
            printf("Message authentication failed\n");
            #ifdef gui
            strcpy(progressSt.statusMessage,"Authentication failure");
            #endif
            exit(EXIT_FAILURE);
        }

        OPENSSL_cleanse(cryptSt.hmacKey, sizeof(*cryptSt.hmacKey) * HMAC_KEY_SIZE);

        /*Reset file posiiton to beginning of cipher-text after the salt and pass tag*/
        fseek(inFile, sizesSt.yaxaSaltSize + PASS_KEYED_HASH_SIZE, SEEK_SET);
        
        #ifdef gui
        strcpy(progressSt.statusMessage,"Decrypting...");
        *progressSt.overallProgressFraction = .8;
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

    OPENSSL_cleanse(cryptSt.hmacKey, sizeof(*cryptSt.hmacKey) * HMAC_KEY_SIZE);

    if(action == 'e') {
        /*Write the MAC to the end of the file*/
        if (fwriteWErrCheck(cryptSt.generatedMAC, sizeof(*cryptSt.generatedMAC), MAC_SIZE, outFile) != 0) {
            printSysError(miscSt.returnVal);
            printError("Could not write MAC");
            exit(EXIT_FAILURE);
        }
    }

    #ifdef gui
    strcpy(progressSt.statusMessage,"Saving file...");
    *progressSt.overallProgressFraction = .9;
    #endif
    
    if(fclose(outFile) != 0) {
        printSysError(errno);
        printError("Could not close file");
        exit(EXIT_FAILURE);
    }
    
    #ifdef gui
    if(action == 'e') {
        strcpy(progressSt.statusMessage,"File encrypted");
        *progressSt.overallProgressFraction = 1;
    } else if (action == 'd') {
        strcpy(progressSt.statusMessage,"File decrypted");
        *progressSt.overallProgressFraction = 1;
    }
    #endif
    
    exit(EXIT_SUCCESS);
    
    return 0;
}
