int workThread(char action, struct dataStruct *st)
{
    pid_t p = fork();
    if(p) return 0;
                
    FILE *inFile = fopen(st->fileNameSt.inputFileName, "rb");
    if (inFile == NULL) {
        printFileError(st->fileNameSt.inputFileName, errno);
        exit(EXIT_FAILURE);
    }
    FILE *outFile = fopen(st->fileNameSt.outputFileName, "wb+");
    if (outFile == NULL) {
        printFileError(st->fileNameSt.outputFileName, errno);
        exit(EXIT_FAILURE);
    }
    
    FILE *otpInFile = NULL;
    FILE *otpOutFile = NULL;
    
    cryptint_t fileSize;
    
    st->cryptSt.counterInt = 0;
    st->cryptSt.keyInt = 0;
    st->cryptSt.k = 0;
    
    #ifdef gui
    st->guiSt.startTime = clock();
    #endif

    if(action == 'e') {
        #ifdef gui
        strcpy(st->guiSt.statusMessage,"Generating salt...");
        *(st->guiSt.overallProgressFraction) = .1;
        #endif
        genYaxaSalt(st);
    } else if(action == 'd') {
        #ifdef gui
        strcpy(st->guiSt.statusMessage,"Reading salt...");
        *(st->guiSt.overallProgressFraction) = .1;
        #endif
        /*Read yaxaSalt from head of cipher-text*/
        if (freadWErrCheck(st->cryptSt.yaxaSalt, sizeof(*st->cryptSt.yaxaSalt), st->cryptSt.yaxaSaltSize, inFile, st) != 0) {
            printSysError(st->miscSt.returnVal);
            printError("Could not read salt");
            exit(EXIT_FAILURE);
        }
    }
        
    if(action == 'd') {
        #ifdef gui
        strcpy(st->guiSt.statusMessage,"Reading pass keyed-hash...");
        *(st->guiSt.overallProgressFraction) = .2;
        #endif
        /*Get passKeyedHashFromFile*/
        if (freadWErrCheck(st->cryptSt.passKeyedHashFromFile, sizeof(*st->cryptSt.passKeyedHashFromFile), PASS_KEYED_HASH_SIZE, inFile, st) != 0) {
            printSysError(st->miscSt.returnVal);
            printError("Could not read password hash");
            exit(EXIT_FAILURE);
        }
    }
        
    if(st->optSt.keyFileGiven) {
        
        FILE *keyFile = fopen(st->fileNameSt.keyFileName,"rb");
        if (keyFile == NULL) {
            printFileError(st->fileNameSt.keyFileName, errno);
            exit(EXIT_FAILURE);
        }
        
        if(!st->optSt.passWordGiven) {
            if(freadWErrCheck(st->cryptSt.yaxaKey,1,sizeof(*st->cryptSt.yaxaKey) * st->cryptSt.keyBufSize,keyFile, st) != 0) {
                printSysError(st->miscSt.returnVal);
                exit(EXIT_FAILURE);
            }
            fclose(keyFile);
        } else {
            if(freadWErrCheck(st->cryptSt.yaxaKey,1,sizeof(*st->cryptSt.yaxaKey) * (st->cryptSt.keyFileSize),keyFile, st) != 0) {
                printSysError(st->miscSt.returnVal);
                exit(EXIT_FAILURE);
            }
            fclose(keyFile);
            st->cryptSt.keyBufSize = HMAC_KEY_SIZE;
            #ifdef gui
            strcpy(st->guiSt.statusMessage,"Generating encryption key...");
            *(st->guiSt.overallProgressFraction) = .2;
            #endif
            genYaxaKey(st);
            st->cryptSt.keyBufSize = st->cryptSt.keyFileSize;
        }
        
    } else if(st->optSt.oneTimePad) {
        
        st->cryptSt.keyBufSize = HMAC_KEY_SIZE;
        
        otpInFile = fopen(st->fileNameSt.otpInFileName,"rb");
        if (otpInFile == NULL) {
            printFileError(st->fileNameSt.otpInFileName, errno);
            exit(EXIT_FAILURE);
        }
        
        if(action == 'e') {
            otpOutFile = fopen(st->fileNameSt.otpOutFileName,"wb");
            if(otpOutFile == NULL) {
                printFileError(st->fileNameSt.otpOutFileName,errno);
            }
        }
        
        if(st->optSt.passWordGiven) {
            #ifdef gui
            strcpy(st->guiSt.statusMessage,"Generating encryption key...");
            *(st->guiSt.overallProgressFraction) = .2;
            #endif
            genYaxaKey(st);
        } else {
            if(freadWErrCheck(st->cryptSt.yaxaKey,sizeof(*st->cryptSt.yaxaKey),HMAC_KEY_SIZE,otpInFile,st) != 0) {
                printSysError(st->miscSt.returnVal);
                exit(EXIT_FAILURE);
            }
            if(action == 'e') {
                if(fwriteWErrCheck(st->cryptSt.yaxaKey,sizeof(*st->cryptSt.yaxaKey),HMAC_KEY_SIZE,otpOutFile,st) != 0) {
                    printSysError(st->miscSt.returnVal);
                    exit(EXIT_FAILURE);
                }
            }
        }
        
    } else {
        #ifdef gui
        strcpy(st->guiSt.statusMessage,"Generating encryption key...");
        *(st->guiSt.overallProgressFraction) = .2;
        #endif
        genYaxaKey(st);
    }
    
    #ifdef gui
    strcpy(st->guiSt.statusMessage,"Generating counter start...");
    #endif
    genCtrStart(st);
    
    #ifdef gui
    strcpy(st->guiSt.statusMessage,"Generating nonce...");
    #endif
    genNonce(st);
    
    #ifdef gui
    strcpy(st->guiSt.statusMessage,"Generation auth key...");
    *(st->guiSt.overallProgressFraction) = .3;
    #endif
    genHMACKey(st);
    
    #ifdef gui
    strcpy(st->guiSt.statusMessage,"Password keyed-hash...");
    *(st->guiSt.overallProgressFraction) = .4;
    #endif
    genPassTag(st);
    
    if(action == 'd') {
        #ifdef gui
        strcpy(st->guiSt.statusMessage,"Verifying password...");
        *(st->guiSt.overallProgressFraction) = .6;
        #endif
        if (CRYPTO_memcmp(st->cryptSt.passKeyedHash, st->cryptSt.passKeyedHashFromFile, sizeof(*st->cryptSt.passKeyedHashFromFile) * PASS_KEYED_HASH_SIZE) != 0) {
            printf("Wrong password\n");
            #ifdef gui
            strcpy(st->guiSt.statusMessage,"Wrong password");
            #endif
            exit(EXIT_FAILURE);
        }
    }

    if(action == 'e') {
        fileSize = getFileSize(st->fileNameSt.inputFileName);
        
        #ifdef gui
        strcpy(st->guiSt.statusMessage,"Writing salt...");
        *(st->guiSt.overallProgressFraction) = .5;
        #endif
        /*Prepend salt to head of file*/
        if (fwriteWErrCheck(st->cryptSt.yaxaSalt, sizeof(*st->cryptSt.yaxaSalt), st->cryptSt.yaxaSaltSize, outFile, st) != 0) {
            printSysError(st->miscSt.returnVal);
            printError("Could not write salt");
            exit(EXIT_FAILURE);
        }

        #ifdef gui
        strcpy(st->guiSt.statusMessage,"Writing password keyed-hash...");
        *(st->guiSt.overallProgressFraction) = .6;
        #endif
        /*Write passKeyedHash to head of file next to salt*/
        if (fwriteWErrCheck(st->cryptSt.passKeyedHash, sizeof(*st->cryptSt.passKeyedHash), PASS_KEYED_HASH_SIZE, outFile, st) != 0) {
            printSysError(st->miscSt.returnVal);
            printError("Could not write password hash");
            exit(EXIT_FAILURE);
        }

        #ifdef gui
        strcpy(st->guiSt.statusMessage,"Encrypting...");
        *(st->guiSt.overallProgressFraction) = .7;
        #endif
    } else if(action == 'd') {
        /*Get filesize, discounting the salt and passKeyedHash*/
        fileSize = getFileSize(st->fileNameSt.inputFileName) - (st->cryptSt.yaxaSaltSize + PASS_KEYED_HASH_SIZE);

        /*Move file position to the start of the MAC*/
        fseek(inFile, (fileSize + st->cryptSt.yaxaSaltSize + PASS_KEYED_HASH_SIZE) - MAC_SIZE, SEEK_SET);

        if (freadWErrCheck(st->cryptSt.fileMAC, sizeof(*st->cryptSt.fileMAC), MAC_SIZE, inFile,st) != 0) {
            printSysError(st->miscSt.returnVal);
            printError("Could not read MAC");
            exit(EXIT_FAILURE);
        }

        /*Reset file position to beginning of file*/
        rewind(inFile);

        #ifdef gui
        strcpy(st->guiSt.statusMessage,"Authenticating data...");
        *(st->guiSt.overallProgressFraction) = .7;
        #endif
        genHMAC(inFile, (fileSize + (st->cryptSt.yaxaSaltSize + PASS_KEYED_HASH_SIZE)) - MAC_SIZE, st);

        /*Verify MAC*/
        if (CRYPTO_memcmp(st->cryptSt.fileMAC, st->cryptSt.generatedMAC, sizeof(*st->cryptSt.generatedMAC) * MAC_SIZE) != 0) {
            printf("Message authentication failed\n");
            #ifdef gui
            strcpy(st->guiSt.statusMessage,"Authentication failure");
            #endif
            exit(EXIT_FAILURE);
        }

        OPENSSL_cleanse(st->cryptSt.hmacKey, sizeof(*st->cryptSt.hmacKey) * HMAC_KEY_SIZE);

        /*Reset file posiiton to beginning of cipher-text after the salt and pass tag*/
        fseek(inFile, st->cryptSt.yaxaSaltSize + PASS_KEYED_HASH_SIZE, SEEK_SET);
        
        #ifdef gui
        strcpy(st->guiSt.statusMessage,"Decrypting...");
        *(st->guiSt.overallProgressFraction) = .8;
        #endif
    }
    
    if(action == 'e') {
        /*Encrypt file and write it out*/
        if(st->optSt.oneTimePad) {
            doCrypt(inFile, outFile, fileSize, otpInFile, otpOutFile,st);
        } else {
            doCrypt(inFile, outFile, fileSize, NULL, NULL,st);
        }
    } else if (action == 'd') {
        /*Now decrypt the cipher-text, disocounting the size of the MAC*/        
        if(st->optSt.oneTimePad) {
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

    OPENSSL_cleanse(st->cryptSt.hmacKey, sizeof(*st->cryptSt.hmacKey) * HMAC_KEY_SIZE);

    if(action == 'e') {
        /*Write the MAC to the end of the file*/
        if (fwriteWErrCheck(st->cryptSt.generatedMAC, sizeof(*st->cryptSt.generatedMAC), MAC_SIZE, outFile, st) != 0) {
            printSysError(st->miscSt.returnVal);
            printError("Could not write MAC");
            exit(EXIT_FAILURE);
        }
    }

    #ifdef gui
    strcpy(st->guiSt.statusMessage,"Saving file...");
    *(st->guiSt.overallProgressFraction) = .9;
    #endif
    
    if(fclose(outFile) != 0) {
        printSysError(errno);
        printError("Could not close file");
        exit(EXIT_FAILURE);
    }
    
    #ifdef gui
    if(action == 'e') {
        sprintf(st->guiSt.statusMessage,"File encrypted... %0.2fs elapsed,%0.2f MB/s", st->guiSt.totalTime, st->guiSt.averageRate);
        *(st->guiSt.overallProgressFraction) = 1;
    } else if (action == 'd') {
        sprintf(st->guiSt.statusMessage,"File decrypted... %0.2fs elapsed,%0.2f MB/s", st->guiSt.totalTime, st->guiSt.averageRate);
        *(st->guiSt.overallProgressFraction) = 1;
    }
    #endif
    
    /*Use SIGCONT so that calling process isn't terminated*/
    if(st->optSt.quitWhenDone) {
        kill(p,SIGCONT);
    }
    
    exit(EXIT_SUCCESS);
    
    return 0;
}
