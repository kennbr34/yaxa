/*
  This product includes software developed by the OpenSSL Project
  for use in the OpenSSL Toolkit (http://www.openssl.org/)
*/
#include "headers.h"
#include "crypt.c"
#include "misc.c"
#include "buffers.c"

uint8_t printSyntax(char *arg)
{
    printf("\
\nUse: \
\n\n%s [-e|-d] -i infile -o outfile [-p pass] [-k keyfile] [-s sizes]\
\n-e,--encrypt - encrypt infile to outfile\
\n-d,--decrypt - decrypt infile to outfile\
\n-i,--input-file - input file\
\n-o,--output-file - output file\
\n-p,--password - password to use\
\n-w,--work-factors - [N=],[r=],[p=]\
\n\t N=num\
\n\t\t N factor for scrypt to use. Must be a power of 2. Default 1048576\
\n\t r=num\
\n\t\t r factor for scrypt to use. Default 8\
\n\t p=num\
\n\t\t p factor for scrypt to use. Default 1\
\n-k,--key-file - keyfile to use\
\n-O,--otp-file - one-time-pad file. Note: message_buffer size must stay the same between encryption and decryption\
\n-s,--sizes - [key_size=],[mac_buffer=],[message_buffer=]\
\n\t key_size=num[b|k|m]\
\n\t\t Size of key to generate from password in bytes, kilobytes or megabytes\
\n\t mac_buffer=num[b|k|m]\
\n\t\t Size of input buffer to use for generating MAC, in bytes, kilobytes, or megabytes\
\n\t message_buffer=num[b|k|m]\
\n\t\t Size of encryption/decryption input/output buffers to use in bytes, kilobytes or megabytes\
\n", arg);
    printf("\nThis product includes software developed by the OpenSSL Project for use in the OpenSSL Toolkit. (http://www.openssl.org/)\n");
    return EXIT_FAILURE;
}

char *getPass(const char *prompt, char *paddedPass)
{
    size_t len = 0;
    int i = 0;
    int passLength = 0;
    char *pass = NULL;
    unsigned char *paddedPassTmp = calloc(sizeof(*paddedPassTmp), MAX_PASS_SIZE);
    if (paddedPassTmp == NULL) {
        printSysError(errno);
        exit(EXIT_FAILURE);
    }

    if (!RAND_bytes(paddedPassTmp, MAX_PASS_SIZE)) {
        fprintf(stderr, "Failure: CSPRNG bytes could not be made unpredictable\n");
        /* Restore terminal. */
        (void)tcsetattr(fileno(stdin), TCSAFLUSH, &termiosOld);
        fprintf(stderr, "\nPassword was too large\n");
        exit(EXIT_FAILURE);
    }
    memcpy(paddedPass, paddedPassTmp, sizeof(*paddedPass) * MAX_PASS_SIZE);
    OPENSSL_cleanse(paddedPassTmp, sizeof(*paddedPassTmp) * MAX_PASS_SIZE);
    free(paddedPassTmp);
    paddedPassTmp = NULL;

    int nread = 0;

    /* Turn echoing off and fail if we can’t. */
    if (tcgetattr(fileno(stdin), &termiosOld) != 0)
        exit(EXIT_FAILURE);
    termiosNew = termiosOld;
    termiosNew.c_lflag &= ~ECHO;
    if (tcsetattr(fileno(stdin), TCSAFLUSH, &termiosNew) != 0)
        exit(EXIT_FAILURE);

    /* Read the password. */
    fprintf(stderr, "\n%s", prompt);
    nread = getline(&pass, &len, stdin);
    if (nread == -1)
        exit(EXIT_FAILURE);
    else if (nread > (MAX_PASS_SIZE - 1)) {
        /* Restore terminal. */
        (void)tcsetattr(fileno(stdin), TCSAFLUSH, &termiosOld);
        OPENSSL_cleanse(pass, sizeof(*pass) * nread);
        free(pass);
        pass = NULL;
        fprintf(stderr, "\nPassword was too large\n");
        exit(EXIT_FAILURE);
    } else {
        /*Replace newline with null terminator*/
        pass[nread - 1] = '\0';
    }

    /* Restore terminal. */
    (void)tcsetattr(fileno(stdin), TCSAFLUSH, &termiosOld);

    fprintf(stderr, "\n");

    /*Copy pass into paddedPass then remove sensitive information*/
    passLength = strlen(pass);
    for (i = 0; i < passLength + 1; i++)
        paddedPass[i] = pass[i];

    OPENSSL_cleanse(pass, sizeof(*pass) * nread);
    free(pass);
    pass = NULL;

    return paddedPass;
}

void parseOptions(
int argc,
char *argv[],
struct optionsStruct *optSt
) {
    int c;
    int errflg = 0;
    char binName[NAME_MAX];
    snprintf(binName,NAME_MAX,"%s",argv[0]);

    /*Process through arguments*/
    while (1) {
        int option_index = 0;
        static struct option long_options[] = {
            {"encrypt",        no_argument,       0,'e' },
            {"decrypt",        no_argument,       0,'d' },
            {"input-file",     required_argument, 0,'i' },
            {"output-file",    required_argument, 0,'o' },
            {"key-file",       required_argument, 0,'k' },
            {"otp-file",       required_argument, 0,'O' },
            {"password",       required_argument, 0,'p' },
            {"work-factors",   required_argument, 0,'w' },
            {"sizes",          required_argument, 0,'s' },
            {0,                0,                 0, 0  }
        };
        
        char *subopts;
        char *value;
        
        c = getopt_long(argc, argv, "edi:o:k:O:p:w:s:",
                        long_options, &option_index);
       if (c == -1)
           break;

        switch (c) {
        
        case 'e':
            optSt->encrypt = true;
        break;
        case 'd':
            optSt->decrypt = true;
        break;
        case 'i':
            if (optarg[0] == '-' && strlen(optarg) == 2) {
                fprintf(stderr, "Option -i requires an argument\n");
                errflg++;
                break;
            } else {
                optSt->inputFileGiven = true;
                snprintf(inputFileName, NAME_MAX, "%s", optarg);
            }
        break;
        case 'o':
            if (optarg[0] == '-' && strlen(optarg) == 2) {
                fprintf(stderr, "Option -o requires an argument\n");
                errflg++;
                break;
            } else {
                optSt->outputFileGiven = true;
                snprintf(outputFileName, NAME_MAX, "%s", optarg);
            }
        break;
        case 'k':
            if (optarg[0] == '-' && strlen(optarg) == 2) {
                fprintf(stderr, "Option -k requires an argument\n");
                errflg++;
                break;
            } else {
                optSt->keyFileGiven = true;
                snprintf(keyFileName, NAME_MAX, "%s", optarg);
                keyFileSize = getFileSize(keyFileName);
                keyBufSize = keyFileSize;
                yaxaSaltSize = keyBufSize / YAXA_KEY_CHUNK_SIZE;
            }
        break;
        case 'O':
            if (optarg[0] == '-' && strlen(optarg) == 2) {
                fprintf(stderr, "Option -O requires an argument\n");
                errflg++;
                break;
            } else {
                optSt->oneTimePad = true;
                snprintf(otpInFileName, NAME_MAX, "%s", optarg);
                sprintf(otpOutFileName,"%s.pad", outputFileName);
                
            }
        break;
        case 'p':
            if (optarg[0] == '-' && strlen(optarg) == 2) {
                fprintf(stderr, "Option -p requires an argument\n");
                errflg++;
                break;
            } else {
                optSt->passWordGiven = true;
                snprintf(userPass, MAX_PASS_SIZE, "%s", optarg);
            }
        break;
        case 'w':
            if (optarg[0] == '-') {
                fprintf(stderr, "Option -%c requires an argument\n", c);
                errflg++;
                break;
            }

            enum {
                N_FACTOR = 0,
                R_FACTOR,
                P_FACTOR
            };

            char *const token[] = {
                [N_FACTOR] = "N",
                [R_FACTOR] = "r",
                [P_FACTOR] = "p",
                NULL};

            subopts = optarg;

            while (*subopts != '\0' && !errflg) {
                switch (getsubopt(&subopts, token, &value)) {
                case N_FACTOR:
                    nFactor = atol(value);

                    int testNum = nFactor;
                    while (testNum > 1) {
                        if (testNum % 2 != 0) {
                            fprintf(stderr, "scrypt's N factor must be a power of 2.");
                            nFactor--;
                            nFactor |= nFactor >> 1;
                            nFactor |= nFactor >> 2;
                            nFactor |= nFactor >> 4;
                            nFactor |= nFactor >> 8;
                            nFactor |= nFactor >> 16;
                            nFactor++;
                            fprintf(stderr, " Rounding it up to %zu\n", nFactor);
                            break;
                        }
                        testNum /= 2;
                    }
                    break;
                case R_FACTOR:
                    rFactor = atol(value);
                    break;
                case P_FACTOR:
                    pFactor = atol(value);
                    break;
                default:
                    fprintf(stderr, "No match found for token: %s\n", value);
                    errflg = 1;
                    break;
                }
            }
        break;
        case 's':
            if (optarg[0] == '-' && strlen(optarg) == 2) {
                fprintf(stderr, "Option -s requires an argument\n");
                errflg++;
                break;
            } else {
                enum {
                    KEY_BUFFER = 0,
                    MAC_BUFFER,
                    MSG_BUFFER
                };

                char *const token[] = {
                    [KEY_BUFFER]   = "key_size",
                    [MAC_BUFFER]   = "mac_buffer",
                    [MSG_BUFFER]   = "message_buffer",
                    NULL
                };
                
                subopts = optarg;
                while (*subopts != '\0' && !errflg) {
                    switch (getsubopt(&subopts, token, &value)) {
                    case KEY_BUFFER:
                        if (value == NULL) {
                            fprintf(stderr, "Missing value for suboption '%s'\n", token[KEY_BUFFER]);
                            errflg = 1;
                            continue;
                        }
                        
                        optSt->keyBufSizeGiven = true;
                        keyBufSize = atol(value) * sizeof(*yaxaKey) * getBufSizeMultiple(value);
                        yaxaSaltSize = keyBufSize / YAXA_KEY_CHUNK_SIZE;
                    break;
                    case MAC_BUFFER:
                        if (value == NULL) {
                            fprintf(stderr, "Missing value for suboption '%s'\n", token[MAC_BUFFER]);
                            errflg = 1;
                            continue;
                        }
                            
                        optSt->macBufSizeGiven = true;
                        genHmacBufSize = atol(value) * sizeof(uint8_t) * getBufSizeMultiple(value);
                        makeMultipleOf(&genHmacBufSize,sizeof(cryptint_t));
                    break;
                    case MSG_BUFFER:
                        if (value == NULL) {
                            fprintf(stderr, "Missing value for "
                            "suboption '%s'\n", token[MSG_BUFFER]);
                            errflg = 1;
                            continue;
                        }
                        
                        optSt->msgBufSizeGiven = true;
                        
                        /*Divide the amount specified by the size of cryptint_t since it will 
                         * be multipled later*/
                        msgBufSize = (atol(value) * getBufSizeMultiple(value));
                        makeMultipleOf(&msgBufSize,sizeof(cryptint_t));
                    break;
                    default:
                        fprintf(stderr, "No match found for token: /%s/\n", value);
                        errflg = 1;
                    break;
                    }
                }
            }
        break;
        case ':':
            fprintf(stderr, "Option -%c requires an argument\n", optopt);
            errflg++;
        break;
        case '?':
            errflg++;
        break;
        }
    }

    if(optSt->encrypt && optSt->decrypt) {
        fprintf(stderr, "-d and -e are mutually exlusive. Can only encrypt or decrypt, not both.\n");
        errflg++;
    }
    if(optSt->keyFileGiven && optSt->oneTimePad) {
        fprintf(stderr, "-k and -O are mutually exlusive. Can only use a keyfileone-time-pad, not both.\n");
        errflg++;
    }
    if(!optSt->encrypt && !optSt->decrypt) {
        fprintf(stderr, "Must specify to either encrypt or decrypt (-e or -d)\n");
        errflg++;
    }
    if(!optSt->inputFileGiven || !optSt->outputFileGiven) {
        fprintf(stderr, "Must specify an input and output file\n");
        errflg++;
    }
    
    if(!strcmp(inputFileName,outputFileName)) {
        fprintf(stderr, "Input file and output file are the same\n");
        errflg++;
    }
    
    if (errflg) {
        printSyntax(binName);
        exit(EXIT_FAILURE);
    }
    
    if((optSt->passWordGiven && optSt->keyFileGiven) || (optSt->passWordGiven && optSt->oneTimePad)) {
        yaxaSaltSize = keyBufSize / YAXA_KEY_CHUNK_SIZE;
    } else if (optSt->oneTimePad || optSt->keyFileGiven) {
        yaxaSaltSize = 0;
    }
}

int main(int argc, char *argv[])
{
    if (argc == 1) {
        printSyntax(argv[0]);
        exit(EXIT_FAILURE);
    }
    
    struct optionsStruct optSt = {0};
    
    parseOptions(argc, argv, &optSt);

    signal(SIGINT, signalHandler);

    atexit(cleanUpBuffers);

    allocateBuffers();

    OpenSSL_add_all_algorithms();

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

    if(optSt.encrypt) {
        genYaxaSalt();
    } else if(optSt.decrypt) {
        /*Read yaxaSalt from head of cipher-text*/
        if (freadWErrCheck(yaxaSalt, sizeof(*yaxaSalt), yaxaSaltSize, inFile) != 0) {
            printSysError(returnVal);
            printError("Could not read salt");
            exit(EXIT_FAILURE);
        }
    }
        
    if(optSt.decrypt) {
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
        
        if(optSt.encrypt) {
            otpOutFile = fopen(otpOutFileName,"wb");
        }
        
        if(optSt.passWordGiven) {;
            genYaxaKey();
        } else {
            if(freadWErrCheck(yaxaKey,sizeof(*yaxaKey),HMAC_KEY_SIZE,otpInFile) != 0) {
                printSysError(returnVal);
                exit(EXIT_FAILURE);
            }
            if(optSt.encrypt) {
                if(fwriteWErrCheck(yaxaKey,sizeof(*yaxaKey),HMAC_KEY_SIZE,otpOutFile) != 0) {
                    printSysError(returnVal);
                    exit(EXIT_FAILURE);
                }
            }
        }
        
    } else {
        genYaxaKey();
    }
    
    genCtrStart();
    
    genNonce();
    
    genHMACKey();
    
    genPassTag();
    
    if(optSt.decrypt) {
        if (CRYPTO_memcmp(passKeyedHash, passKeyedHashFromFile, sizeof(*passKeyedHashFromFile) * PASS_KEYED_HASH_SIZE) != 0) {
            printf("Wrong password\n");
            strcpy(statusMessage,"Wrong password");
            exit(EXIT_FAILURE);
        }
    }

    if(optSt.encrypt) {
        fileSize = getFileSize(inputFileName);
        
        /*Prepend salt to head of file*/
        if (fwriteWErrCheck(yaxaSalt, sizeof(*yaxaSalt), yaxaSaltSize, outFile) != 0) {
            printSysError(returnVal);
            printError("Could not write salt");
            exit(EXIT_FAILURE);
        }

        /*Write passKeyedHash to head of file next to salt*/
        if (fwriteWErrCheck(passKeyedHash, sizeof(*passKeyedHash), PASS_KEYED_HASH_SIZE, outFile) != 0) {
            printSysError(returnVal);
            printError("Could not write password hash");
            exit(EXIT_FAILURE);
        }

    } else if(optSt.decrypt) {
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

        genHMAC(inFile, (fileSize + (yaxaSaltSize + PASS_KEYED_HASH_SIZE)) - MAC_SIZE);

        /*Verify MAC*/
        if (CRYPTO_memcmp(fileMAC, generatedMAC, sizeof(*generatedMAC) * MAC_SIZE) != 0) {
            printf("Message authentication failed\n");
            strcpy(statusMessage,"Authentication failure");
            exit(EXIT_FAILURE);
        }

        OPENSSL_cleanse(hmacKey, sizeof(*hmacKey) * HMAC_KEY_SIZE);

        /*Reset file posiiton to beginning of cipher-text after the salt and pass tag*/
        fseek(inFile, yaxaSaltSize + PASS_KEYED_HASH_SIZE, SEEK_SET);
    }
    
    if(optSt.encrypt) {
        /*Encrypt file and write it out*/
        if(optSt.oneTimePad) {
            doCrypt(inFile, outFile, fileSize, otpInFile, otpOutFile);
        } else {
            doCrypt(inFile, outFile, fileSize, NULL, NULL);
        }
    } else if (optSt.decrypt) {
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

    if(optSt.encrypt) {
        /*Write the MAC to the end of the file*/
        if (fwriteWErrCheck(generatedMAC, sizeof(*generatedMAC), MAC_SIZE, outFile) != 0) {
            printSysError(returnVal);
            printError("Could not write MAC");
            exit(EXIT_FAILURE);
        }
    }
    
    if(fclose(outFile) != 0) {
        printSysError(errno);
        printError("Could not close file");
        exit(EXIT_FAILURE);
    }
    
    exit(EXIT_SUCCESS);

    return EXIT_SUCCESS;
}
