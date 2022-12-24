/*
  This product includes software developed by the OpenSSL Project
  for use in the OpenSSL Toolkit (http://www.openssl.org/)
*/
#include "headers.h"
#include "crypt.c"
#include "misc.c"
#include "buffers.c"
#include "workthread.c"

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
                snprintf(fileSt.inputFileName, NAME_MAX, "%s", optarg);
            }
        break;
        case 'o':
            if (optarg[0] == '-' && strlen(optarg) == 2) {
                fprintf(stderr, "Option -o requires an argument\n");
                errflg++;
                break;
            } else {
                optSt->outputFileGiven = true;
                snprintf(fileSt.outputFileName, NAME_MAX, "%s", optarg);
            }
        break;
        case 'k':
            if (optarg[0] == '-' && strlen(optarg) == 2) {
                fprintf(stderr, "Option -k requires an argument\n");
                errflg++;
                break;
            } else {
                optSt->keyFileGiven = true;
                snprintf(fileSt.keyFileName, NAME_MAX, "%s", optarg);
                sizesSt.keyFileSize = getFileSize(fileSt.keyFileName);
                sizesSt.keyBufSize = sizesSt.keyFileSize;
                sizesSt.yaxaSaltSize = sizesSt.keyBufSize / YAXA_KEY_CHUNK_SIZE;
            }
        break;
        case 'O':
            if (optarg[0] == '-' && strlen(optarg) == 2) {
                fprintf(stderr, "Option -O requires an argument\n");
                errflg++;
                break;
            } else {
                optSt->oneTimePad = true;
                snprintf(fileSt.otpInFileName, NAME_MAX, "%s", optarg);
                sprintf(fileSt.otpOutFileName,"%s.pad", fileSt.outputFileName);
                
            }
        break;
        case 'p':
            if (optarg[0] == '-' && strlen(optarg) == 2) {
                fprintf(stderr, "Option -p requires an argument\n");
                errflg++;
                break;
            } else {
                optSt->passWordGiven = true;
                snprintf(cryptSt.userPass, MAX_PASS_SIZE, "%s", optarg);
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
                    cryptSt.nFactor = atol(value);

                    int testNum = cryptSt.nFactor;
                    while (testNum > 1) {
                        if (testNum % 2 != 0) {
                            fprintf(stderr, "scrypt's N factor must be a power of 2.");
                            cryptSt.nFactor--;
                            cryptSt.nFactor |= cryptSt.nFactor >> 1;
                            cryptSt.nFactor |= cryptSt.nFactor >> 2;
                            cryptSt.nFactor |= cryptSt.nFactor >> 4;
                            cryptSt.nFactor |= cryptSt.nFactor >> 8;
                            cryptSt.nFactor |= cryptSt.nFactor >> 16;
                            cryptSt.nFactor++;
                            fprintf(stderr, " Rounding it up to %zu\n", cryptSt.nFactor);
                            break;
                        }
                        testNum /= 2;
                    }
                    break;
                case R_FACTOR:
                    cryptSt.rFactor = atol(value);
                    break;
                case P_FACTOR:
                    cryptSt.pFactor = atol(value);
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
                        sizesSt.keyBufSize = atol(value) * sizeof(*cryptSt.yaxaKey) * getBufSizeMultiple(value);
                        sizesSt.yaxaSaltSize = sizesSt.keyBufSize / YAXA_KEY_CHUNK_SIZE;
                    break;
                    case MAC_BUFFER:
                        if (value == NULL) {
                            fprintf(stderr, "Missing value for suboption '%s'\n", token[MAC_BUFFER]);
                            errflg = 1;
                            continue;
                        }
                            
                        optSt->macBufSizeGiven = true;
                        sizesSt.genHmacBufSize = atol(value) * sizeof(uint8_t) * getBufSizeMultiple(value);
                        makeMultipleOf(&sizesSt.genHmacBufSize,sizeof(cryptint_t));
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
                        sizesSt.msgBufSize = (atol(value) * getBufSizeMultiple(value));
                        makeMultipleOf(&sizesSt.msgBufSize,sizeof(cryptint_t));
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
    
    if(!strcmp(fileSt.inputFileName,fileSt.outputFileName)) {
        fprintf(stderr, "Input file and output file are the same\n");
        errflg++;
    }
    
    if (errflg) {
        printSyntax(binName);
        exit(EXIT_FAILURE);
    }
    
    if((optSt->passWordGiven && optSt->keyFileGiven) || (optSt->passWordGiven && optSt->oneTimePad)) {
        sizesSt.yaxaSaltSize = sizesSt.keyBufSize / YAXA_KEY_CHUNK_SIZE;
    } else if (optSt->oneTimePad || optSt->keyFileGiven) {
        sizesSt.yaxaSaltSize = 0;
    }
}

int main(int argc, char *argv[])
{
    if (argc == 1) {
        printSyntax(argv[0]);
        exit(EXIT_FAILURE);
    }
    
    cryptSt.nFactor = DEFAULT_SCRYPT_N;
    cryptSt.pFactor = DEFAULT_SCRYPT_P;
    cryptSt.rFactor = DEFAULT_SCRYPT_R;
    cryptSt.k = 0;
    
    sizesSt.keyBufSize = YAXA_KEYBUF_SIZE;
    sizesSt.genHmacBufSize = 1024 * 1024;
    sizesSt.msgBufSize = 1024 * 1024;
    sizesSt.yaxaSaltSize = YAXA_KEYBUF_SIZE / YAXA_KEY_CHUNK_SIZE;
    
    struct optionsStruct optSt = {0};
    
    parseOptions(argc, argv, &optSt);

    signal(SIGINT, signalHandler);

    atexit(cleanUpBuffers);

    allocateBuffers();

    OpenSSL_add_all_algorithms();
    
    if(optSt.encrypt) {
        workThread('e',optSt);
    } else if(optSt.decrypt) {
        workThread('d',optSt);
    }
    
    wait(NULL);

    return EXIT_SUCCESS;
}
