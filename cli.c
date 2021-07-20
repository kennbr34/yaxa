/*
  This product includes software developed by the OpenSSL Project
  for use in the OpenSSL Toolkit (http://www.openssl.org/)
*/
#include "headers.h"
#include "crypt.c"
#include "misc.c"
#include "buffers.c"

int main(int argc, char *argv[])
{
    if (argc == 1) {
        printSyntax(argv[0]);
        exit(EXIT_FAILURE);
    }

    if (strcmp(argv[1], "-e") != 0 && strcmp(argv[1], "-d") != 0) {
        printSyntax(argv[0]);
        exit(EXIT_FAILURE);
    }

    signal(SIGINT, signalHandler);

    atexit(cleanUpBuffers);

    allocateBuffers();

    OpenSSL_add_all_algorithms();

    FILE *inFile = fopen(argv[2], "rb");
    if (inFile == NULL) {
        printFileError(argv[2], errno);
        exit(EXIT_FAILURE);
    }
    FILE *outFile = fopen(argv[3], "wb+");
    if (outFile == NULL) {
        printFileError(argv[3], errno);
        exit(EXIT_FAILURE);
    }

    cryptint_t fileSize;
    
    counterInt = 0;
    keyInt = 0;

    if (strcmp(argv[1], "-e") == 0) {

        if (argc == 4) {
            getPass("Enter password to encrypt with: ",userPass);

            /*Get the password again to verify it wasn't misspelled*/
            getPass("Verify password: ",userPassToVerify);
            if (strcmp(userPass,userPassToVerify) != 0) {
                printf("\nPasswords do not match.  Nothing done.\n\n");
                exit(EXIT_FAILURE);
            }
        } else if (argc == 5) {
            snprintf(userPass, MAX_PASS_SIZE, "%s", argv[4]);
        }

        genYaxaSalt();

        genYaxaKey();
        
        genCtrStart();
        
        genHMACKey();
        
        genPassTag();

        fileSize = getFileSize(argv[2]);

        /*Prepend salt to head of file*/
        if (fwriteWErrCheck(yaxaSalt, sizeof(*yaxaSalt), YAXA_SALT_SIZE, outFile) != 0) {
            printSysError(returnVal);
            exit(EXIT_FAILURE);
        }

        /*Write passKeyedHash to head of file next to salt*/
        if (fwriteWErrCheck(passKeyedHash, sizeof(*passKeyedHash), PASS_KEYED_HASH_SIZE, outFile) != 0) {
            printSysError(returnVal);
            exit(EXIT_FAILURE);
        }

        /*Encrypt file and write it out*/
        doCrypt(inFile, outFile, fileSize);

        if(fclose(inFile) != 0) {
            printSysError(errno);
            exit(EXIT_FAILURE);
        }

        /*Now get new filesize and reset flie position to beginning*/
        fileSize = ftell(outFile);
        rewind(outFile);

        genHMAC(outFile, fileSize);

        OPENSSL_cleanse(hmacKey, HMAC_KEY_SIZE);

        /*Write the MAC to the end of the file*/
        if (fwriteWErrCheck(generatedMAC, sizeof(*generatedMAC), MAC_SIZE, outFile) != 0) {
            printSysError(returnVal);
            exit(EXIT_FAILURE);
        }

        if(fclose(outFile) != 0) {
            printSysError(errno);
            exit(EXIT_FAILURE);
        }

    } else if (strcmp(argv[1], "-d") == 0) {

        if (argc == 4)
            getPass("Enter password to decrypt with: ",userPass);
        else if (argc == 5)
            snprintf(userPass, MAX_PASS_SIZE, "%s", argv[4]);

        /*Read yaxaSalt from head of cipher-text*/
        if (freadWErrCheck(yaxaSalt, sizeof(*yaxaSalt), YAXA_SALT_SIZE, inFile) != 0) {
            printSysError(returnVal);
            exit(EXIT_FAILURE);
        }

        /*Get passKeyedHashFromFile*/
        if (freadWErrCheck(passKeyedHashFromFile, sizeof(*passKeyedHashFromFile), PASS_KEYED_HASH_SIZE, inFile) != 0) {
            printSysError(returnVal);
            exit(EXIT_FAILURE);
        }

        genYaxaKey();
        
        genCtrStart();
        
        genHMACKey();
        
        genPassTag();

        if (CRYPTO_memcmp(passKeyedHash, passKeyedHashFromFile, sizeof(*passKeyedHashFromFile) * PASS_KEYED_HASH_SIZE) != 0) {
            printf("Wrong password\n");
            exit(EXIT_FAILURE);
        }

        /*Get filesize, discounting the salt and passKeyedHash*/
        fileSize = getFileSize(argv[2]) - (YAXA_SALT_SIZE + PASS_KEYED_HASH_SIZE);

        /*Move file position to the start of the MAC*/
        fseek(inFile, (fileSize + YAXA_SALT_SIZE + PASS_KEYED_HASH_SIZE) - MAC_SIZE, SEEK_SET);

        if (freadWErrCheck(fileMAC, sizeof(*fileMAC), MAC_SIZE, inFile) != 0) {
            printSysError(returnVal);
            exit(EXIT_FAILURE);
        }

        /*Reset file position to beginning of file*/
        rewind(inFile);

        genHMAC(inFile, (fileSize + (YAXA_SALT_SIZE + PASS_KEYED_HASH_SIZE)) - MAC_SIZE);

        /*Verify MAC*/
        if (CRYPTO_memcmp(fileMAC, generatedMAC, sizeof(*generatedMAC) * MAC_SIZE) != 0) {
            printf("Message authentication failed\n");
            exit(EXIT_FAILURE);
        }

        OPENSSL_cleanse(hmacKey, sizeof(*hmacKey) * HMAC_KEY_SIZE);

        /*Reset file posiiton to beginning of cipher-text after the salt and pass tag*/
        fseek(inFile, YAXA_SALT_SIZE + PASS_KEYED_HASH_SIZE, SEEK_SET);

        /*Now decrypt the cipher-text, disocounting the size of the MAC*/
        doCrypt(inFile, outFile, fileSize - MAC_SIZE);

        if(fclose(outFile) != 0) {
            printSysError(errno);
            exit(EXIT_FAILURE);
        }
        if(fclose(inFile) != 0) {
            printSysError(errno);
            exit(EXIT_FAILURE);
        }
    }

    return EXIT_SUCCESS;
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

uint8_t printSyntax(char *arg)
{
    printf("\
\nUse: \
\n\n%s [-e|-d] infile outfile [pass]\
\n-e - encrypt infile to outfile\
\n-d - decrypt infile to outfile\
\n\
",
           arg);
    printf("\nThis product includes software developed by the OpenSSL Project for use in the OpenSSL Toolkit. (http://www.openssl.org/)\n");
    return EXIT_FAILURE;
}
