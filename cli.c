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

    unsigned __int128 fileSize;
    
    counterInt = 0;
    keyInt = 0;

    if (strcmp(argv[1], "-e") == 0) {

        if (argc == 4) {
            userPass = getPass("Enter password to encrypt with: ");

            /*Get the password again to verify it wasn't misspelled*/
            if (strcmp(userPass, getPass("Verify password: ")) != 0) {
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
        if (fwriteWErrCheck(yaxaSalt, sizeof(unsigned char), YAXA_SALT_SIZE, outFile) != 0) {
            printSysError(returnVal);
            exit(EXIT_FAILURE);
        }

        /*Write passKeyedHash to head of file next to salt*/
        if (fwriteWErrCheck(passKeyedHash, sizeof(unsigned char), PASS_KEYED_HASH_SIZE, outFile) != 0) {
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
        if (fwriteWErrCheck(generatedMAC, sizeof(unsigned char), MAC_SIZE, outFile) != 0) {
            printSysError(returnVal);
            exit(EXIT_FAILURE);
        }

        if(fclose(outFile) != 0) {
            printSysError(errno);
            exit(EXIT_FAILURE);
        }

    } else if (strcmp(argv[1], "-d") == 0) {

        if (argc == 4)
            userPass = getPass("Enter password to decrypt with: ");
        else if (argc == 5)
            snprintf(userPass, MAX_PASS_SIZE, "%s", argv[4]);

        /*Read yaxaSalt from head of cipher-text*/
        if (freadWErrCheck(yaxaSalt, sizeof(unsigned char), YAXA_SALT_SIZE, inFile) != 0) {
            printSysError(returnVal);
            exit(EXIT_FAILURE);
        }

        /*Get passKeyedHashFromFile*/
        if (freadWErrCheck(passKeyedHashFromFile, sizeof(unsigned char), PASS_KEYED_HASH_SIZE, inFile) != 0) {
            printSysError(returnVal);
            exit(EXIT_FAILURE);
        }

        genYaxaKey();
        
        genCtrStart();
        
        genHMACKey();
        
        genPassTag();

        if (CRYPTO_memcmp(passKeyedHash, passKeyedHashFromFile, PASS_KEYED_HASH_SIZE) != 0) {
            printf("Wrong password\n");
            exit(EXIT_FAILURE);
        }

        /*Get filesize, discounting the salt and passKeyedHash*/
        fileSize = getFileSize(argv[2]) - (YAXA_SALT_SIZE + PASS_KEYED_HASH_SIZE);

        /*Move file position to the start of the MAC*/
        fseek(inFile, (fileSize + YAXA_SALT_SIZE + PASS_KEYED_HASH_SIZE) - MAC_SIZE, SEEK_SET);

        if (freadWErrCheck(fileMAC, sizeof(unsigned char), MAC_SIZE, inFile) != 0) {
            printSysError(returnVal);
            exit(EXIT_FAILURE);
        }

        /*Reset file position to beginning of file*/
        rewind(inFile);

        genHMAC(inFile, (fileSize + (YAXA_SALT_SIZE + PASS_KEYED_HASH_SIZE)) - MAC_SIZE);

        /*Verify MAC*/
        if (CRYPTO_memcmp(fileMAC, generatedMAC, MAC_SIZE) != 0) {
            printf("Message authentication failed\n");
            exit(EXIT_FAILURE);
        }

        OPENSSL_cleanse(hmacKey, HMAC_KEY_SIZE);

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

char *getPass(const char *prompt)
{
    gotPassFromCmdLine = true;
    size_t len = 0;
    char *pass = NULL;

    size_t nread;

    /* Turn echoing off and fail if we can’t. */
    if (tcgetattr(fileno(stdin), &termisOld) != 0)
        exit(EXIT_FAILURE);
    termiosNew = termisOld;
    termiosNew.c_lflag &= ~ECHO;
    if (tcsetattr(fileno(stdin), TCSAFLUSH, &termiosNew) != 0)
        exit(EXIT_FAILURE);

    /* Read the password. */
    printf("\n%s", prompt);
    nread = getline(&pass, &len, stdin);
    if (nread == -1)
        exit(EXIT_FAILURE);
    else if (nread > MAX_PASS_SIZE) {
        /* Restore terminal. */
        (void)tcsetattr(fileno(stdin), TCSAFLUSH, &termisOld);
        for (int i = 0; i < nread; i++)
            pass[i] = 0;
        free(pass);
        printf("\nPassword was too large\n");
        exit(EXIT_FAILURE);
    } else {
        /*Replace newline with null terminator*/
        pass[nread - 1] = '\0';
    }

    /* Restore terminal. */
    (void)tcsetattr(fileno(stdin), TCSAFLUSH, &termisOld);

    printf("\n");
    return pass;
}

int printSyntax(char *arg)
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
