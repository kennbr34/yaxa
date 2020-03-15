/*
  This product includes software developed by the OpenSSL Project
  for use in the OpenSSL Toolkit (http://www.openssl.org/)
*/
#define _FILE_OFFSET_BITS 64

#include <errno.h>
#include <openssl/err.h>
#include <openssl/hmac.h>
#include <openssl/kdf.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <termios.h>
#include <stdbool.h>

#define printSysError(errCode) \
    { \
        fprintf(stderr, "%s:%s:%d: %s\n", __FILE__, __func__, __LINE__, strerror(errCode)); \
    }

#define printFileError(fileName, errCode) \
    { \
        fprintf(stderr, "%s: %s (Line: %i)\n", fileName, strerror(errCode), __LINE__); \
    }

#define printError(errMsg) \
    { \
        fprintf(stderr, "%s:%s:%d: %s\n", __FILE__, __func__, __LINE__, errMsg); \
    }

#define MAX_PASS_SIZE 512

#define YAXA_KEYBUF_SIZE (1024 * 1024) * 32

#define YAXA_KEY_LENGTH YAXA_KEYBUF_SIZE - 1

#define YAXA_KEY_CHUNK_SIZE SHA512_DIGEST_LENGTH

#define YAXA_SALT_SIZE YAXA_KEYBUF_SIZE / YAXA_KEY_CHUNK_SIZE

#define DEFAULT_SCRYPT_N 1048576

#define DEFAULT_SCRYPT_R 8

#define DEFAULT_SCRYPT_P 1

#define PASS_KEYED_HASH_SIZE SHA512_DIGEST_LENGTH

#define HMAC_KEY_SIZE SHA512_DIGEST_LENGTH

#define MAC_SIZE SHA512_DIGEST_LENGTH

struct termios termisOld, termiosNew;

union counterUnion {
    uint64_t counterInt;
    uint8_t counterBytes[8];
};

union counterUnion counter;

union keyUnion {
    uint64_t keyInt;
    uint8_t keyBytes[8];
};

union keyUnion key;

unsigned char yaxaKeyArray[YAXA_SALT_SIZE][YAXA_KEY_CHUNK_SIZE];
unsigned char *yaxaKeyChunk = NULL;
unsigned char *yaxaKey = NULL;
unsigned char *yaxaSalt = NULL;

char *userPass = NULL;
unsigned char passKeyedHash[PASS_KEYED_HASH_SIZE], passKeyedHashFromFile[PASS_KEYED_HASH_SIZE];

unsigned char generatedMAC[MAC_SIZE];
unsigned char fileMAC[MAC_SIZE];
unsigned char *hmacKey = NULL;
unsigned int *HMACLengthPtr = NULL;

/*Iterator for indexing yaxaKey array*/
int k = 0;

int returnVal;
int gotPassFromCmdLine = false;

/*Prototype functions*/
void allocateBuffers();                                                  /*Allocates all the buffers used*/
void cleanUpBuffers();                                                   /*Writes zeroes to all the buffers when done*/
void doCrypt(FILE *inFile, FILE *outFile, uint64_t fileSize);            /*Encryption/Decryption routines*/
int freadWErrCheck(void *ptr, size_t size, size_t nmemb, FILE *stream);  /*fread() error checking wrapper*/
int fwriteWErrCheck(void *ptr, size_t size, size_t nmemb, FILE *stream); /*fwrite() error checking wrapper*/
void genHMAC(FILE *dataFile, uint64_t fileSize);                         /*Generate HMAC*/
void genHMACKey();                                                       /*Generate key for HMAC*/
void genPassTag();                                                       /*Generate passKeyedHash*/
void genYaxaSalt();                                                      /*Generates YAXA salt*/
void genYaxaKey();                                                       /*YAXA key deriving function*/
uint64_t getFileSize(const char *filename);                              /*Returns filesize using stat()*/
char *getPass(const char *prompt);                                       /*Function to retrive passwords with no echo*/
int printSyntax(char *arg);                                              /*Print program usage and help*/
void signalHandler(int signum);                                          /*Signal handler for Ctrl+C*/
uint64_t yaxa(uint64_t messageInt);                                      /*YAXA encryption/decryption function*/

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

    uint64_t fileSize;
    
    counter.counterInt = 0;
    key.keyInt = 0;

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

void allocateBuffers()
{
    yaxaKey = calloc(YAXA_KEYBUF_SIZE, sizeof(unsigned char));
    if (yaxaKey == NULL) {
        printSysError(errno);
        exit(EXIT_FAILURE);
    }

    userPass = calloc(YAXA_KEY_LENGTH, sizeof(unsigned char));
    if (userPass == NULL) {
        printSysError(errno);
        exit(EXIT_FAILURE);
    }

    yaxaKeyChunk = calloc(YAXA_KEY_CHUNK_SIZE, sizeof(unsigned char));
    if (yaxaKeyChunk == NULL) {
        printSysError(errno);
        exit(EXIT_FAILURE);
    }

    yaxaSalt = calloc(YAXA_SALT_SIZE, sizeof(unsigned char));
    if (yaxaSalt == NULL) {
        printSysError(errno);
        exit(EXIT_FAILURE);
    }

    hmacKey = calloc(HMAC_KEY_SIZE, sizeof(unsigned char));
    if (hmacKey == NULL) {
        printSysError(errno);
        exit(EXIT_FAILURE);
    }
}

void cleanUpBuffers()
{
    OPENSSL_cleanse(yaxaKey, YAXA_KEYBUF_SIZE);
    free(yaxaKey);
    OPENSSL_cleanse(hmacKey, HMAC_KEY_SIZE);
    free(hmacKey);
    OPENSSL_cleanse(yaxaKeyChunk, YAXA_KEY_CHUNK_SIZE);
    free(yaxaKeyChunk);
    OPENSSL_cleanse(userPass, strlen(userPass));
    free(userPass);

    OPENSSL_cleanse(yaxaKeyArray, YAXA_KEYBUF_SIZE);

    free(yaxaSalt);
}

void doCrypt(FILE *inFile, FILE *outFile, uint64_t fileSize)
{
    uint64_t outInt, inInt;

    for (uint64_t i = 0; i < (fileSize); i += sizeof(uint64_t)) {

        if (freadWErrCheck(&inInt, sizeof(uint64_t), 1, inFile) != 0) {
            printSysError(returnVal);
            exit(EXIT_FAILURE);
        }

        outInt = yaxa(inInt);

        /*Write remainder of fileSize % sizeof(uint64_t) on the laster iteration if fileSize isn't a multiple of uint64_t*/
        if ((i + sizeof(uint64_t)) > fileSize) {
            if (fwriteWErrCheck(&outInt, sizeof(uint8_t), fileSize % sizeof(uint64_t), outFile) != 0) {
                printSysError(returnVal);
                exit(EXIT_FAILURE);
            }
        } else {
            if (fwriteWErrCheck(&outInt, sizeof(uint64_t), 1, outFile) != 0) {
                printSysError(returnVal);
                exit(EXIT_FAILURE);
            }
        }
    }
}

int freadWErrCheck(void *ptr, size_t size, size_t nmemb, FILE *stream)
{
    if (fread(ptr, size, nmemb, stream) != nmemb / size) {
        if (feof(stream)) {
            returnVal = EBADMSG;
            return EBADMSG;
        } else if (ferror(stream)) {
            returnVal = errno;
            return errno;
        }
    }

    return 0;
}

int fwriteWErrCheck(void *ptr, size_t size, size_t nmemb, FILE *stream)
{
    if (fwrite(ptr, size, nmemb, stream) != nmemb / size) {
        if (feof(stream)) {
            returnVal = EBADMSG;
            return EBADMSG;
        } else if (ferror(stream)) {
            returnVal = errno;
            return errno;
        }
    }

    return 0;
}

void genHMAC(FILE *dataFile, uint64_t fileSize)
{
    unsigned char inByte;

    /*Initiate HMAC*/
    HMAC_CTX *ctx = HMAC_CTX_new();
    HMAC_Init_ex(ctx, hmacKey, HMAC_KEY_SIZE, EVP_sha512(), NULL);

    /*HMAC the cipher-text, passtag and salt*/
    uint64_t i; /*Declare i outside of for loop so it can be used in HMAC_Final as the size*/
    for (i = 0; i < fileSize; i++) {
        if (freadWErrCheck(&inByte, sizeof(unsigned char), 1, dataFile) != 0) {
            printSysError(returnVal);
            exit(EXIT_FAILURE);
        }
        HMAC_Update(ctx, (unsigned char *)&inByte, sizeof(unsigned char));
    }
    HMAC_Final(ctx, generatedMAC, (unsigned int *)&i);
    HMAC_CTX_free(ctx);
}

void genHMACKey()
{

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
    
    if (HMAC(EVP_sha512(), hmacKey, HMAC_KEY_SIZE, userPass, strlen(userPass), passKeyedHash, HMACLengthPtr) == NULL) {
        printError("Password keyed-hash failure");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
}

void genYaxaKey()
{
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
    }

    memcpy(yaxaKey, yaxaKeyArray, YAXA_KEYBUF_SIZE);

    OPENSSL_cleanse(yaxaKeyArray, YAXA_KEYBUF_SIZE);
    OPENSSL_cleanse(yaxaKeyChunk, YAXA_KEY_CHUNK_SIZE);
}

void genYaxaSalt()
{

    unsigned char b; /*Random byte*/

    for (int i = 0; i < YAXA_SALT_SIZE; i++) {
        if (!RAND_bytes(&b, 1)) {
            printError("Aborting: CSPRNG bytes may not be unpredictable");
            exit(EXIT_FAILURE);
        }
        yaxaSalt[i] = b;
    }
}

uint64_t getFileSize(const char *filename)
{
    struct stat st;
    stat(filename, &st);
    return st.st_size;
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

void signalHandler(int signum)
{
    printf("\nCaught signal %d\nCleaning up buffers...\n", signum);

    /* Restore terminal. */
    if (gotPassFromCmdLine == false) {
        tcgetattr(fileno(stdin), &termisOld);
        termiosNew = termisOld;
        termiosNew.c_lflag &= ~ECHO;
    }
    (void)tcsetattr(fileno(stdin), TCSAFLUSH, &termisOld);

    exit(EXIT_FAILURE);
}

uint64_t yaxa(uint64_t messageInt)
{
    /*Fill up 64-bit key integer with 8 8-bit bytes from yaxaKey*/
    for (uint8_t i = 0; i < sizeof(uint64_t); i++)
        key.keyBytes[i] = yaxaKey[k++];

    /*Reset to the start of the key if reached the end*/
    if (k + 1 >= YAXA_KEY_LENGTH)
        k = 0;

    /*Ctr ^ K ^ M*/
    /*All values are 64-bit*/
    /*Increment counter variable too*/
    return counter.counterInt++ ^ key.keyInt ^ messageInt;
}
