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
#include <gtk/gtk.h>
#include <sys/mman.h>

#define printSysError(errCode) \
    { \
        fprintf(stderr, "%s:%s:%d: %s\n", __FILE__, __func__, __LINE__, strerror(errCode)); \
        snprintf(statusMessage,256, "%s: %s:%s:%d", strerror(errCode), __FILE__, __func__, __LINE__); \
    }

#define printFileError(fileName, errCode) \
    { \
        fprintf(stderr, "%s: %s (Line: %i)\n", strerror(errCode), fileName, __LINE__); \
        snprintf(statusMessage,256, "%s: %s (Line: %i)", strerror(errCode), fileName, __LINE__); \
    }

#define printError(errMsg) \
    { \
        fprintf(stderr, "%s:%s:%d: %s\n", __FILE__, __func__, __LINE__, errMsg); \
        snprintf(statusMessage, 256, " %s: %s:%s:%d", errMsg, __FILE__, __func__, __LINE__); \
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
    unsigned __int128 counterInt;
    uint8_t counterBytes[16];
};

union counterUnion counter;

union keyUnion {
    unsigned __int128 keyInt;
    uint8_t keyBytes[16];
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
int k;

int returnVal;
int gotPassFromCmdLine = false;

/*Prototype functions*/
void allocateBuffers();                                                  /*Allocates all the buffers used*/
void cleanUpBuffers();                                                   /*Writes zeroes to all the buffers when done*/
void doCrypt(FILE *inFile, FILE *outFile, unsigned __int128 fileSize);   /*Encryption/Decryption routines*/
int freadWErrCheck(void *ptr, size_t size, size_t nmemb, FILE *stream);  /*fread() error checking wrapper*/
int fwriteWErrCheck(void *ptr, size_t size, size_t nmemb, FILE *stream); /*fwrite() error checking wrapper*/
void genHMAC(FILE *dataFile, unsigned __int128 fileSize);                /*Generate HMAC*/
void genHMACKey();                                                       /*Generate key for HMAC*/
void genPassTag();                                                       /*Generate passKeyedHash*/
void genYaxaSalt();                                                      /*Generates YAXA salt*/
void genYaxaKey();                                                       /*YAXA key deriving function*/
void genCtrStart();														 /*Derive starting point for Ctr from key*/
unsigned __int128 getFileSize(const char *filename);                     /*Returns filesize using stat()*/
void signalHandler(int signum);                                          /*Signal handler for Ctrl+C*/
unsigned __int128 yaxa(unsigned __int128 messageInt);                    /*YAXA encryption/decryption function*/
void on_encryptButton_clicked(GtkWidget *wid, gpointer ptr);
void on_decryptButton_clicked(GtkWidget *wid, gpointer ptr);
static void inputFileSelect (GtkWidget *wid, gpointer ptr);
static void outputFileSelect (GtkWidget *wid, gpointer ptr);
void passVisibilityToggle (GtkWidget *wid, gpointer ptr);
static gboolean updateStatus(gpointer user_data);
static gboolean updateProgress(gpointer user_data);
static gboolean updateOverallProgress(gpointer user_data);
int workThread();

GtkWidget *inputFileNameBox;
GtkWidget *outputFileNameBox;
GtkWidget *passwordBox;
GtkWidget *passwordVerificationBox;

const char *inputFilePath;
const char *outputFilePath;
const char *passWord;
const char *verificationPass;

char action = 0;

GtkWidget *statusBar;
guint statusContextID;
char *statusMessage;

GtkWidget *overallProgressBar;
double *overallProgressFraction;

GtkWidget *progressBar;
double *progressFraction;

int main(int argc, char *argv[])
{
    /*These must be mapped as shared memory for the worker thread to manipulate their values in the main thread*/
    statusMessage = mmap(NULL, 256, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    progressFraction = mmap(NULL, sizeof(double), PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    overallProgressFraction = mmap(NULL, sizeof(double), PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    
    signal(SIGINT, signalHandler);

    atexit(cleanUpBuffers);

    allocateBuffers();

    OpenSSL_add_all_algorithms();
    
    gtk_init (&argc, &argv);
    
    GtkWidget *win = gtk_window_new (GTK_WINDOW_TOPLEVEL);
    
    gtk_window_set_title(GTK_WINDOW (win), "YAXA File Encryption Utility");
    
    GtkWidget *inputFileLabel = gtk_label_new ("Input File Path");
    inputFileNameBox = gtk_entry_new ();
    gtk_widget_set_tooltip_text (inputFileNameBox, "Enter the full path to the file you want to encrypt/decrypt here");
    GtkWidget *inputFileButton = gtk_button_new_with_label ("Select File");
    gtk_widget_set_tooltip_text (inputFileButton, "Select the file you want to encrypt/decrypt to fill in this path");
    g_signal_connect (inputFileButton, "clicked", G_CALLBACK (inputFileSelect), win);
    
    GtkWidget *outputFileLabel = gtk_label_new ("Output File Path");
    outputFileNameBox = gtk_entry_new ();
    gtk_widget_set_tooltip_text (outputFileNameBox, "Enter the full path to where you want to save the result of encryption/decryption");
    GtkWidget *outputFileButton = gtk_button_new_with_label ("Select File");
    gtk_widget_set_tooltip_text (outputFileButton, "Select where you want to save the result of encryption/decryption to fill in this path");
    g_signal_connect (outputFileButton, "clicked", G_CALLBACK (outputFileSelect), win);
    
    GtkWidget *passwordLabel = gtk_label_new ("Password");
    passwordBox = gtk_entry_new ();
    gtk_widget_set_tooltip_text (passwordBox, "Password to derive key from");
    gtk_entry_set_invisible_char(GTK_ENTRY (passwordBox),'*');
    gtk_entry_set_visibility(GTK_ENTRY (passwordBox), FALSE);
    
    GtkWidget *verificationLabel = gtk_label_new ("Verify Password");
    passwordVerificationBox = gtk_entry_new ();
    gtk_widget_set_tooltip_text (passwordVerificationBox, "Note: Not needed for decryption");
    gtk_entry_set_invisible_char(GTK_ENTRY (passwordVerificationBox),'*');
    gtk_entry_set_visibility(GTK_ENTRY (passwordVerificationBox), FALSE);
    
    GtkWidget *visibilityButton = gtk_check_button_new_with_label ("Show Password");
    gtk_widget_set_tooltip_text (visibilityButton, "Hint: Use this to avoid typos");
    gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON (visibilityButton), FALSE);
    g_signal_connect (visibilityButton, "toggled", G_CALLBACK (passVisibilityToggle),NULL);
    
    GtkWidget *encryptButton = gtk_button_new_with_label ("Encrypt");
    g_signal_connect (encryptButton, "clicked", G_CALLBACK (on_encryptButton_clicked), NULL);
        
    GtkWidget *decryptButton = gtk_button_new_with_label ("Decrypt");
    g_signal_connect (decryptButton, "clicked", G_CALLBACK (on_decryptButton_clicked), NULL);
    
    progressBar = gtk_progress_bar_new ();
    gtk_progress_bar_set_text (GTK_PROGRESS_BAR (progressBar), "Step Progress");
    gtk_progress_bar_set_show_text (GTK_PROGRESS_BAR (progressBar), TRUE);
    *progressFraction = 0.0;
    g_timeout_add (50, updateProgress, NULL);
    
    overallProgressBar = gtk_progress_bar_new ();
    gtk_progress_bar_set_text (GTK_PROGRESS_BAR (overallProgressBar), "Overall Progress");
    gtk_progress_bar_set_show_text (GTK_PROGRESS_BAR (overallProgressBar), TRUE);
    *overallProgressFraction = 0.0;
    g_timeout_add (50, updateOverallProgress, NULL);
    
    statusBar = gtk_statusbar_new ();
    gtk_widget_set_tooltip_text (statusBar, "Program will show status updates here");
    strcpy(statusMessage,"Ready");
    g_timeout_add (50, updateStatus, statusMessage);
    
    GtkWidget *grid = gtk_grid_new();
    gtk_widget_set_hexpand (inputFileLabel, TRUE);
    gtk_grid_attach (GTK_GRID (grid), inputFileLabel, 0, 0, 1, 1);
    gtk_grid_attach (GTK_GRID (grid), inputFileNameBox, 0, 2, 1, 1);
    gtk_grid_attach (GTK_GRID (grid), inputFileButton, 1, 2, 1, 1);
    gtk_grid_attach (GTK_GRID (grid), outputFileLabel, 0, 4, 1, 1);
    gtk_grid_attach (GTK_GRID (grid), outputFileNameBox, 0, 5, 1, 1);
    gtk_grid_attach (GTK_GRID (grid), outputFileButton, 1, 5, 1, 1);
    gtk_grid_attach (GTK_GRID (grid), passwordLabel, 0, 7, 1, 1);
    gtk_grid_attach (GTK_GRID (grid), passwordBox, 0, 8, 1, 1);
    gtk_grid_attach (GTK_GRID (grid), verificationLabel, 0, 9, 1, 1);
    gtk_grid_attach (GTK_GRID (grid), passwordVerificationBox, 0, 10, 1, 1);
    gtk_grid_attach (GTK_GRID (grid), visibilityButton, 1, 8, 1, 1);
    gtk_grid_attach (GTK_GRID (grid), encryptButton, 0, 12, 2, 1);
    gtk_grid_attach (GTK_GRID (grid), decryptButton, 0, 13, 2, 1);
    gtk_grid_attach (GTK_GRID (grid), progressBar, 0, 14, 2, 1);
    gtk_grid_attach (GTK_GRID (grid), overallProgressBar, 0, 15, 2, 1);
    gtk_grid_attach (GTK_GRID (grid), statusBar, 0, 16, 2, 1);
    
    
    gtk_container_add (GTK_CONTAINER (win), grid);
    
    g_signal_connect (win, "delete_event", G_CALLBACK (gtk_main_quit), NULL);
    
    gtk_widget_show_all (win);
    gtk_main ();

    exit(EXIT_SUCCESS);
}

int workThread()
{
    pid_t p = fork();
    if(p) return 0;
    
    if(!strlen(userPass)) {
        strcpy(statusMessage,"No password entered");
        exit(EXIT_FAILURE);
    }
    
    if(!strlen(inputFilePath)) {
        strcpy(statusMessage, "No input file specified");
        exit(EXIT_FAILURE);
    }
    
    if(!strlen(outputFilePath)) {
        strcpy(statusMessage, "No output file specified");
        exit(EXIT_FAILURE);
    }
    
    FILE *inFile = fopen(inputFilePath, "rb");
    if (inFile == NULL) {
        printFileError(inputFilePath, errno);
        exit(EXIT_FAILURE);
    }
    FILE *outFile = fopen(outputFilePath, "wb+");
    if (outFile == NULL) {
        printFileError(outputFilePath, errno);
        exit(EXIT_FAILURE);
    }

    unsigned __int128 fileSize;
    
    counter.counterInt = 0;
    key.keyInt = 0;
    k = 0;

    if (action == 'e') {

        strcpy(statusMessage,"Generating salt...");
        *overallProgressFraction = .1;
        genYaxaSalt();

        strcpy(statusMessage,"Generating enecryption key...");
        *overallProgressFraction = .2;
        genYaxaKey();
        
        strcpy(statusMessage,"Generating counter start...");
        genCtrStart();
        
        strcpy(statusMessage,"Generation auth key...");
        *overallProgressFraction = .3;
        genHMACKey();
        
        strcpy(statusMessage,"Password keyed-hash...");
        *overallProgressFraction = .4;
        genPassTag();

        fileSize = getFileSize(inputFilePath);
        
        strcpy(statusMessage,"Writing salt...");
        *overallProgressFraction = .5;
        /*Prepend salt to head of file*/
        if (fwriteWErrCheck(yaxaSalt, sizeof(*yaxaSalt), YAXA_SALT_SIZE, outFile) != 0) {
            printSysError(returnVal);
            printError("Could not write salt");
            exit(EXIT_FAILURE);
        }

        strcpy(statusMessage,"Writing password keyed-hash...");
        *overallProgressFraction = .6;
        /*Write passKeyedHash to head of file next to salt*/
        if (fwriteWErrCheck(passKeyedHash, sizeof(*passKeyedHash), PASS_KEYED_HASH_SIZE, outFile) != 0) {
            printSysError(returnVal);
            printError("Could not write password hash");
            exit(EXIT_FAILURE);
        }

        strcpy(statusMessage,"Encrypting...");
        *overallProgressFraction = .7;
        
        /*Encrypt file and write it out*/
        doCrypt(inFile, outFile, fileSize);

        if(fclose(inFile) != 0) {
            printSysError(errno);
            printError("Error closing file");
            exit(EXIT_FAILURE);
        }

        /*Now get new filesize and reset flie position to beginning*/
        fileSize = ftell(outFile);
        rewind(outFile);
        
        strcpy(statusMessage,"Generating MAC...");
        *overallProgressFraction = .8;
        
        genHMAC(outFile, fileSize);

        OPENSSL_cleanse(hmacKey, HMAC_KEY_SIZE);

        /*Write the MAC to the end of the file*/
        if (fwriteWErrCheck(generatedMAC, sizeof(*generatedMAC), MAC_SIZE, outFile) != 0) {
            printSysError(returnVal);
            printError("Could not write MAC");
            exit(EXIT_FAILURE);
        }

        strcpy(statusMessage,"Saving file...");
        *overallProgressFraction = .9;

        if(fclose(outFile) != 0) {
            printSysError(errno);
            printError("Could not close file");
            exit(EXIT_FAILURE);
        }
        
        strcpy(statusMessage,"File encrypted");
        *overallProgressFraction = 1;
        
        exit(EXIT_SUCCESS);

    } else if (action == 'd') {

        strcpy(statusMessage,"Reading salt...");
        *overallProgressFraction = .1;
        /*Read yaxaSalt from head of cipher-text*/
        if (freadWErrCheck(yaxaSalt, sizeof(*yaxaSalt), YAXA_SALT_SIZE, inFile) != 0) {
            printSysError(returnVal);
            printError("Could not read salt");
            exit(EXIT_FAILURE);
        }

        strcpy(statusMessage,"Reading pass keyed-hash...");
        *overallProgressFraction = .2;
        /*Get passKeyedHashFromFile*/
        if (freadWErrCheck(passKeyedHashFromFile, sizeof(*passKeyedHashFromFile), PASS_KEYED_HASH_SIZE, inFile) != 0) {
            printSysError(returnVal);
            printError("Could not read password hash");
            exit(EXIT_FAILURE);
        }

        strcpy(statusMessage,"Generating decryption key...");
        *overallProgressFraction = .3;
        genYaxaKey();
        
        strcpy(statusMessage,"Generating counter start...");
        genCtrStart();
        
        strcpy(statusMessage,"Generating auth key...");
        *overallProgressFraction = .4;
        genHMACKey();
        
        strcpy(statusMessage,"Generation password keyed-hash...");
        *overallProgressFraction = .5;
        genPassTag();

        strcpy(statusMessage,"Verifying password...");
        *overallProgressFraction = .6;
        if (CRYPTO_memcmp(passKeyedHash, passKeyedHashFromFile, PASS_KEYED_HASH_SIZE) != 0) {
            printf("Wrong password\n");
            strcpy(statusMessage,"Wrong password");
            exit(EXIT_FAILURE);
        }

        /*Get filesize, discounting the salt and passKeyedHash*/
        fileSize = getFileSize(inputFilePath) - (YAXA_SALT_SIZE + PASS_KEYED_HASH_SIZE);

        /*Move file position to the start of the MAC*/
        fseek(inFile, (fileSize + YAXA_SALT_SIZE + PASS_KEYED_HASH_SIZE) - MAC_SIZE, SEEK_SET);

        if (freadWErrCheck(fileMAC, sizeof(*fileMAC), MAC_SIZE, inFile) != 0) {
            printSysError(returnVal);
            printError("Could not read MAC");
            exit(EXIT_FAILURE);
        }

        /*Reset file position to beginning of file*/
        rewind(inFile);

        strcpy(statusMessage,"Authenticating data...");
        *overallProgressFraction = .7;
        genHMAC(inFile, (fileSize + (YAXA_SALT_SIZE + PASS_KEYED_HASH_SIZE)) - MAC_SIZE);

        /*Verify MAC*/
        if (CRYPTO_memcmp(fileMAC, generatedMAC, MAC_SIZE) != 0) {
            printf("Message authentication failed\n");
            strcpy(statusMessage,"Authentication failure");
            exit(EXIT_FAILURE);
        }

        OPENSSL_cleanse(hmacKey, HMAC_KEY_SIZE);

        /*Reset file posiiton to beginning of cipher-text after the salt and pass tag*/
        fseek(inFile, YAXA_SALT_SIZE + PASS_KEYED_HASH_SIZE, SEEK_SET);
        
        strcpy(statusMessage,"Decrypting...");
        *overallProgressFraction = .8;

        /*Now decrypt the cipher-text, disocounting the size of the MAC*/
        doCrypt(inFile, outFile, fileSize - MAC_SIZE);

        strcpy(statusMessage,"Saving file...");
        *overallProgressFraction = .9;
        
        if(fclose(outFile) != 0) {
            printSysError(errno);
            printError("Could not close file");
            exit(EXIT_FAILURE);
        }
        if(fclose(inFile) != 0) {
            printSysError(errno);
            printError("Could not close file");
            exit(EXIT_FAILURE);
        }
        
        strcpy(statusMessage, "File decrypted");
        *overallProgressFraction = 1;
        
        exit(EXIT_SUCCESS);
    }
}

void allocateBuffers()
{
    yaxaKey = calloc(YAXA_KEYBUF_SIZE, sizeof(*yaxaKey));
    if (yaxaKey == NULL) {
        printSysError(errno);
        printError("Could not allocate yaxaKey buffer");
        exit(EXIT_FAILURE);
    }

    userPass = calloc(YAXA_KEY_LENGTH, sizeof(*userPass));
    if (userPass == NULL) {
        printSysError(errno);
        printError("Could not allocate userPass buffer");
        exit(EXIT_FAILURE);
    }

    yaxaKeyChunk = calloc(YAXA_KEY_CHUNK_SIZE, sizeof(*yaxaKeyChunk));
    if (yaxaKeyChunk == NULL) {
        printSysError(errno);
        printError("Could not allocate yaxaKeyChunk buffer");
        exit(EXIT_FAILURE);
    }

    yaxaSalt = calloc(YAXA_SALT_SIZE, sizeof(*yaxaSalt));
    if (yaxaSalt == NULL) {
        printSysError(errno);
        printError("Could not allocate yaxaSalt buffer");
        exit(EXIT_FAILURE);
    }

    hmacKey = calloc(HMAC_KEY_SIZE, sizeof(*hmacKey));
    if (hmacKey == NULL) {
        printSysError(errno);
        printError("Could not allocate hmacKey buffer");
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

void doCrypt(FILE *inFile, FILE *outFile, unsigned __int128 fileSize)
{
    unsigned __int128 outInt, inInt;
    *progressFraction = 0.0;

    for (unsigned __int128 i = 0; i < (fileSize); i += sizeof(i)) {

        if (freadWErrCheck(&inInt, sizeof(inInt), 1, inFile) != 0) {
            printSysError(returnVal);
            printError("Could not read file for encryption/decryption");
            exit(EXIT_FAILURE);
        }

        outInt = yaxa(inInt);

        /*Write remainder of fileSize % sizeof(outInt) on the last iteration if fileSize isn't a multiple of unsigned __int128*/
        if ((i + sizeof(i)) > fileSize) {
            if (fwriteWErrCheck(&outInt, 1, fileSize % sizeof(outInt), outFile) != 0) {
                printSysError(returnVal);
                printError("Could not write file for encryption/decryption");
                exit(EXIT_FAILURE);
            }
        } else {
            if (fwriteWErrCheck(&outInt, sizeof(outInt), 1, outFile) != 0) {
                printSysError(returnVal);
                printError("Could not write file for encryption/decryption");
                exit(EXIT_FAILURE);
            }
        }
        *progressFraction = (double)i / (double)fileSize;
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

void genHMAC(FILE *dataFile, unsigned __int128 fileSize)
{
    unsigned char inByte;
    *progressFraction = 0.0;

    /*Initiate HMAC*/
    HMAC_CTX *ctx = HMAC_CTX_new();
    HMAC_Init_ex(ctx, hmacKey, HMAC_KEY_SIZE, EVP_sha512(), NULL);

    /*HMAC the cipher-text, passtag and salt*/
    unsigned __int128 i; /*Declare i outside of for loop so it can be used in HMAC_Final as the size*/
    for (i = 0; i < fileSize; i++) {
        if (freadWErrCheck(&inByte, sizeof(unsigned char), 1, dataFile) != 0) {
            printSysError(returnVal);
            printError("Could not generate HMAC");
            exit(EXIT_FAILURE);
        }
        HMAC_Update(ctx, (unsigned char *)&inByte, sizeof(inByte));
        *progressFraction = (double)i/(double)fileSize;
    }
    HMAC_Final(ctx, generatedMAC, (unsigned int *)&i);
    HMAC_CTX_free(ctx);
}

void genHMACKey()
{

    strcpy(statusMessage,"Deriving auth key...");

    EVP_PKEY_CTX *pctx;
    size_t outlen = sizeof(*hmacKey) * HMAC_KEY_SIZE;
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
    *progressFraction = 0;
    if (HMAC(EVP_sha512(), hmacKey, HMAC_KEY_SIZE, (unsigned char *)userPass, strlen(userPass), passKeyedHash, HMACLengthPtr) == NULL) {
        printError("Password keyed-hash failure");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    *progressFraction = 1;
}

void genYaxaKey()
{
    *progressFraction = 0;
    double keyChunkFloat = YAXA_KEY_CHUNK_SIZE;
    double keyBufFloat = YAXA_KEYBUF_SIZE;
    
    /*Derive a 64-byte key to expand*/
    EVP_PKEY_CTX *pctx;

    size_t outlen = sizeof(*yaxaKeyChunk) * YAXA_KEY_CHUNK_SIZE;
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
    
    *progressFraction = keyChunkFloat / keyBufFloat;

    /*Expand that 64-byte key into YAXA_KEYBUF_SIZE key*/
    for (int i = 1; i < YAXA_SALT_SIZE; i++) {
                
        EVP_PKEY_CTX *pctx;
        size_t outlen = sizeof(*yaxaKeyChunk) * YAXA_KEY_CHUNK_SIZE;
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
        
        *progressFraction = ((double)i * keyChunkFloat) / keyBufFloat;
    }

    memcpy(yaxaKey, yaxaKeyArray, YAXA_KEYBUF_SIZE);

    OPENSSL_cleanse(yaxaKeyArray, YAXA_KEYBUF_SIZE);
    OPENSSL_cleanse(yaxaKeyChunk, YAXA_KEY_CHUNK_SIZE);
}

void genCtrStart()
{	
	/*Use these bytes to initialize counter.counterInt*/
	uint8_t initBytes[sizeof(counter.counterInt)];
	
	/*Use HKDF to derive bytes for initBytes based on yaxaKey*/
	EVP_PKEY_CTX *pctx;
	size_t outlen = sizeof(initBytes);
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
	if (EVP_PKEY_derive(pctx, initBytes, &outlen) <= 0) {
		printError("HKDF failed\n");
		ERR_print_errors_fp(stderr);
		exit(EXIT_FAILURE);
	}
	
	EVP_PKEY_CTX_free(pctx);
		
	//The following construction uses the quotient of the first byte of initBytes and the size of counter.counterInt
	//to determine how many bytes of initBytes to fill into counter.counterInt. This way counter.counterInt will be
	//intialized to a number within a wider range of 2^128. If all bytes of initBytes were assigned to the full
	//counter.counterBytes array then the counter.counterInt bitspace would be mostly full and never produce numbers
	//from the lower range of 2^128. The loop must make 16 iterations every time, and use the ternary condition to
	//assing bytes from initBytes or zero to counter.counterBytes[i]; in this way the loop and assignments will be
	//in constant time.

	for (uint8_t i = 0; i < sizeof(counter.counterInt); i++) {
        counter.counterBytes[i] = initBytes[0] / sizeof(counter.counterInt) >= i ? initBytes[i] : 0;
    }
}

void genYaxaSalt()
{
    unsigned char b; /*Random byte*/
    double saltSizeFloat = YAXA_SALT_SIZE;
    *progressFraction = 0;

    for (int i = 0; i < YAXA_SALT_SIZE; i++) {
        if (!RAND_bytes(&b, 1)) {
            printError("Aborting: CSPRNG bytes may not be unpredictable");
            exit(EXIT_FAILURE);
        }
        yaxaSalt[i] = b;
        *progressFraction = (double)i/saltSizeFloat;
    }
}

unsigned __int128 getFileSize(const char *filename)
{
    struct stat st;
    stat(filename, &st);
    return st.st_size;
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

unsigned __int128 yaxa(unsigned __int128 messageInt)
{
    /*Fill up 128-bit key integer with 16 8-bit bytes from yaxaKey*/
    for (uint8_t i = 0; i < sizeof(key.keyInt); i++)
        key.keyBytes[i] = yaxaKey[k++];

    /*Reset to the start of the key if reached the end*/
    if (k + 1 >= YAXA_KEY_LENGTH)
        k = 0;

    /*Ctr ^ K ^ M*/
    /*All values are 128-bit*/
    /*Increment counter variable too*/
    return counter.counterInt++ ^ key.keyInt ^ messageInt;
}

static gboolean updateStatus(gpointer user_data)
{
    statusContextID = gtk_statusbar_get_context_id (GTK_STATUSBAR (statusBar), "Statusbar");
    gtk_statusbar_push (GTK_STATUSBAR (statusBar), GPOINTER_TO_INT (statusContextID), statusMessage);
}

static gboolean updateProgress(gpointer user_data)
{
    gtk_progress_bar_set_fraction (GTK_PROGRESS_BAR (progressBar), *progressFraction);
    if(*progressFraction > 1)
        *progressFraction = 0.0;
}

static gboolean updateOverallProgress(gpointer user_data)
{
    gtk_progress_bar_set_fraction (GTK_PROGRESS_BAR (overallProgressBar), *overallProgressFraction);
    if(*overallProgressFraction > 1)
        *overallProgressFraction = 0.0;
}
void on_encryptButton_clicked(GtkWidget *wid, gpointer ptr)
{
    gboolean passwordsMatch = FALSE;
    
    inputFilePath = gtk_entry_get_text (GTK_ENTRY (inputFileNameBox));
    outputFilePath = gtk_entry_get_text (GTK_ENTRY (outputFileNameBox));
    
    passWord = gtk_entry_get_text (GTK_ENTRY (passwordBox));
    verificationPass = gtk_entry_get_text (GTK_ENTRY (passwordVerificationBox));
    if(strcmp(passWord,verificationPass) == 0)
        passwordsMatch = TRUE;
    
    if (passwordsMatch == FALSE) {
        strcpy(statusMessage,"Passwords didn't match");
    } else if(passwordsMatch == TRUE) {
        snprintf(userPass,MAX_PASS_SIZE,"%s",passWord);
    
        gtk_entry_set_text(GTK_ENTRY (passwordBox), "");
        OPENSSL_cleanse((void *)passWord, strlen(passWord));
        gtk_entry_set_text(GTK_ENTRY (passwordBox), passWord);
        
        gtk_entry_set_text(GTK_ENTRY (passwordVerificationBox), "");
        OPENSSL_cleanse((void *)verificationPass, strlen(verificationPass));
        gtk_entry_set_text(GTK_ENTRY (passwordVerificationBox), verificationPass);
        
        action = 'e';
        strcpy(statusMessage,"Starting encryption...");
        workThread();
    }
}

void on_decryptButton_clicked(GtkWidget *wid, gpointer ptr)
{
    inputFilePath = gtk_entry_get_text (GTK_ENTRY (inputFileNameBox));
    outputFilePath = gtk_entry_get_text (GTK_ENTRY (outputFileNameBox));
    
    passWord = gtk_entry_get_text (GTK_ENTRY (passwordBox));
    verificationPass = gtk_entry_get_text (GTK_ENTRY (passwordVerificationBox));
    
    snprintf(userPass,MAX_PASS_SIZE,"%s",passWord);
    
    gtk_entry_set_text(GTK_ENTRY (passwordBox), "");
    OPENSSL_cleanse((void *)passWord, strlen(passWord));
    gtk_entry_set_text(GTK_ENTRY (passwordBox), passWord);
    
    if(strlen(verificationPass)) {
        gtk_entry_set_text(GTK_ENTRY (passwordVerificationBox), "");
        OPENSSL_cleanse((void *)verificationPass, strlen(verificationPass));
        gtk_entry_set_text(GTK_ENTRY (passwordVerificationBox), verificationPass);
    }
    
    action = 'd';
    strcpy(statusMessage,"Starting decryption...");
    workThread();
}

static void inputFileSelect (GtkWidget *wid, gpointer ptr)
{
    GtkWidget *dialog;
    GtkFileChooserAction action = GTK_FILE_CHOOSER_ACTION_OPEN;
    gint res;
    char *fileName;
    
    dialog = gtk_file_chooser_dialog_new ("Open File",
                                          GTK_WINDOW (ptr),
                                          action,
                                          "Cancel",
                                          GTK_RESPONSE_CANCEL,
                                          "Open",
                                          GTK_RESPONSE_ACCEPT,
                                          NULL);
    
    res = gtk_dialog_run (GTK_DIALOG (dialog));
    if (res == GTK_RESPONSE_ACCEPT)
      {
        GtkFileChooser *chooser = GTK_FILE_CHOOSER (dialog);
        fileName = gtk_file_chooser_get_filename (chooser);
        gtk_entry_set_text(GTK_ENTRY (inputFileNameBox), fileName);
      }
    
    gtk_widget_destroy (dialog);
}

static void outputFileSelect (GtkWidget *wid, gpointer ptr)
{
    GtkWidget *dialog;
    GtkFileChooserAction action = GTK_FILE_CHOOSER_ACTION_SAVE;
    gint res;
    char *fileName;
    
    dialog = gtk_file_chooser_dialog_new ("Save File",
                                          GTK_WINDOW (ptr),
                                          action,
                                          "Cancel",
                                          GTK_RESPONSE_CANCEL,
                                          "Save As",
                                          GTK_RESPONSE_ACCEPT,
                                          NULL);
    
    res = gtk_dialog_run (GTK_DIALOG (dialog));
    if (res == GTK_RESPONSE_ACCEPT)
      {
        GtkFileChooser *chooser = GTK_FILE_CHOOSER (dialog);
        fileName = gtk_file_chooser_get_filename (chooser);
        gtk_entry_set_text(GTK_ENTRY (outputFileNameBox), fileName);
      }
    
    gtk_widget_destroy (dialog);
}

void passVisibilityToggle (GtkWidget *wid, gpointer ptr)
{
    gtk_entry_set_visibility(GTK_ENTRY (passwordBox), gtk_toggle_button_get_active (GTK_TOGGLE_BUTTON (wid)));
    gtk_entry_set_visibility(GTK_ENTRY (passwordVerificationBox), gtk_toggle_button_get_active (GTK_TOGGLE_BUTTON (wid)));
}
