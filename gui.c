/*
  This product includes software developed by the OpenSSL Project
  for use in the OpenSSL Toolkit (http://www.openssl.org/)
*/
#include "headers.h"
#include "crypt.c"
#include "misc.c"
#include "buffers.c"

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

GtkWidget *overallProgressBar;
double *overallProgressFraction;

GtkWidget *progressBar;

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

    cryptint_t fileSize;
    
    counterInt = 0;
    keyInt = 0;
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
