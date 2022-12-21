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
static void keyFileSelect (GtkWidget *wid, gpointer ptr);
static void otpFileSelect (GtkWidget *wid, gpointer ptr);
void passVisibilityToggle (GtkWidget *wid, gpointer ptr);
void otpFileEntryDisable (void);
void keyFileEntryDisable (void);
void otpFileEntryEnable (void);
void keyFileEntryEnable (void);
static gboolean updateStatus(gpointer user_data);
static gboolean updateProgress(gpointer user_data);
static gboolean updateOverallProgress(gpointer user_data);
int workThread();

GtkWidget *inputFileNameBox;
GtkWidget *outputFileNameBox;
GtkWidget *keyFileNameBox;
GtkWidget *otpFileNameBox;
GtkWidget *passwordBox;
GtkWidget *passwordVerificationBox;

GtkWidget *nFactorTextBox;
GtkWidget *rFactorTextBox;
GtkWidget *pFactorTextBox;

GtkWidget *otpFileButton;
GtkWidget *keyFileButton;

GtkWidget *keySizeComboBox;
GtkWidget *macBufSizeComboBox;
GtkWidget *msgBufSizeComboBox;

const char *inputFilePath;
const char *outputFilePath;
const char *keyFilePath;
const char *otpFilePath;
const char *passWord;
const char *verificationPass;
const char *keySizeComboBoxText;
const char *macBufSizeComboBoxText;
const char *msgBufSizeComboBoxText;

char action = 0;

GtkWidget *statusBar;
guint statusContextID;

GtkWidget *overallProgressBar;
double *overallProgressFraction;

GtkWidget *progressBar;

struct optionsStruct optSt = {0};

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
    
    GtkWidget *scryptWorkFactorsLabel = gtk_label_new ("scrypt work factors:");
    
    GtkWidget *nFactorLabel = gtk_label_new ("N Factor");
    GtkAdjustment *nFactorSpinButtonAdj = gtk_adjustment_new (DEFAULT_SCRYPT_N, DEFAULT_SCRYPT_N, DEFAULT_SCRYPT_N * 8, 1048576, 0, 0);
    nFactorTextBox = gtk_spin_button_new (GTK_ADJUSTMENT (nFactorSpinButtonAdj), 0, 0);
    gtk_widget_set_tooltip_text (nFactorTextBox, "This is the N factor that will be used by scrypt");
    
    GtkWidget *rFactorLabel = gtk_label_new ("r Factor");
    GtkAdjustment *rFactorSpinButtonAdj = gtk_adjustment_new (DEFAULT_SCRYPT_R, -10, 10, 1, 0, 0);
    rFactorTextBox = gtk_spin_button_new (GTK_ADJUSTMENT (rFactorSpinButtonAdj), 0, 0);
    gtk_widget_set_tooltip_text (rFactorTextBox, "This is the r factor that will be used by scrypt");
    
    GtkWidget *pFactorLabel = gtk_label_new ("p Factor");
    GtkAdjustment *pFactorSpinButtonAdj = gtk_adjustment_new (DEFAULT_SCRYPT_P, -10, 10, 1, 0, 0);
    pFactorTextBox = gtk_spin_button_new (GTK_ADJUSTMENT (pFactorSpinButtonAdj), 0, 0);
    gtk_widget_set_tooltip_text (pFactorTextBox, "This is the p factor that will be used by scrypt");
    
    char scryptToolTipText[] = "\
    scrypt is a Key Derivation Function which derives a key from a password \
    that is very computationally and memory-expensive to attempt to brute-force\
    \n\
    \nN is the \"CostFactor\" and will increase CPU and memory usage. It must be a power of 2 and \
    it will increase memory usage exponentially, so you may run out of RAM if you set too high\n\
    \nr is the \"BlockSizeFactor\" which controls memory read size and performance\n\
    \np is the \"ParallelizationFactor\" factor which controls how many CPUs or cores to use\n\
    \nThe N factor is typically the only value which the user should modify and the default\
    is the current reccomendation, but one should Google for more guidance on this. Or, \
    as a rule of thumb, tune this to a factor which takes as long for your CPU to generate\
    a key as is satisfactory to you and/or that your computer has memory resources for.\
    \n\n ***Very Important***\n\
    You must remember these settings to generate the proper key for decryption";
    
    gtk_widget_set_tooltip_text (scryptWorkFactorsLabel, (const gchar * )scryptToolTipText);
    gtk_widget_set_tooltip_text (nFactorLabel, (const gchar * )scryptToolTipText);
    gtk_widget_set_tooltip_text (rFactorLabel, (const gchar * )scryptToolTipText);
    gtk_widget_set_tooltip_text (pFactorLabel, (const gchar * )scryptToolTipText);
    
    
    GtkWidget *keySizeLabel = gtk_label_new ("Key Size");
    keySizeComboBox = gtk_combo_box_text_new ();
    gtk_widget_set_tooltip_text (keySizeComboBox, "This controls the size of the key that will be derived from the password");
    gtk_combo_box_text_append_text (GTK_COMBO_BOX_TEXT (keySizeComboBox), "16 bytes");
    gtk_combo_box_text_append_text (GTK_COMBO_BOX_TEXT (keySizeComboBox), "32 bytes");
    gtk_combo_box_text_append_text (GTK_COMBO_BOX_TEXT (keySizeComboBox), "64 bytes");
    gtk_combo_box_text_append_text (GTK_COMBO_BOX_TEXT (keySizeComboBox), "128 bytes");
    gtk_combo_box_text_append_text (GTK_COMBO_BOX_TEXT (keySizeComboBox), "256 bytes");
    gtk_combo_box_text_append_text (GTK_COMBO_BOX_TEXT (keySizeComboBox), "512 bytes");
    gtk_combo_box_text_append_text (GTK_COMBO_BOX_TEXT (keySizeComboBox), "2 Kb");
    gtk_combo_box_text_append_text (GTK_COMBO_BOX_TEXT (keySizeComboBox), "4 Kb");
    gtk_combo_box_text_append_text (GTK_COMBO_BOX_TEXT (keySizeComboBox), "8 Kb");
    gtk_combo_box_text_append_text (GTK_COMBO_BOX_TEXT (keySizeComboBox), "16 Kb");
    gtk_combo_box_text_append_text (GTK_COMBO_BOX_TEXT (keySizeComboBox), "32 Kb");
    gtk_combo_box_text_append_text (GTK_COMBO_BOX_TEXT (keySizeComboBox), "64 Kb");
    gtk_combo_box_text_append_text (GTK_COMBO_BOX_TEXT (keySizeComboBox), "128 Kb");
    gtk_combo_box_text_append_text (GTK_COMBO_BOX_TEXT (keySizeComboBox), "256 Kb");
    gtk_combo_box_text_append_text (GTK_COMBO_BOX_TEXT (keySizeComboBox), "512 Kb");
    gtk_combo_box_text_append_text (GTK_COMBO_BOX_TEXT (keySizeComboBox), "1 Mb");
    gtk_combo_box_text_append_text (GTK_COMBO_BOX_TEXT (keySizeComboBox), "2 Mb");
    gtk_combo_box_text_append_text (GTK_COMBO_BOX_TEXT (keySizeComboBox), "4 Mb");
    gtk_combo_box_text_append_text (GTK_COMBO_BOX_TEXT (keySizeComboBox), "8 Mb");
    gtk_combo_box_text_append_text (GTK_COMBO_BOX_TEXT (keySizeComboBox), "16 Mb");
    gtk_combo_box_text_append_text (GTK_COMBO_BOX_TEXT (keySizeComboBox), "32 Mb");
    gtk_combo_box_text_append_text (GTK_COMBO_BOX_TEXT (keySizeComboBox), "64 Mb");
    gtk_combo_box_text_append_text (GTK_COMBO_BOX_TEXT (keySizeComboBox), "128 Mb");
    gtk_combo_box_text_append_text (GTK_COMBO_BOX_TEXT (keySizeComboBox), "256 Mb");
    gtk_combo_box_text_append_text (GTK_COMBO_BOX_TEXT (keySizeComboBox), "512 Mb");
    gtk_combo_box_set_active (GTK_COMBO_BOX (keySizeComboBox), 20);
    
    GtkWidget *visibilityButton = gtk_check_button_new_with_label ("Show Password");
    gtk_widget_set_tooltip_text (visibilityButton, "Hint: Use this to avoid typos");
    gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON (visibilityButton), FALSE);
    g_signal_connect (visibilityButton, "toggled", G_CALLBACK (passVisibilityToggle),NULL);
    
    GtkWidget *keyFileLabel = gtk_label_new ("Key File Path");
    keyFileNameBox = gtk_entry_new ();
    g_signal_connect (keyFileNameBox, "insert-text", G_CALLBACK (otpFileEntryDisable), NULL);
    g_signal_connect (keyFileNameBox, "delete-text", G_CALLBACK (otpFileEntryEnable), NULL);
    gtk_widget_set_tooltip_text (keyFileNameBox, "Enter the full path to the key you want to use here");
    keyFileButton = gtk_button_new_with_label ("Select File");
    gtk_widget_set_tooltip_text (keyFileButton, "Select the key file you want to use here");
    g_signal_connect (keyFileButton, "clicked", G_CALLBACK (keyFileSelect), win);
    g_signal_connect (keyFileButton, "clicked", G_CALLBACK (otpFileEntryDisable), NULL);
    
    GtkWidget *otpFileLabel = gtk_label_new ("One-Time-Pad File Path");
    otpFileNameBox = gtk_entry_new ();
    g_signal_connect (otpFileNameBox, "insert-text", G_CALLBACK (keyFileEntryDisable), NULL);
    g_signal_connect (otpFileNameBox, "delete-text", G_CALLBACK (keyFileEntryEnable), NULL);
    otpFileButton = gtk_button_new_with_label ("Select File");
    gtk_widget_set_tooltip_text (otpFileButton, "Select the one-time-pad file you want to use here");
    g_signal_connect (otpFileButton, "clicked", G_CALLBACK (otpFileSelect), win);
    g_signal_connect (otpFileButton, "clicked", G_CALLBACK (keyFileEntryDisable), NULL);
    
    gtk_widget_set_tooltip_text (otpFileNameBox, "Enter the full path to the one-time-pad you want to use here\
    \n\n\
    Using a one-time-pad means using something like /dev/urandom or another random-number generator\
    to produce a keystream that will be as long as the file being encrypted is. This cannot be used\
    in conjunction with a regular key, and the one-time-pad will be saved in the same directory as\
    the input file, under the same name, but with a .pad extension\
    \n***Very Important:*** Must use same size buffers between encryption and decryption");
    
    GtkWidget *macBufSizeLabel = gtk_label_new ("Authentication Buffer Size");
    macBufSizeComboBox = gtk_combo_box_text_new ();
    gtk_widget_set_tooltip_text (macBufSizeComboBox, "This controls the size of the buffer used for authenticating data");
    gtk_combo_box_text_append_text (GTK_COMBO_BOX_TEXT (macBufSizeComboBox), "1 byte");
    gtk_combo_box_text_append_text (GTK_COMBO_BOX_TEXT (macBufSizeComboBox), "2 bytes");
    gtk_combo_box_text_append_text (GTK_COMBO_BOX_TEXT (macBufSizeComboBox), "4 bytes");
    gtk_combo_box_text_append_text (GTK_COMBO_BOX_TEXT (macBufSizeComboBox), "8 bytes");
    gtk_combo_box_text_append_text (GTK_COMBO_BOX_TEXT (macBufSizeComboBox), "16 bytes");
    gtk_combo_box_text_append_text (GTK_COMBO_BOX_TEXT (macBufSizeComboBox), "32 bytes");
    gtk_combo_box_text_append_text (GTK_COMBO_BOX_TEXT (macBufSizeComboBox), "64 bytes");
    gtk_combo_box_text_append_text (GTK_COMBO_BOX_TEXT (macBufSizeComboBox), "128 bytes");
    gtk_combo_box_text_append_text (GTK_COMBO_BOX_TEXT (macBufSizeComboBox), "256 bytes");
    gtk_combo_box_text_append_text (GTK_COMBO_BOX_TEXT (macBufSizeComboBox), "512 bytes");
    gtk_combo_box_text_append_text (GTK_COMBO_BOX_TEXT (macBufSizeComboBox), "1 Kb");
    gtk_combo_box_text_append_text (GTK_COMBO_BOX_TEXT (macBufSizeComboBox), "2 Kb");
    gtk_combo_box_text_append_text (GTK_COMBO_BOX_TEXT (macBufSizeComboBox), "4 Kb");
    gtk_combo_box_text_append_text (GTK_COMBO_BOX_TEXT (macBufSizeComboBox), "8 Kb");
    gtk_combo_box_text_append_text (GTK_COMBO_BOX_TEXT (macBufSizeComboBox), "16 Kb");
    gtk_combo_box_text_append_text (GTK_COMBO_BOX_TEXT (macBufSizeComboBox), "32 Kb");
    gtk_combo_box_text_append_text (GTK_COMBO_BOX_TEXT (macBufSizeComboBox), "64 Kb");
    gtk_combo_box_text_append_text (GTK_COMBO_BOX_TEXT (macBufSizeComboBox), "128 Kb");
    gtk_combo_box_text_append_text (GTK_COMBO_BOX_TEXT (macBufSizeComboBox), "256 Kb");
    gtk_combo_box_text_append_text (GTK_COMBO_BOX_TEXT (macBufSizeComboBox), "512 Kb");
    gtk_combo_box_text_append_text (GTK_COMBO_BOX_TEXT (macBufSizeComboBox), "1 Mb");
    gtk_combo_box_text_append_text (GTK_COMBO_BOX_TEXT (macBufSizeComboBox), "2 Mb");
    gtk_combo_box_text_append_text (GTK_COMBO_BOX_TEXT (macBufSizeComboBox), "4 Mb");
    gtk_combo_box_text_append_text (GTK_COMBO_BOX_TEXT (macBufSizeComboBox), "8 Mb");
    gtk_combo_box_text_append_text (GTK_COMBO_BOX_TEXT (macBufSizeComboBox), "16 Mb");
    gtk_combo_box_text_append_text (GTK_COMBO_BOX_TEXT (macBufSizeComboBox), "32 Mb");
    gtk_combo_box_text_append_text (GTK_COMBO_BOX_TEXT (macBufSizeComboBox), "64 Mb");
    gtk_combo_box_text_append_text (GTK_COMBO_BOX_TEXT (macBufSizeComboBox), "128 Mb");
    gtk_combo_box_text_append_text (GTK_COMBO_BOX_TEXT (macBufSizeComboBox), "256 Mb");
    gtk_combo_box_text_append_text (GTK_COMBO_BOX_TEXT (macBufSizeComboBox), "512 Mb");
    gtk_combo_box_text_append_text (GTK_COMBO_BOX_TEXT (macBufSizeComboBox), "1 Gb");
    gtk_combo_box_text_append_text (GTK_COMBO_BOX_TEXT (macBufSizeComboBox), "2 Gb");
    gtk_combo_box_text_append_text (GTK_COMBO_BOX_TEXT (macBufSizeComboBox), "4 Gb");
    gtk_combo_box_text_append_text (GTK_COMBO_BOX_TEXT (macBufSizeComboBox), "8 Gb");
    gtk_combo_box_set_active (GTK_COMBO_BOX (macBufSizeComboBox), 20);
    
    GtkWidget *msgBufSizeLabel = gtk_label_new ("File Buffer Size");
    msgBufSizeComboBox = gtk_combo_box_text_new ();
    gtk_widget_set_tooltip_text (msgBufSizeComboBox, "This controls the size of the buffer used for encryption/decryption data");
    gtk_combo_box_text_append_text (GTK_COMBO_BOX_TEXT (msgBufSizeComboBox), "1 byte");
    gtk_combo_box_text_append_text (GTK_COMBO_BOX_TEXT (msgBufSizeComboBox), "2 bytes");
    gtk_combo_box_text_append_text (GTK_COMBO_BOX_TEXT (msgBufSizeComboBox), "4 bytes");
    gtk_combo_box_text_append_text (GTK_COMBO_BOX_TEXT (msgBufSizeComboBox), "8 bytes");
    gtk_combo_box_text_append_text (GTK_COMBO_BOX_TEXT (msgBufSizeComboBox), "16 bytes");
    gtk_combo_box_text_append_text (GTK_COMBO_BOX_TEXT (msgBufSizeComboBox), "32 bytes");
    gtk_combo_box_text_append_text (GTK_COMBO_BOX_TEXT (msgBufSizeComboBox), "64 bytes");
    gtk_combo_box_text_append_text (GTK_COMBO_BOX_TEXT (msgBufSizeComboBox), "128 bytes");
    gtk_combo_box_text_append_text (GTK_COMBO_BOX_TEXT (msgBufSizeComboBox), "256 bytes");
    gtk_combo_box_text_append_text (GTK_COMBO_BOX_TEXT (msgBufSizeComboBox), "512 bytes");
    gtk_combo_box_text_append_text (GTK_COMBO_BOX_TEXT (msgBufSizeComboBox), "1 Kb");
    gtk_combo_box_text_append_text (GTK_COMBO_BOX_TEXT (msgBufSizeComboBox), "2 Kb");
    gtk_combo_box_text_append_text (GTK_COMBO_BOX_TEXT (msgBufSizeComboBox), "4 Kb");
    gtk_combo_box_text_append_text (GTK_COMBO_BOX_TEXT (msgBufSizeComboBox), "8 Kb");
    gtk_combo_box_text_append_text (GTK_COMBO_BOX_TEXT (msgBufSizeComboBox), "16 Kb");
    gtk_combo_box_text_append_text (GTK_COMBO_BOX_TEXT (msgBufSizeComboBox), "32 Kb");
    gtk_combo_box_text_append_text (GTK_COMBO_BOX_TEXT (msgBufSizeComboBox), "64 Kb");
    gtk_combo_box_text_append_text (GTK_COMBO_BOX_TEXT (msgBufSizeComboBox), "128 Kb");
    gtk_combo_box_text_append_text (GTK_COMBO_BOX_TEXT (msgBufSizeComboBox), "256 Kb");
    gtk_combo_box_text_append_text (GTK_COMBO_BOX_TEXT (msgBufSizeComboBox), "512 Kb");
    gtk_combo_box_text_append_text (GTK_COMBO_BOX_TEXT (msgBufSizeComboBox), "1 Mb");
    gtk_combo_box_text_append_text (GTK_COMBO_BOX_TEXT (msgBufSizeComboBox), "2 Mb");
    gtk_combo_box_text_append_text (GTK_COMBO_BOX_TEXT (msgBufSizeComboBox), "4 Mb");
    gtk_combo_box_text_append_text (GTK_COMBO_BOX_TEXT (msgBufSizeComboBox), "8 Mb");
    gtk_combo_box_text_append_text (GTK_COMBO_BOX_TEXT (msgBufSizeComboBox), "16 Mb");
    gtk_combo_box_text_append_text (GTK_COMBO_BOX_TEXT (msgBufSizeComboBox), "32 Mb");
    gtk_combo_box_text_append_text (GTK_COMBO_BOX_TEXT (msgBufSizeComboBox), "64 Mb");
    gtk_combo_box_text_append_text (GTK_COMBO_BOX_TEXT (msgBufSizeComboBox), "128 Mb");
    gtk_combo_box_text_append_text (GTK_COMBO_BOX_TEXT (msgBufSizeComboBox), "256 Mb");
    gtk_combo_box_text_append_text (GTK_COMBO_BOX_TEXT (msgBufSizeComboBox), "512 Mb");
    gtk_combo_box_text_append_text (GTK_COMBO_BOX_TEXT (msgBufSizeComboBox), "1 Gb");
    gtk_combo_box_text_append_text (GTK_COMBO_BOX_TEXT (msgBufSizeComboBox), "2 Gb");
    gtk_combo_box_text_append_text (GTK_COMBO_BOX_TEXT (msgBufSizeComboBox), "4 Gb");
    gtk_combo_box_text_append_text (GTK_COMBO_BOX_TEXT (msgBufSizeComboBox), "8 Gb");
    gtk_combo_box_set_active (GTK_COMBO_BOX (msgBufSizeComboBox), 20);
    
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
    gtk_grid_attach (GTK_GRID (grid), visibilityButton, 1, 8, 1, 1);
    gtk_grid_attach (GTK_GRID (grid), verificationLabel, 0, 9, 1, 1);
    gtk_grid_attach (GTK_GRID (grid), keySizeLabel, 0, 11, 1, 1);
    gtk_grid_attach (GTK_GRID (grid), keySizeComboBox, 1, 11, 1, 1);
    gtk_grid_attach (GTK_GRID (grid), passwordVerificationBox, 0, 10, 1, 1);
    gtk_grid_attach (GTK_GRID (grid), scryptWorkFactorsLabel, 0, 12, 1, 1);
    gtk_grid_attach (GTK_GRID (grid), nFactorLabel, 0, 13, 1, 1);
    gtk_grid_attach (GTK_GRID (grid), nFactorTextBox, 1, 13, 1, 1);
    gtk_grid_attach (GTK_GRID (grid), rFactorLabel, 0, 15, 1, 1);
    gtk_grid_attach (GTK_GRID (grid), rFactorTextBox, 1, 15, 1, 1);
    gtk_grid_attach (GTK_GRID (grid), pFactorLabel, 0, 17, 1, 1);
    gtk_grid_attach (GTK_GRID (grid), pFactorTextBox, 1, 17, 1, 1);
    gtk_grid_attach (GTK_GRID (grid), keyFileLabel, 0, 18, 1, 1);
    gtk_grid_attach (GTK_GRID (grid), keyFileNameBox, 0, 19, 1, 1);
    gtk_grid_attach (GTK_GRID (grid), keyFileButton, 1, 19, 1, 1);
    gtk_grid_attach (GTK_GRID (grid), otpFileLabel, 0, 20, 1, 1);
    gtk_grid_attach (GTK_GRID (grid), otpFileNameBox, 0, 21, 1, 1);
    gtk_grid_attach (GTK_GRID (grid), otpFileButton, 1, 21, 1, 1);
    gtk_grid_attach (GTK_GRID (grid), macBufSizeLabel, 0, 24, 1, 1);
    gtk_grid_attach (GTK_GRID (grid), macBufSizeComboBox, 0, 25, 1, 1);
    gtk_grid_attach (GTK_GRID (grid), msgBufSizeLabel, 1, 24, 1, 1);
    gtk_grid_attach (GTK_GRID (grid), msgBufSizeComboBox, 1, 25, 1, 1);
    gtk_grid_attach (GTK_GRID (grid), encryptButton, 0, 26, 2, 1);
    gtk_grid_attach (GTK_GRID (grid), decryptButton, 0, 27, 2, 1);
    gtk_grid_attach (GTK_GRID (grid), progressBar, 0, 28, 2, 1);
    gtk_grid_attach (GTK_GRID (grid), overallProgressBar, 0, 29, 2, 1);
    gtk_grid_attach (GTK_GRID (grid), statusBar, 0, 30, 2, 1);
    
    
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
    
    FILE *otpInFile = NULL;
    FILE *otpOutFile = NULL;

    cryptint_t fileSize;
    
    counterInt = 0;
    keyInt = 0;
    k = 0;

    if (action == 'e') {
        
        if(optSt.keyFileGiven) {
            strcpy(statusMessage,"Generating salt...");
            *overallProgressFraction = .1;
            genYaxaSalt();
            
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
                strcpy(statusMessage,"Generating encryption key...");
                *overallProgressFraction = .2;
                genYaxaKey();
                keyBufSize = keyFileSize;
            }
            
        } else if(optSt.oneTimePad) {
            
            keyBufSize = HMAC_KEY_SIZE;
            
            strcpy(statusMessage,"Generating salt...");
            *overallProgressFraction = .1;
            genYaxaSalt();
            
            otpInFile = fopen(otpInFileName,"rb");
            if (otpInFile == NULL) {
                printFileError(otpInFileName, errno);
                exit(EXIT_FAILURE);
            }
            
            otpOutFile = fopen(otpOutFileName,"wb");
            
            if(optSt.passWordGiven) {
                strcpy(statusMessage,"Generating enecryption key...");
                *overallProgressFraction = .2;
                genYaxaKey();
            } else {
                if(freadWErrCheck(yaxaKey,sizeof(*yaxaKey),HMAC_KEY_SIZE,otpInFile) != 0) {
                    printSysError(returnVal);
                    exit(EXIT_FAILURE);
                }
                if(fwriteWErrCheck(yaxaKey,sizeof(*yaxaKey),HMAC_KEY_SIZE,otpOutFile) != 0) {
                    printSysError(returnVal);
                    exit(EXIT_FAILURE);
                }
            }
            
        } else {

            strcpy(statusMessage,"Generating salt...");
            *overallProgressFraction = .1;
            genYaxaSalt();
    
            strcpy(statusMessage,"Generating enecryption key...");
            *overallProgressFraction = .2;
            genYaxaKey();
        }
        
        strcpy(statusMessage,"Generating counter start...");
        genCtrStart();
        
        strcpy(statusMessage,"Generating nonce...");
        genNonce();
        
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
        if (fwriteWErrCheck(yaxaSalt, sizeof(*yaxaSalt), yaxaSaltSize, outFile) != 0) {
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
        if(optSt.oneTimePad) {
            doCrypt(inFile, outFile, fileSize, otpInFile, otpOutFile);
        } else {
            doCrypt(inFile, outFile, fileSize, NULL, NULL);
        }

        if(fclose(inFile) != 0) {
            printSysError(errno);
            printError("Error closing file");
            exit(EXIT_FAILURE);
        }

        OPENSSL_cleanse(hmacKey, sizeof(*hmacKey) * HMAC_KEY_SIZE);

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
        if (freadWErrCheck(yaxaSalt, sizeof(*yaxaSalt), yaxaSaltSize, inFile) != 0) {
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
        
        if(optSt.keyFileGiven) {
            FILE *keyFile = fopen(keyFileName,"rb");
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
                strcpy(statusMessage,"Generating encryption key...");
                *overallProgressFraction = .2;
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
            
            if(optSt.passWordGiven) {
                strcpy(statusMessage,"Generating decryption key...");
                *overallProgressFraction = .3;
                genYaxaKey();
            } else {
                if(freadWErrCheck(yaxaKey,sizeof(*yaxaKey),HMAC_KEY_SIZE,otpInFile) != 0) {
                    printSysError(returnVal);
                    exit(EXIT_FAILURE);
                }
            }
                        
        } else {
            strcpy(statusMessage,"Generating decryption key...");
            *overallProgressFraction = .3;
            genYaxaKey();
        }
        
        strcpy(statusMessage,"Generating counter start...");
        genCtrStart();
        
        strcpy(statusMessage,"Generating nonce...");
        genNonce();
        
        strcpy(statusMessage,"Generating auth key...");
        *overallProgressFraction = .4;
        genHMACKey();
        
        strcpy(statusMessage,"Generation password keyed-hash...");
        *overallProgressFraction = .5;
        genPassTag();

        strcpy(statusMessage,"Verifying password...");
        *overallProgressFraction = .6;
        if (CRYPTO_memcmp(passKeyedHash, passKeyedHashFromFile, sizeof(*passKeyedHashFromFile) * PASS_KEYED_HASH_SIZE) != 0) {
            printf("Wrong password\n");
            strcpy(statusMessage,"Wrong password");
            exit(EXIT_FAILURE);
        }

        /*Get filesize, discounting the salt and passKeyedHash*/
        fileSize = getFileSize(inputFilePath) - (yaxaSaltSize + PASS_KEYED_HASH_SIZE);

        /*Move file position to the start of the MAC*/
        fseek(inFile, (fileSize + yaxaSaltSize + PASS_KEYED_HASH_SIZE) - MAC_SIZE, SEEK_SET);

        if (freadWErrCheck(fileMAC, sizeof(*fileMAC), MAC_SIZE, inFile) != 0) {
            printSysError(returnVal);
            printError("Could not read MAC");
            exit(EXIT_FAILURE);
        }

        /*Reset file position to beginning of file*/
        rewind(inFile);

        strcpy(statusMessage,"Authenticating data...");
        *overallProgressFraction = .7;
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
        
        strcpy(statusMessage,"Decrypting...");
        *overallProgressFraction = .8;

        /*Now decrypt the cipher-text, disocounting the size of the MAC*/        
        if(optSt.oneTimePad) {
            doCrypt(inFile, outFile, fileSize - MAC_SIZE, otpInFile, NULL);
        } else {
            doCrypt(inFile, outFile, fileSize - MAC_SIZE, NULL, NULL);
        }

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
    
    return 0;
}

static gboolean updateStatus(gpointer user_data)
{
    statusContextID = gtk_statusbar_get_context_id (GTK_STATUSBAR (statusBar), "Statusbar");
    gtk_statusbar_push (GTK_STATUSBAR (statusBar), GPOINTER_TO_INT (statusContextID), statusMessage);
    
    return TRUE;
}

static gboolean updateProgress(gpointer user_data)
{
    gtk_progress_bar_set_fraction (GTK_PROGRESS_BAR (progressBar), *progressFraction);
    if(*progressFraction > 1)
        *progressFraction = 0.0;
        
    return TRUE;
}

static gboolean updateOverallProgress(gpointer user_data)
{
    gtk_progress_bar_set_fraction (GTK_PROGRESS_BAR (overallProgressBar), *overallProgressFraction);
    if(*overallProgressFraction > 1)
        *overallProgressFraction = 0.0;
        
    return TRUE;
}

void on_encryptButton_clicked(GtkWidget *wid, gpointer ptr)
{
    keyFileEntryEnable();
    otpFileEntryEnable();
    
    gboolean passwordsMatch = FALSE;
    gboolean error = FALSE;
    
    inputFilePath = gtk_entry_get_text (GTK_ENTRY (inputFileNameBox));
    outputFilePath = gtk_entry_get_text (GTK_ENTRY (outputFileNameBox));
    passWord = gtk_entry_get_text (GTK_ENTRY (passwordBox));
    keyFilePath = gtk_entry_get_text (GTK_ENTRY (keyFileNameBox));
    otpFilePath = gtk_entry_get_text (GTK_ENTRY (otpFileNameBox));
    keySizeComboBoxText = gtk_combo_box_text_get_active_text (GTK_COMBO_BOX_TEXT (keySizeComboBox));
    macBufSizeComboBoxText = gtk_combo_box_text_get_active_text (GTK_COMBO_BOX_TEXT (macBufSizeComboBox));
    msgBufSizeComboBoxText = gtk_combo_box_text_get_active_text (GTK_COMBO_BOX_TEXT (msgBufSizeComboBox));
    
    if(strlen(inputFilePath)) {
        optSt.inputFileGiven = true;
    } else {
        strcpy(statusMessage,"Need input file...");
        error = TRUE;
    }
    
    if(strlen(outputFilePath)) {
        optSt.outputFileGiven = true;
    } else {
        strcpy(statusMessage,"Need output file...");
        error = TRUE;
    }
    
    if(!strcmp(inputFilePath,outputFilePath)) {
        strcpy(statusMessage,"Input and output file are the same...");
        error = TRUE;
    }
        
    if(gtk_spin_button_get_value_as_int (GTK_SPIN_BUTTON(nFactorTextBox)) != DEFAULT_SCRYPT_N) {
        nFactor = gtk_spin_button_get_value_as_int (GTK_SPIN_BUTTON(nFactorTextBox));
    }
    
    if(gtk_spin_button_get_value_as_int (GTK_SPIN_BUTTON(rFactorTextBox)) != DEFAULT_SCRYPT_R) {
        rFactor = gtk_spin_button_get_value_as_int (GTK_SPIN_BUTTON(rFactorTextBox));
    }
    
    if(gtk_spin_button_get_value_as_int (GTK_SPIN_BUTTON(pFactorTextBox)) != DEFAULT_SCRYPT_P) {
        pFactor = gtk_spin_button_get_value_as_int (GTK_SPIN_BUTTON(pFactorTextBox));
    }
    
    if(strcmp(keySizeComboBoxText,"32 Mb") != 0) {
        keyBufSize = atol(keySizeComboBoxText) * sizeof(uint8_t) * getBufSizeMultiple((char *)keySizeComboBoxText);
        yaxaSaltSize = keyBufSize / YAXA_KEY_CHUNK_SIZE;
    }
    
    if(strcmp(macBufSizeComboBoxText,"1 Mb") != 0) {
        genHmacBufSize = atol(macBufSizeComboBoxText) * sizeof(uint8_t) * getBufSizeMultiple((char *)macBufSizeComboBoxText);
        makeMultipleOf(&genHmacBufSize,sizeof(cryptint_t));
    }
    
    if(strcmp(msgBufSizeComboBoxText,"1 Mb") != 0) {
         msgBufSize = atol(msgBufSizeComboBoxText) * sizeof(uint8_t) * getBufSizeMultiple((char *)msgBufSizeComboBoxText);
         makeMultipleOf(&msgBufSize,sizeof(cryptint_t));
    }
    
    if(strlen(passWord)) {
        optSt.passWordGiven = true;
    } else {
        optSt.passWordGiven = false;
    }
    
    if(strlen(keyFilePath)) {
        optSt.keyFileGiven = true;
        strcpy(keyFileName,keyFilePath);
        keyFileSize = getFileSize(keyFileName);
        keyBufSize = keyFileSize;
        yaxaSaltSize = keyBufSize / YAXA_KEY_CHUNK_SIZE;
    } else {
        optSt.keyFileGiven = false;
    }
    
    if(strlen(otpFilePath)) {
        optSt.oneTimePad = true;
        yaxaSaltSize = 0;
        strcpy(otpInFileName,otpFilePath);
        snprintf(otpOutFileName, NAME_MAX, "%s", otpFilePath);
        sprintf(otpOutFileName,"%s.pad", outputFilePath);
    } else {
        optSt.oneTimePad = false;
    }
    
    if((optSt.passWordGiven && optSt.keyFileGiven) || (optSt.passWordGiven && optSt.oneTimePad)) {
        yaxaSaltSize = keyBufSize / YAXA_KEY_CHUNK_SIZE;
    } else if (optSt.oneTimePad || optSt.keyFileGiven) {
        yaxaSaltSize = 0;
    }
    
    if(optSt.passWordGiven) {
        verificationPass = gtk_entry_get_text (GTK_ENTRY (passwordVerificationBox));
        if(strcmp(passWord,verificationPass) == 0)
            passwordsMatch = TRUE;
        
        if (passwordsMatch == FALSE) {
            strcpy(statusMessage,"Passwords didn't match");
            error = TRUE;
        } else if(passwordsMatch == TRUE) {
            snprintf(userPass,MAX_PASS_SIZE,"%s",passWord);
        
            gtk_entry_set_text(GTK_ENTRY (passwordBox), "");
            OPENSSL_cleanse((void *)passWord, strlen(passWord));
            gtk_entry_set_text(GTK_ENTRY (passwordBox), passWord);
            
            gtk_entry_set_text(GTK_ENTRY (passwordVerificationBox), "");
            OPENSSL_cleanse((void *)verificationPass, strlen(verificationPass));
            gtk_entry_set_text(GTK_ENTRY (passwordVerificationBox), verificationPass);
        }
    }
    
    if(optSt.keyFileGiven && optSt.oneTimePad) {
        strcpy(statusMessage,"Can only use keyfile OR one-time-pad");
        error = TRUE;
    }
    
    if(error != TRUE) {
        action = 'e';
        strcpy(statusMessage,"Starting encryption...");
        workThread();
    }
}

void on_decryptButton_clicked(GtkWidget *wid, gpointer ptr)
{
    keyFileEntryEnable();
    otpFileEntryEnable();
    
    gboolean error = FALSE;
    
    inputFilePath = gtk_entry_get_text (GTK_ENTRY (inputFileNameBox));
    outputFilePath = gtk_entry_get_text (GTK_ENTRY (outputFileNameBox));
    passWord = gtk_entry_get_text (GTK_ENTRY (passwordBox));
    verificationPass = gtk_entry_get_text (GTK_ENTRY (passwordVerificationBox));
    keyFilePath = gtk_entry_get_text (GTK_ENTRY (keyFileNameBox));
    otpFilePath = gtk_entry_get_text (GTK_ENTRY (otpFileNameBox));
    keySizeComboBoxText = gtk_combo_box_text_get_active_text (GTK_COMBO_BOX_TEXT (keySizeComboBox));
    macBufSizeComboBoxText = gtk_combo_box_text_get_active_text (GTK_COMBO_BOX_TEXT (macBufSizeComboBox));
    msgBufSizeComboBoxText = gtk_combo_box_text_get_active_text (GTK_COMBO_BOX_TEXT (msgBufSizeComboBox));
    
    if(strlen(inputFilePath)) {
        optSt.inputFileGiven = true;
    } else {
        strcpy(statusMessage,"Need input file...");
        error = TRUE;
    }
    
    if(strlen(outputFilePath)) {
        optSt.outputFileGiven = true;
    } else {
        strcpy(statusMessage,"Need output file...");
        error = TRUE;
    }
    
    if(gtk_spin_button_get_value_as_int (GTK_SPIN_BUTTON(nFactorTextBox)) != DEFAULT_SCRYPT_N) {
        nFactor = gtk_spin_button_get_value_as_int (GTK_SPIN_BUTTON(nFactorTextBox));
    }
    
    if(gtk_spin_button_get_value_as_int (GTK_SPIN_BUTTON(rFactorTextBox)) != DEFAULT_SCRYPT_R) {
        rFactor = gtk_spin_button_get_value_as_int (GTK_SPIN_BUTTON(rFactorTextBox));
    }
    
    if(gtk_spin_button_get_value_as_int (GTK_SPIN_BUTTON(pFactorTextBox)) != DEFAULT_SCRYPT_P) {
        pFactor = gtk_spin_button_get_value_as_int (GTK_SPIN_BUTTON(pFactorTextBox));
    }
    
    if(strcmp(keySizeComboBoxText,"32 Mb") != 0) {
        keyBufSize = atol(keySizeComboBoxText) * sizeof(uint8_t) * getBufSizeMultiple((char *)keySizeComboBoxText);
        yaxaSaltSize = keyBufSize / YAXA_KEY_CHUNK_SIZE;
    }
    
    if(strcmp(macBufSizeComboBoxText,"1 Mb") != 0) {
        genHmacBufSize = atol(macBufSizeComboBoxText) * sizeof(uint8_t) * getBufSizeMultiple((char *)macBufSizeComboBoxText);
        makeMultipleOf(&genHmacBufSize,sizeof(cryptint_t));
    }
    
    if(strcmp(msgBufSizeComboBoxText,"1 Mb") != 0) {
         msgBufSize = atol(msgBufSizeComboBoxText) * sizeof(uint8_t) * getBufSizeMultiple((char *)msgBufSizeComboBoxText);
         makeMultipleOf(&msgBufSize,sizeof(cryptint_t));
    }
    
    if(strlen(passWord)) {
        optSt.passWordGiven = true;
    } else {
        optSt.passWordGiven = false;
    }
    
    if(!strcmp(inputFilePath,outputFilePath)) {
        strcpy(statusMessage,"Input and output file are the same...");
        error = TRUE;
    }
    
    if(strlen(keyFilePath)) {
        optSt.keyFileGiven = true;
        strcpy(keyFileName,keyFilePath);
        keyFileSize = getFileSize(keyFileName);
        keyBufSize = keyFileSize;
        yaxaSaltSize = keyBufSize / YAXA_KEY_CHUNK_SIZE;
    } else {
        optSt.keyFileGiven = false;
    }
    
    if(strlen(otpFilePath)) {
        optSt.oneTimePad = true;
        yaxaSaltSize = 0;
        strcpy(otpInFileName,otpFilePath);
        snprintf(otpOutFileName, NAME_MAX, "%s", otpFilePath);
        sprintf(otpOutFileName,"%s.pad", outputFilePath);
    } else {
        optSt.oneTimePad = false;
    }
    
    if((optSt.passWordGiven && optSt.keyFileGiven) || (optSt.passWordGiven && optSt.oneTimePad)) {
        yaxaSaltSize = keyBufSize / YAXA_KEY_CHUNK_SIZE;
    } else if (optSt.oneTimePad || optSt.keyFileGiven) {
        yaxaSaltSize = 0;
    }
    
    snprintf(userPass,MAX_PASS_SIZE,"%s",passWord);
    
    gtk_entry_set_text(GTK_ENTRY (passwordBox), "");
    OPENSSL_cleanse((void *)passWord, strlen(passWord));
    gtk_entry_set_text(GTK_ENTRY (passwordBox), passWord);
    
    if(strlen(verificationPass)) {
        gtk_entry_set_text(GTK_ENTRY (passwordVerificationBox), "");
        OPENSSL_cleanse((void *)verificationPass, strlen(verificationPass));
        gtk_entry_set_text(GTK_ENTRY (passwordVerificationBox), verificationPass);
    }
    
    if(optSt.keyFileGiven && optSt.oneTimePad) {
        strcpy(statusMessage,"Can only use keyfile OR one-time-pad");
        error = TRUE;
    }
        
    if(error != TRUE) {
        action = 'd';
        strcpy(statusMessage,"Starting encryption...");
        workThread();
    }
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

static void keyFileSelect (GtkWidget *wid, gpointer ptr)
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
        gtk_entry_set_text(GTK_ENTRY (keyFileNameBox), fileName);
      }
    
    gtk_widget_destroy (dialog);
}

static void otpFileSelect (GtkWidget *wid, gpointer ptr)
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
        gtk_entry_set_text(GTK_ENTRY (otpFileNameBox), fileName);
      }
    
    gtk_widget_destroy (dialog);
}

void passVisibilityToggle (GtkWidget *wid, gpointer ptr)
{
    gtk_entry_set_visibility(GTK_ENTRY (passwordBox), gtk_toggle_button_get_active (GTK_TOGGLE_BUTTON (wid)));
    gtk_entry_set_visibility(GTK_ENTRY (passwordVerificationBox), gtk_toggle_button_get_active (GTK_TOGGLE_BUTTON (wid)));
}

void otpFileEntryDisable (void)
{
    gtk_editable_set_editable(GTK_EDITABLE(otpFileNameBox), FALSE);
    gtk_widget_set_sensitive (GTK_WIDGET(otpFileButton), FALSE);

}

void keyFileEntryDisable (void)
{
    gtk_editable_set_editable(GTK_EDITABLE(keyFileNameBox), FALSE);
    gtk_widget_set_sensitive (GTK_WIDGET(keyFileButton), FALSE);

}

void otpFileEntryEnable (void)
{
    gtk_editable_set_editable(GTK_EDITABLE(otpFileNameBox), TRUE);
    gtk_widget_set_sensitive (GTK_WIDGET(otpFileButton), TRUE);

}

void keyFileEntryEnable (void)
{
    gtk_editable_set_editable(GTK_EDITABLE(keyFileNameBox), TRUE);
    gtk_widget_set_sensitive (GTK_WIDGET(keyFileButton), TRUE);

}

