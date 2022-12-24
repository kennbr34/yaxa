/*
  This product includes software developed by the OpenSSL Project
  for use in the OpenSSL Toolkit (http://www.openssl.org/)
*/
#include "headers.h"
#include "crypt.c"
#include "misc.c"
#include "buffers.c"
#include "workthread.c"

void on_cryptButton_clicked(GtkWidget *wid, gpointer ptr);
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

struct guiStruct {
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
};

struct guiStruct guiSt = {0};

int main(int argc, char *argv[])
{
    
    cryptSt.nFactor = DEFAULT_SCRYPT_N;
    cryptSt.pFactor = DEFAULT_SCRYPT_P;
    cryptSt.rFactor = DEFAULT_SCRYPT_R;
    cryptSt.k = 0;
    
    sizesSt.keyBufSize = YAXA_KEYBUF_SIZE;
    sizesSt.genHmacBufSize = 1024 * 1024;
    sizesSt.msgBufSize = 1024 * 1024;
    sizesSt.yaxaSaltSize = YAXA_KEYBUF_SIZE / YAXA_KEY_CHUNK_SIZE;

    /*These must be mapped as shared memory for the worker thread to manipulate their values in the main thread*/
    progressSt.statusMessage = mmap(NULL, 256, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    progressSt.progressFraction = mmap(NULL, sizeof(double), PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    progressSt.overallProgressFraction = mmap(NULL, sizeof(double), PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    
    signal(SIGINT, signalHandler);

    atexit(cleanUpBuffers);

    allocateBuffers();

    OpenSSL_add_all_algorithms();
    
    gtk_init (&argc, &argv);
    
    GtkWidget *win = gtk_window_new (GTK_WINDOW_TOPLEVEL);
    
    gtk_window_set_title(GTK_WINDOW (win), "YAXA File Encryption Utility");
    
    GtkWidget *inputFileLabel = gtk_label_new ("Input File Path");
    guiSt.inputFileNameBox = gtk_entry_new ();
    gtk_widget_set_tooltip_text (guiSt.inputFileNameBox, "Enter the full path to the file you want to encrypt/decrypt here");
    GtkWidget *inputFileButton = gtk_button_new_with_label ("Select File");
    gtk_widget_set_tooltip_text (inputFileButton, "Select the file you want to encrypt/decrypt to fill in this path");
    g_signal_connect (inputFileButton, "clicked", G_CALLBACK (inputFileSelect), win);
    
    GtkWidget *outputFileLabel = gtk_label_new ("Output File Path");
    guiSt.outputFileNameBox = gtk_entry_new ();
    gtk_widget_set_tooltip_text (guiSt.outputFileNameBox, "Enter the full path to where you want to save the result of encryption/decryption");
    GtkWidget *outputFileButton = gtk_button_new_with_label ("Select File");
    gtk_widget_set_tooltip_text (outputFileButton, "Select where you want to save the result of encryption/decryption to fill in this path");
    g_signal_connect (outputFileButton, "clicked", G_CALLBACK (outputFileSelect), win);
    
    GtkWidget *passwordLabel = gtk_label_new ("Password");
    guiSt.passwordBox = gtk_entry_new ();
    gtk_widget_set_tooltip_text (guiSt.passwordBox, "Password to derive key from");
    gtk_entry_set_invisible_char(GTK_ENTRY (guiSt.passwordBox),'*');
    gtk_entry_set_visibility(GTK_ENTRY (guiSt.passwordBox), FALSE);
    
    GtkWidget *verificationLabel = gtk_label_new ("Verify Password");
    guiSt.passwordVerificationBox = gtk_entry_new ();
    gtk_widget_set_tooltip_text (guiSt.passwordVerificationBox, "Note: Not needed for decryption");
    gtk_entry_set_invisible_char(GTK_ENTRY (guiSt.passwordVerificationBox),'*');
    gtk_entry_set_visibility(GTK_ENTRY (guiSt.passwordVerificationBox), FALSE);
    
    GtkWidget *scryptWorkFactorsLabel = gtk_label_new ("scrypt work factors:");
    
    GtkWidget *nFactorLabel = gtk_label_new ("N Factor");
    GtkAdjustment *nFactorSpinButtonAdj = gtk_adjustment_new (DEFAULT_SCRYPT_N, 0, DEFAULT_SCRYPT_N * 8, 1048576, 0, 0);
    guiSt.nFactorTextBox = gtk_spin_button_new (GTK_ADJUSTMENT (nFactorSpinButtonAdj), 0, 0);
    gtk_widget_set_tooltip_text (guiSt.nFactorTextBox, "This is the N factor that will be used by scrypt");
    
    GtkWidget *rFactorLabel = gtk_label_new ("r Factor");
    GtkAdjustment *rFactorSpinButtonAdj = gtk_adjustment_new (DEFAULT_SCRYPT_R, 0, 10, 1, 0, 0);
    guiSt.rFactorTextBox = gtk_spin_button_new (GTK_ADJUSTMENT (rFactorSpinButtonAdj), 0, 0);
    gtk_widget_set_tooltip_text (guiSt.rFactorTextBox, "This is the r factor that will be used by scrypt");
    
    GtkWidget *pFactorLabel = gtk_label_new ("p Factor");
    GtkAdjustment *pFactorSpinButtonAdj = gtk_adjustment_new (DEFAULT_SCRYPT_P, 0, 10, 1, 0, 0);
    guiSt.pFactorTextBox = gtk_spin_button_new (GTK_ADJUSTMENT (pFactorSpinButtonAdj), 0, 0);
    gtk_widget_set_tooltip_text (guiSt.pFactorTextBox, "This is the p factor that will be used by scrypt");
    
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
    guiSt.keySizeComboBox = gtk_combo_box_text_new ();
    gtk_widget_set_tooltip_text (guiSt.keySizeComboBox, "This controls the size of the key that will be derived from the password");
    gtk_combo_box_text_append_text (GTK_COMBO_BOX_TEXT (guiSt.keySizeComboBox), "16 bytes");
    gtk_combo_box_text_append_text (GTK_COMBO_BOX_TEXT (guiSt.keySizeComboBox), "32 bytes");
    gtk_combo_box_text_append_text (GTK_COMBO_BOX_TEXT (guiSt.keySizeComboBox), "64 bytes");
    gtk_combo_box_text_append_text (GTK_COMBO_BOX_TEXT (guiSt.keySizeComboBox), "128 bytes");
    gtk_combo_box_text_append_text (GTK_COMBO_BOX_TEXT (guiSt.keySizeComboBox), "256 bytes");
    gtk_combo_box_text_append_text (GTK_COMBO_BOX_TEXT (guiSt.keySizeComboBox), "512 bytes");
    gtk_combo_box_text_append_text (GTK_COMBO_BOX_TEXT (guiSt.keySizeComboBox), "2 Kb");
    gtk_combo_box_text_append_text (GTK_COMBO_BOX_TEXT (guiSt.keySizeComboBox), "4 Kb");
    gtk_combo_box_text_append_text (GTK_COMBO_BOX_TEXT (guiSt.keySizeComboBox), "8 Kb");
    gtk_combo_box_text_append_text (GTK_COMBO_BOX_TEXT (guiSt.keySizeComboBox), "16 Kb");
    gtk_combo_box_text_append_text (GTK_COMBO_BOX_TEXT (guiSt.keySizeComboBox), "32 Kb");
    gtk_combo_box_text_append_text (GTK_COMBO_BOX_TEXT (guiSt.keySizeComboBox), "64 Kb");
    gtk_combo_box_text_append_text (GTK_COMBO_BOX_TEXT (guiSt.keySizeComboBox), "128 Kb");
    gtk_combo_box_text_append_text (GTK_COMBO_BOX_TEXT (guiSt.keySizeComboBox), "256 Kb");
    gtk_combo_box_text_append_text (GTK_COMBO_BOX_TEXT (guiSt.keySizeComboBox), "512 Kb");
    gtk_combo_box_text_append_text (GTK_COMBO_BOX_TEXT (guiSt.keySizeComboBox), "1 Mb");
    gtk_combo_box_text_append_text (GTK_COMBO_BOX_TEXT (guiSt.keySizeComboBox), "2 Mb");
    gtk_combo_box_text_append_text (GTK_COMBO_BOX_TEXT (guiSt.keySizeComboBox), "4 Mb");
    gtk_combo_box_text_append_text (GTK_COMBO_BOX_TEXT (guiSt.keySizeComboBox), "8 Mb");
    gtk_combo_box_text_append_text (GTK_COMBO_BOX_TEXT (guiSt.keySizeComboBox), "16 Mb");
    gtk_combo_box_text_append_text (GTK_COMBO_BOX_TEXT (guiSt.keySizeComboBox), "32 Mb");
    gtk_combo_box_text_append_text (GTK_COMBO_BOX_TEXT (guiSt.keySizeComboBox), "64 Mb");
    gtk_combo_box_text_append_text (GTK_COMBO_BOX_TEXT (guiSt.keySizeComboBox), "128 Mb");
    gtk_combo_box_text_append_text (GTK_COMBO_BOX_TEXT (guiSt.keySizeComboBox), "256 Mb");
    gtk_combo_box_text_append_text (GTK_COMBO_BOX_TEXT (guiSt.keySizeComboBox), "512 Mb");
    gtk_combo_box_set_active (GTK_COMBO_BOX (guiSt.keySizeComboBox), 20);
    
    GtkWidget *visibilityButton = gtk_check_button_new_with_label ("Show Password");
    gtk_widget_set_tooltip_text (visibilityButton, "Hint: Use this to avoid typos");
    gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON (visibilityButton), FALSE);
    g_signal_connect (visibilityButton, "toggled", G_CALLBACK (passVisibilityToggle),NULL);
    
    GtkWidget *keyFileLabel = gtk_label_new ("Key File Path");
    guiSt.keyFileNameBox = gtk_entry_new ();
    g_signal_connect (guiSt.keyFileNameBox, "insert-text", G_CALLBACK (otpFileEntryDisable), NULL);
    g_signal_connect (guiSt.keyFileNameBox, "delete-text", G_CALLBACK (otpFileEntryEnable), NULL);
    gtk_widget_set_tooltip_text (guiSt.keyFileNameBox, "Enter the full path to the key you want to use here");
    guiSt.keyFileButton = gtk_button_new_with_label ("Select File");
    gtk_widget_set_tooltip_text (guiSt.keyFileButton, "Select the key file you want to use here");
    g_signal_connect (guiSt.keyFileButton, "clicked", G_CALLBACK (keyFileSelect), win);
    g_signal_connect (guiSt.keyFileButton, "clicked", G_CALLBACK (otpFileEntryDisable), NULL);
    
    GtkWidget *otpFileLabel = gtk_label_new ("One-Time-Pad File Path");
    guiSt.otpFileNameBox = gtk_entry_new ();
    g_signal_connect (guiSt.otpFileNameBox, "insert-text", G_CALLBACK (keyFileEntryDisable), NULL);
    g_signal_connect (guiSt.otpFileNameBox, "delete-text", G_CALLBACK (keyFileEntryEnable), NULL);
    guiSt.otpFileButton = gtk_button_new_with_label ("Select File");
    gtk_widget_set_tooltip_text (guiSt.otpFileButton, "Select the one-time-pad file you want to use here");
    g_signal_connect (guiSt.otpFileButton, "clicked", G_CALLBACK (otpFileSelect), win);
    g_signal_connect (guiSt.otpFileButton, "clicked", G_CALLBACK (keyFileEntryDisable), NULL);
    
    gtk_widget_set_tooltip_text (guiSt.otpFileNameBox, "Enter the full path to the one-time-pad you want to use here\
    \n\n\
    Using a one-time-pad means using something like /dev/urandom or another random-number generator\
    to produce a keystream that will be as long as the file being encrypted is. This cannot be used\
    in conjunction with a regular key, and the one-time-pad will be saved in the same directory as\
    the input file, under the same name, but with a .pad extension\
    \n***Very Important:*** Must use same size buffers between encryption and decryption");
    
    GtkWidget *macBufSizeLabel = gtk_label_new ("Authentication Buffer Size");
    guiSt.macBufSizeComboBox = gtk_combo_box_text_new ();
    gtk_widget_set_tooltip_text (guiSt.macBufSizeComboBox, "This controls the size of the buffer used for authenticating data");
    gtk_combo_box_text_append_text (GTK_COMBO_BOX_TEXT (guiSt.macBufSizeComboBox), "1 byte");
    gtk_combo_box_text_append_text (GTK_COMBO_BOX_TEXT (guiSt.macBufSizeComboBox), "2 bytes");
    gtk_combo_box_text_append_text (GTK_COMBO_BOX_TEXT (guiSt.macBufSizeComboBox), "4 bytes");
    gtk_combo_box_text_append_text (GTK_COMBO_BOX_TEXT (guiSt.macBufSizeComboBox), "8 bytes");
    gtk_combo_box_text_append_text (GTK_COMBO_BOX_TEXT (guiSt.macBufSizeComboBox), "16 bytes");
    gtk_combo_box_text_append_text (GTK_COMBO_BOX_TEXT (guiSt.macBufSizeComboBox), "32 bytes");
    gtk_combo_box_text_append_text (GTK_COMBO_BOX_TEXT (guiSt.macBufSizeComboBox), "64 bytes");
    gtk_combo_box_text_append_text (GTK_COMBO_BOX_TEXT (guiSt.macBufSizeComboBox), "128 bytes");
    gtk_combo_box_text_append_text (GTK_COMBO_BOX_TEXT (guiSt.macBufSizeComboBox), "256 bytes");
    gtk_combo_box_text_append_text (GTK_COMBO_BOX_TEXT (guiSt.macBufSizeComboBox), "512 bytes");
    gtk_combo_box_text_append_text (GTK_COMBO_BOX_TEXT (guiSt.macBufSizeComboBox), "1 Kb");
    gtk_combo_box_text_append_text (GTK_COMBO_BOX_TEXT (guiSt.macBufSizeComboBox), "2 Kb");
    gtk_combo_box_text_append_text (GTK_COMBO_BOX_TEXT (guiSt.macBufSizeComboBox), "4 Kb");
    gtk_combo_box_text_append_text (GTK_COMBO_BOX_TEXT (guiSt.macBufSizeComboBox), "8 Kb");
    gtk_combo_box_text_append_text (GTK_COMBO_BOX_TEXT (guiSt.macBufSizeComboBox), "16 Kb");
    gtk_combo_box_text_append_text (GTK_COMBO_BOX_TEXT (guiSt.macBufSizeComboBox), "32 Kb");
    gtk_combo_box_text_append_text (GTK_COMBO_BOX_TEXT (guiSt.macBufSizeComboBox), "64 Kb");
    gtk_combo_box_text_append_text (GTK_COMBO_BOX_TEXT (guiSt.macBufSizeComboBox), "128 Kb");
    gtk_combo_box_text_append_text (GTK_COMBO_BOX_TEXT (guiSt.macBufSizeComboBox), "256 Kb");
    gtk_combo_box_text_append_text (GTK_COMBO_BOX_TEXT (guiSt.macBufSizeComboBox), "512 Kb");
    gtk_combo_box_text_append_text (GTK_COMBO_BOX_TEXT (guiSt.macBufSizeComboBox), "1 Mb");
    gtk_combo_box_text_append_text (GTK_COMBO_BOX_TEXT (guiSt.macBufSizeComboBox), "2 Mb");
    gtk_combo_box_text_append_text (GTK_COMBO_BOX_TEXT (guiSt.macBufSizeComboBox), "4 Mb");
    gtk_combo_box_text_append_text (GTK_COMBO_BOX_TEXT (guiSt.macBufSizeComboBox), "8 Mb");
    gtk_combo_box_text_append_text (GTK_COMBO_BOX_TEXT (guiSt.macBufSizeComboBox), "16 Mb");
    gtk_combo_box_text_append_text (GTK_COMBO_BOX_TEXT (guiSt.macBufSizeComboBox), "32 Mb");
    gtk_combo_box_text_append_text (GTK_COMBO_BOX_TEXT (guiSt.macBufSizeComboBox), "64 Mb");
    gtk_combo_box_text_append_text (GTK_COMBO_BOX_TEXT (guiSt.macBufSizeComboBox), "128 Mb");
    gtk_combo_box_text_append_text (GTK_COMBO_BOX_TEXT (guiSt.macBufSizeComboBox), "256 Mb");
    gtk_combo_box_text_append_text (GTK_COMBO_BOX_TEXT (guiSt.macBufSizeComboBox), "512 Mb");
    gtk_combo_box_text_append_text (GTK_COMBO_BOX_TEXT (guiSt.macBufSizeComboBox), "1 Gb");
    gtk_combo_box_text_append_text (GTK_COMBO_BOX_TEXT (guiSt.macBufSizeComboBox), "2 Gb");
    gtk_combo_box_text_append_text (GTK_COMBO_BOX_TEXT (guiSt.macBufSizeComboBox), "4 Gb");
    gtk_combo_box_text_append_text (GTK_COMBO_BOX_TEXT (guiSt.macBufSizeComboBox), "8 Gb");
    gtk_combo_box_set_active (GTK_COMBO_BOX (guiSt.macBufSizeComboBox), 20);
    
    GtkWidget *msgBufSizeLabel = gtk_label_new ("File Buffer Size");
    guiSt.msgBufSizeComboBox = gtk_combo_box_text_new ();
    gtk_widget_set_tooltip_text (guiSt.msgBufSizeComboBox, "This controls the size of the buffer used for encryption/decryption data");
    gtk_combo_box_text_append_text (GTK_COMBO_BOX_TEXT (guiSt.msgBufSizeComboBox), "1 byte");
    gtk_combo_box_text_append_text (GTK_COMBO_BOX_TEXT (guiSt.msgBufSizeComboBox), "2 bytes");
    gtk_combo_box_text_append_text (GTK_COMBO_BOX_TEXT (guiSt.msgBufSizeComboBox), "4 bytes");
    gtk_combo_box_text_append_text (GTK_COMBO_BOX_TEXT (guiSt.msgBufSizeComboBox), "8 bytes");
    gtk_combo_box_text_append_text (GTK_COMBO_BOX_TEXT (guiSt.msgBufSizeComboBox), "16 bytes");
    gtk_combo_box_text_append_text (GTK_COMBO_BOX_TEXT (guiSt.msgBufSizeComboBox), "32 bytes");
    gtk_combo_box_text_append_text (GTK_COMBO_BOX_TEXT (guiSt.msgBufSizeComboBox), "64 bytes");
    gtk_combo_box_text_append_text (GTK_COMBO_BOX_TEXT (guiSt.msgBufSizeComboBox), "128 bytes");
    gtk_combo_box_text_append_text (GTK_COMBO_BOX_TEXT (guiSt.msgBufSizeComboBox), "256 bytes");
    gtk_combo_box_text_append_text (GTK_COMBO_BOX_TEXT (guiSt.msgBufSizeComboBox), "512 bytes");
    gtk_combo_box_text_append_text (GTK_COMBO_BOX_TEXT (guiSt.msgBufSizeComboBox), "1 Kb");
    gtk_combo_box_text_append_text (GTK_COMBO_BOX_TEXT (guiSt.msgBufSizeComboBox), "2 Kb");
    gtk_combo_box_text_append_text (GTK_COMBO_BOX_TEXT (guiSt.msgBufSizeComboBox), "4 Kb");
    gtk_combo_box_text_append_text (GTK_COMBO_BOX_TEXT (guiSt.msgBufSizeComboBox), "8 Kb");
    gtk_combo_box_text_append_text (GTK_COMBO_BOX_TEXT (guiSt.msgBufSizeComboBox), "16 Kb");
    gtk_combo_box_text_append_text (GTK_COMBO_BOX_TEXT (guiSt.msgBufSizeComboBox), "32 Kb");
    gtk_combo_box_text_append_text (GTK_COMBO_BOX_TEXT (guiSt.msgBufSizeComboBox), "64 Kb");
    gtk_combo_box_text_append_text (GTK_COMBO_BOX_TEXT (guiSt.msgBufSizeComboBox), "128 Kb");
    gtk_combo_box_text_append_text (GTK_COMBO_BOX_TEXT (guiSt.msgBufSizeComboBox), "256 Kb");
    gtk_combo_box_text_append_text (GTK_COMBO_BOX_TEXT (guiSt.msgBufSizeComboBox), "512 Kb");
    gtk_combo_box_text_append_text (GTK_COMBO_BOX_TEXT (guiSt.msgBufSizeComboBox), "1 Mb");
    gtk_combo_box_text_append_text (GTK_COMBO_BOX_TEXT (guiSt.msgBufSizeComboBox), "2 Mb");
    gtk_combo_box_text_append_text (GTK_COMBO_BOX_TEXT (guiSt.msgBufSizeComboBox), "4 Mb");
    gtk_combo_box_text_append_text (GTK_COMBO_BOX_TEXT (guiSt.msgBufSizeComboBox), "8 Mb");
    gtk_combo_box_text_append_text (GTK_COMBO_BOX_TEXT (guiSt.msgBufSizeComboBox), "16 Mb");
    gtk_combo_box_text_append_text (GTK_COMBO_BOX_TEXT (guiSt.msgBufSizeComboBox), "32 Mb");
    gtk_combo_box_text_append_text (GTK_COMBO_BOX_TEXT (guiSt.msgBufSizeComboBox), "64 Mb");
    gtk_combo_box_text_append_text (GTK_COMBO_BOX_TEXT (guiSt.msgBufSizeComboBox), "128 Mb");
    gtk_combo_box_text_append_text (GTK_COMBO_BOX_TEXT (guiSt.msgBufSizeComboBox), "256 Mb");
    gtk_combo_box_text_append_text (GTK_COMBO_BOX_TEXT (guiSt.msgBufSizeComboBox), "512 Mb");
    gtk_combo_box_text_append_text (GTK_COMBO_BOX_TEXT (guiSt.msgBufSizeComboBox), "1 Gb");
    gtk_combo_box_text_append_text (GTK_COMBO_BOX_TEXT (guiSt.msgBufSizeComboBox), "2 Gb");
    gtk_combo_box_text_append_text (GTK_COMBO_BOX_TEXT (guiSt.msgBufSizeComboBox), "4 Gb");
    gtk_combo_box_text_append_text (GTK_COMBO_BOX_TEXT (guiSt.msgBufSizeComboBox), "8 Gb");
    gtk_combo_box_set_active (GTK_COMBO_BOX (guiSt.msgBufSizeComboBox), 20);
    
    GtkWidget *encryptButton = gtk_button_new_with_label ("Encrypt");
    g_signal_connect (encryptButton, "clicked", G_CALLBACK (on_cryptButton_clicked), (gpointer)"encrypt");
        
    GtkWidget *decryptButton = gtk_button_new_with_label ("Decrypt");
    g_signal_connect (decryptButton, "clicked", G_CALLBACK (on_cryptButton_clicked), (gpointer)"decrypt");
    
    progressSt.progressBar = gtk_progress_bar_new ();
    gtk_progress_bar_set_text (GTK_PROGRESS_BAR (progressSt.progressBar), "Step Progress");
    gtk_progress_bar_set_show_text (GTK_PROGRESS_BAR (progressSt.progressBar), TRUE);
    *progressSt.progressFraction = 0.0;
    g_timeout_add (50, updateProgress, NULL);
    
    progressSt.overallProgressBar = gtk_progress_bar_new ();
    gtk_progress_bar_set_text (GTK_PROGRESS_BAR (progressSt.overallProgressBar), "Overall Progress");
    gtk_progress_bar_set_show_text (GTK_PROGRESS_BAR (progressSt.overallProgressBar), TRUE);
    *progressSt.overallProgressFraction = 0.0;
    g_timeout_add (50, updateOverallProgress, NULL);
    
    progressSt.statusBar = gtk_statusbar_new ();
    gtk_widget_set_tooltip_text (progressSt.statusBar, "Program will show status updates here");
    strcpy(progressSt.statusMessage,"Ready");
    g_timeout_add (50, updateStatus, progressSt.statusMessage);
    
    GtkWidget *grid = gtk_grid_new();
    gtk_widget_set_hexpand (inputFileLabel, TRUE);
    gtk_grid_attach (GTK_GRID (grid), inputFileLabel, 0, 0, 1, 1);
    gtk_grid_attach (GTK_GRID (grid), guiSt.inputFileNameBox, 0, 2, 1, 1);
    gtk_grid_attach (GTK_GRID (grid), inputFileButton, 1, 2, 1, 1);
    gtk_grid_attach (GTK_GRID (grid), outputFileLabel, 0, 4, 1, 1);
    gtk_grid_attach (GTK_GRID (grid), guiSt.outputFileNameBox, 0, 5, 1, 1);
    gtk_grid_attach (GTK_GRID (grid), outputFileButton, 1, 5, 1, 1);
    gtk_grid_attach (GTK_GRID (grid), passwordLabel, 0, 7, 1, 1);
    gtk_grid_attach (GTK_GRID (grid), guiSt.passwordBox, 0, 8, 1, 1);
    gtk_grid_attach (GTK_GRID (grid), visibilityButton, 1, 8, 1, 1);
    gtk_grid_attach (GTK_GRID (grid), verificationLabel, 0, 9, 1, 1);
    gtk_grid_attach (GTK_GRID (grid), keySizeLabel, 0, 11, 1, 1);
    gtk_grid_attach (GTK_GRID (grid), guiSt.keySizeComboBox, 1, 11, 1, 1);
    gtk_grid_attach (GTK_GRID (grid), guiSt.passwordVerificationBox, 0, 10, 1, 1);
    gtk_grid_attach (GTK_GRID (grid), scryptWorkFactorsLabel, 0, 12, 1, 1);
    gtk_grid_attach (GTK_GRID (grid), nFactorLabel, 0, 13, 1, 1);
    gtk_grid_attach (GTK_GRID (grid), guiSt.nFactorTextBox, 1, 13, 1, 1);
    gtk_grid_attach (GTK_GRID (grid), rFactorLabel, 0, 15, 1, 1);
    gtk_grid_attach (GTK_GRID (grid), guiSt.rFactorTextBox, 1, 15, 1, 1);
    gtk_grid_attach (GTK_GRID (grid), pFactorLabel, 0, 17, 1, 1);
    gtk_grid_attach (GTK_GRID (grid), guiSt.pFactorTextBox, 1, 17, 1, 1);
    gtk_grid_attach (GTK_GRID (grid), keyFileLabel, 0, 18, 1, 1);
    gtk_grid_attach (GTK_GRID (grid), guiSt.keyFileNameBox, 0, 19, 1, 1);
    gtk_grid_attach (GTK_GRID (grid), guiSt.keyFileButton, 1, 19, 1, 1);
    gtk_grid_attach (GTK_GRID (grid), otpFileLabel, 0, 20, 1, 1);
    gtk_grid_attach (GTK_GRID (grid), guiSt.otpFileNameBox, 0, 21, 1, 1);
    gtk_grid_attach (GTK_GRID (grid), guiSt.otpFileButton, 1, 21, 1, 1);
    gtk_grid_attach (GTK_GRID (grid), macBufSizeLabel, 0, 24, 1, 1);
    gtk_grid_attach (GTK_GRID (grid), guiSt.macBufSizeComboBox, 0, 25, 1, 1);
    gtk_grid_attach (GTK_GRID (grid), msgBufSizeLabel, 1, 24, 1, 1);
    gtk_grid_attach (GTK_GRID (grid), guiSt.msgBufSizeComboBox, 1, 25, 1, 1);
    gtk_grid_attach (GTK_GRID (grid), encryptButton, 0, 26, 2, 1);
    gtk_grid_attach (GTK_GRID (grid), decryptButton, 0, 27, 2, 1);
    gtk_grid_attach (GTK_GRID (grid), progressSt.progressBar, 0, 28, 2, 1);
    gtk_grid_attach (GTK_GRID (grid), progressSt.overallProgressBar, 0, 29, 2, 1);
    gtk_grid_attach (GTK_GRID (grid), progressSt.statusBar, 0, 30, 2, 1);
    
    
    gtk_container_add (GTK_CONTAINER (win), grid);
    
    g_signal_connect (win, "delete_event", G_CALLBACK (gtk_main_quit), NULL);
    
    gtk_widget_show_all (win);
    gtk_main ();

    exit(EXIT_SUCCESS);
}

static gboolean updateStatus(gpointer user_data)
{
    progressSt.statusContextID = gtk_statusbar_get_context_id (GTK_STATUSBAR (progressSt.statusBar), "Statusbar");
    gtk_statusbar_push (GTK_STATUSBAR (progressSt.statusBar), GPOINTER_TO_INT (progressSt.statusContextID), progressSt.statusMessage);
    
    return TRUE;
}

static gboolean updateProgress(gpointer user_data)
{
    gtk_progress_bar_set_fraction (GTK_PROGRESS_BAR (progressSt.progressBar), *progressSt.progressFraction);
    if(*progressSt.progressFraction > 1)
        *progressSt.progressFraction = 0.0;
        
    return TRUE;
}

static gboolean updateOverallProgress(gpointer user_data)
{
    gtk_progress_bar_set_fraction (GTK_PROGRESS_BAR (progressSt.overallProgressBar), *progressSt.overallProgressFraction);
    if(*progressSt.overallProgressFraction > 1)
        *progressSt.overallProgressFraction = 0.0;
        
    return TRUE;
}

void on_cryptButton_clicked(GtkWidget *wid, gpointer ptr) {
    char *encryptOrDecrypt = (char *)ptr;
    
    keyFileEntryEnable();
    otpFileEntryEnable();
    
    gboolean passwordsMatch = FALSE;
    gboolean error = FALSE;
    
    guiSt.inputFilePath = gtk_entry_get_text (GTK_ENTRY (guiSt.inputFileNameBox));
    guiSt.outputFilePath = gtk_entry_get_text (GTK_ENTRY (guiSt.outputFileNameBox));
    guiSt.passWord = gtk_entry_get_text (GTK_ENTRY (guiSt.passwordBox));
    guiSt.verificationPass = gtk_entry_get_text (GTK_ENTRY (guiSt.passwordVerificationBox));
    guiSt.keyFilePath = gtk_entry_get_text (GTK_ENTRY (guiSt.keyFileNameBox));
    guiSt.otpFilePath = gtk_entry_get_text (GTK_ENTRY (guiSt.otpFileNameBox));
    guiSt.keySizeComboBoxText = gtk_combo_box_text_get_active_text (GTK_COMBO_BOX_TEXT (guiSt.keySizeComboBox));
    guiSt.macBufSizeComboBoxText = gtk_combo_box_text_get_active_text (GTK_COMBO_BOX_TEXT (guiSt.macBufSizeComboBox));
    guiSt.msgBufSizeComboBoxText = gtk_combo_box_text_get_active_text (GTK_COMBO_BOX_TEXT (guiSt.msgBufSizeComboBox));
    
    if(strlen(guiSt.inputFilePath)) {
        optSt.inputFileGiven = true;
        strcpy(fileSt.inputFileName,guiSt.inputFilePath);
    } else {
        strcpy(progressSt.statusMessage,"Need input file...");
        error = TRUE;
    }
    
    if(strlen(guiSt.outputFilePath)) {
        optSt.outputFileGiven = true;
        strcpy(fileSt.outputFileName,guiSt.outputFilePath);
    } else {
        strcpy(progressSt.statusMessage,"Need output file...");
        error = TRUE;
    }
    
    if(!strcmp(guiSt.inputFilePath,guiSt.outputFilePath)) {
        strcpy(progressSt.statusMessage,"Input and output file are the same...");
        error = TRUE;
    }
        
    cryptSt.nFactor = gtk_spin_button_get_value_as_int (GTK_SPIN_BUTTON(guiSt.nFactorTextBox));
    cryptSt.rFactor = gtk_spin_button_get_value_as_int (GTK_SPIN_BUTTON(guiSt.rFactorTextBox));
    cryptSt.pFactor = gtk_spin_button_get_value_as_int (GTK_SPIN_BUTTON(guiSt.pFactorTextBox));
    
    sizesSt.keyBufSize = atol(guiSt.keySizeComboBoxText) * sizeof(uint8_t) * getBufSizeMultiple((char *)guiSt.keySizeComboBoxText);
    sizesSt.yaxaSaltSize = sizesSt.keyBufSize / YAXA_KEY_CHUNK_SIZE;

    sizesSt.genHmacBufSize = atol(guiSt.macBufSizeComboBoxText) * sizeof(uint8_t) * getBufSizeMultiple((char *)guiSt.macBufSizeComboBoxText);
    makeMultipleOf(&sizesSt.genHmacBufSize,sizeof(cryptint_t));
    
    sizesSt.msgBufSize = atol(guiSt.msgBufSizeComboBoxText) * sizeof(uint8_t) * getBufSizeMultiple((char *)guiSt.msgBufSizeComboBoxText);
    makeMultipleOf(&sizesSt.msgBufSize,sizeof(cryptint_t));
    
    if(strlen(guiSt.passWord)) {
        optSt.passWordGiven = true;
    } else {
        optSt.passWordGiven = false;
    }
    
    if(strlen(guiSt.keyFilePath)) {
        optSt.keyFileGiven = true;
        strcpy(fileSt.keyFileName,guiSt.keyFilePath);
        sizesSt.keyFileSize = getFileSize(fileSt.keyFileName);
        sizesSt.keyBufSize = sizesSt.keyFileSize;
        sizesSt.yaxaSaltSize = sizesSt.keyBufSize / YAXA_KEY_CHUNK_SIZE;
    } else {
        optSt.keyFileGiven = false;
    }
    
    if(strlen(guiSt.otpFilePath)) {
        optSt.oneTimePad = true;
        sizesSt.yaxaSaltSize = 0;
        strcpy(fileSt.otpInFileName,guiSt.otpFilePath);
        snprintf(fileSt.otpOutFileName, NAME_MAX, "%s", guiSt.otpFilePath);
        sprintf(fileSt.otpOutFileName,"%s.pad", guiSt.outputFilePath);
    } else {
        optSt.oneTimePad = false;
    }
    
    if((optSt.passWordGiven && optSt.keyFileGiven) || (optSt.passWordGiven && optSt.oneTimePad)) {
        sizesSt.yaxaSaltSize = sizesSt.keyBufSize / YAXA_KEY_CHUNK_SIZE;
    } else if (optSt.oneTimePad || optSt.keyFileGiven) {
        sizesSt.yaxaSaltSize = 0;
    }
    
    if(!optSt.passWordGiven && !optSt.keyFileGiven && !optSt.oneTimePad) {
        strcpy(progressSt.statusMessage,"Need at least password, keyfile or one-time-pad");
        error = TRUE;
    }
    
    if(strcmp(encryptOrDecrypt,"encrypt") == 0) {
        if(optSt.passWordGiven) {
            guiSt.verificationPass = gtk_entry_get_text (GTK_ENTRY (guiSt.passwordVerificationBox));
            if(strcmp(guiSt.passWord,guiSt.verificationPass) == 0)
                passwordsMatch = TRUE;
            
            if (passwordsMatch == FALSE) {
                strcpy(progressSt.statusMessage,"Passwords didn't match");
                error = TRUE;
            } else if(passwordsMatch == TRUE) {
                snprintf(cryptSt.userPass,MAX_PASS_SIZE,"%s",guiSt.passWord);
            
                gtk_entry_set_text(GTK_ENTRY (guiSt.passwordBox), "");
                OPENSSL_cleanse((void *)guiSt.passWord, strlen(guiSt.passWord));
                gtk_entry_set_text(GTK_ENTRY (guiSt.passwordBox), guiSt.passWord);
                
                gtk_entry_set_text(GTK_ENTRY (guiSt.passwordVerificationBox), "");
                OPENSSL_cleanse((void *)guiSt.verificationPass, strlen(guiSt.verificationPass));
                gtk_entry_set_text(GTK_ENTRY (guiSt.passwordVerificationBox), guiSt.verificationPass);
            }
        }
    } else if (strcmp(encryptOrDecrypt,"decrypt") == 0) {
        snprintf(cryptSt.userPass,MAX_PASS_SIZE,"%s",guiSt.passWord);
    
        gtk_entry_set_text(GTK_ENTRY (guiSt.passwordBox), "");
        OPENSSL_cleanse((void *)guiSt.passWord, strlen(guiSt.passWord));
        gtk_entry_set_text(GTK_ENTRY (guiSt.passwordBox), guiSt.passWord);
        
        if(strlen(guiSt.verificationPass)) {
            gtk_entry_set_text(GTK_ENTRY (guiSt.passwordVerificationBox), "");
            OPENSSL_cleanse((void *)guiSt.verificationPass, strlen(guiSt.verificationPass));
            gtk_entry_set_text(GTK_ENTRY (guiSt.passwordVerificationBox), guiSt.verificationPass);
        }
    }
    
    if(optSt.keyFileGiven && optSt.oneTimePad) {
        strcpy(progressSt.statusMessage,"Can only use keyfile OR one-time-pad");
        error = TRUE;
    }
    
    if(error != TRUE) {
        if(strcmp(encryptOrDecrypt,"encrypt") == 0) {
            strcpy(progressSt.statusMessage,"Starting encryption...");
            workThread('e',optSt);
        } else if (strcmp(encryptOrDecrypt,"decrypt") == 0) {
            strcpy(progressSt.statusMessage,"Starting decryption...");
            workThread('d',optSt);
        }
    }
    
    OPENSSL_cleanse((void *)cryptSt.userPass, strlen(cryptSt.userPass));
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
        gtk_entry_set_text(GTK_ENTRY (guiSt.inputFileNameBox), fileName);
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
        gtk_entry_set_text(GTK_ENTRY (guiSt.outputFileNameBox), fileName);
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
        gtk_entry_set_text(GTK_ENTRY (guiSt.keyFileNameBox), fileName);
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
        gtk_entry_set_text(GTK_ENTRY (guiSt.otpFileNameBox), fileName);
      }
    
    gtk_widget_destroy (dialog);
}

void passVisibilityToggle (GtkWidget *wid, gpointer ptr)
{
    gtk_entry_set_visibility(GTK_ENTRY (guiSt.passwordBox), gtk_toggle_button_get_active (GTK_TOGGLE_BUTTON (wid)));
    gtk_entry_set_visibility(GTK_ENTRY (guiSt.passwordVerificationBox), gtk_toggle_button_get_active (GTK_TOGGLE_BUTTON (wid)));
}

void otpFileEntryDisable (void)
{
    gtk_editable_set_editable(GTK_EDITABLE(guiSt.otpFileNameBox), FALSE);
    gtk_widget_set_sensitive (GTK_WIDGET(guiSt.otpFileButton), FALSE);

}

void keyFileEntryDisable (void)
{
    gtk_editable_set_editable(GTK_EDITABLE(guiSt.keyFileNameBox), FALSE);
    gtk_widget_set_sensitive (GTK_WIDGET(guiSt.keyFileButton), FALSE);

}

void otpFileEntryEnable (void)
{
    gtk_editable_set_editable(GTK_EDITABLE(guiSt.otpFileNameBox), TRUE);
    gtk_widget_set_sensitive (GTK_WIDGET(guiSt.otpFileButton), TRUE);

}

void keyFileEntryEnable (void)
{
    gtk_editable_set_editable(GTK_EDITABLE(guiSt.keyFileNameBox), TRUE);
    gtk_widget_set_sensitive (GTK_WIDGET(guiSt.keyFileButton), TRUE);

}

