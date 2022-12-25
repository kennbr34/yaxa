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
void choseEncrypt(GtkWidget *wid, gpointer ptr);
void choseDecrypt(GtkWidget *wid, gpointer ptr);
static void inputFileSelect (GtkWidget *wid, gpointer ptr);
static void outputFileSelect (GtkWidget *wid, gpointer ptr);
static void keyFileSelect (GtkWidget *wid, gpointer ptr);
static void otpFileSelect (GtkWidget *wid, gpointer ptr);
void passVisibilityToggle (GtkWidget *wid, gpointer ptr);
void otpFileEntryDisable (GtkWidget *wid, gpointer ptr);
void keyFileEntryDisable (GtkWidget *wid, gpointer ptr);
void otpFileEntryEnable (GtkWidget *wid, gpointer ptr);
void keyFileEntryEnable (GtkWidget *wid, gpointer ptr);
static gboolean updateStatus(gpointer user_data);
static gboolean updateProgress(gpointer user_data);
static gboolean updateOverallProgress(gpointer user_data);

int main(int argc, char *argv[])
{
    static struct dataStruct st = {0};
    
    //struct dataStruct *st = g_new0(struct dataStruct, 1);
    
    st.nFactor = DEFAULT_SCRYPT_N;
    st.pFactor = DEFAULT_SCRYPT_P;
    st.rFactor = DEFAULT_SCRYPT_R;
    st.k = 0;
    
    st.keyBufSize = YAXA_KEYBUF_SIZE;
    st.genHmacBufSize = 1024 * 1024;
    st.msgBufSize = 1024 * 1024;
    st.yaxaSaltSize = YAXA_KEYBUF_SIZE / YAXA_KEY_CHUNK_SIZE;

    /*These must be mapped as shared memory for the worker thread to manipulate their values in the main thread*/
    st.statusMessage = mmap(NULL, 256, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    st.progressFraction = mmap(NULL, sizeof(double), PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    st.overallProgressFraction = mmap(NULL, sizeof(double), PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    
    //signal(SIGINT, signalHandler);

    //atexit(cleanUpBuffers);

    allocateBuffers(&st);

    OpenSSL_add_all_algorithms();
    
    gtk_init (&argc, &argv);
    
    GtkWidget *win = gtk_window_new (GTK_WINDOW_TOPLEVEL);
    
    gtk_window_set_title(GTK_WINDOW (win), "YAXA File Encryption Utility");
    
    GtkWidget *inputFileLabel = gtk_label_new ("Input File Path");
    st.inputFileNameBox = gtk_entry_new ();
    gtk_widget_set_tooltip_text (st.inputFileNameBox, "Enter the full path to the file you want to encrypt/decrypt here");
    GtkWidget *inputFileButton = gtk_button_new_with_label ("Select File");
    gtk_widget_set_tooltip_text (inputFileButton, "Select the file you want to encrypt/decrypt to fill in this path");
    g_signal_connect (inputFileButton, "clicked", G_CALLBACK (inputFileSelect), (gpointer)&st);
    
    GtkWidget *outputFileLabel = gtk_label_new ("Output File Path");
    st.outputFileNameBox = gtk_entry_new ();
    gtk_widget_set_tooltip_text (st.outputFileNameBox, "Enter the full path to where you want to save the result of encryption/decryption");
    GtkWidget *outputFileButton = gtk_button_new_with_label ("Select File");
    gtk_widget_set_tooltip_text (outputFileButton, "Select where you want to save the result of encryption/decryption to fill in this path");
    g_signal_connect (outputFileButton, "clicked", G_CALLBACK (outputFileSelect), (gpointer)&st);
    
    GtkWidget *passwordLabel = gtk_label_new ("Password");
    st.passwordBox = gtk_entry_new ();
    gtk_widget_set_tooltip_text (st.passwordBox, "Password to derive key from");
    gtk_entry_set_invisible_char(GTK_ENTRY (st.passwordBox),'*');
    gtk_entry_set_visibility(GTK_ENTRY (st.passwordBox), FALSE);
    
    GtkWidget *verificationLabel = gtk_label_new ("Verify Password");
    st.passwordVerificationBox = gtk_entry_new ();
    gtk_widget_set_tooltip_text (st.passwordVerificationBox, "Note: Not needed for decryption");
    gtk_entry_set_invisible_char(GTK_ENTRY (st.passwordVerificationBox),'*');
    gtk_entry_set_visibility(GTK_ENTRY (st.passwordVerificationBox), FALSE);
    
    GtkWidget *scryptWorkFactorsLabel = gtk_label_new ("scrypt work factors:");
    
    GtkWidget *nFactorLabel = gtk_label_new ("N Factor");
    GtkAdjustment *nFactorSpinButtonAdj = gtk_adjustment_new (DEFAULT_SCRYPT_N, 0, DEFAULT_SCRYPT_N * 8, 1048576, 0, 0);
    st.nFactorTextBox = gtk_spin_button_new (GTK_ADJUSTMENT (nFactorSpinButtonAdj), 0, 0);
    gtk_widget_set_tooltip_text (st.nFactorTextBox, "This is the N factor that will be used by scrypt");
    
    GtkWidget *rFactorLabel = gtk_label_new ("r Factor");
    GtkAdjustment *rFactorSpinButtonAdj = gtk_adjustment_new (DEFAULT_SCRYPT_R, 0, 10, 1, 0, 0);
    st.rFactorTextBox = gtk_spin_button_new (GTK_ADJUSTMENT (rFactorSpinButtonAdj), 0, 0);
    gtk_widget_set_tooltip_text (st.rFactorTextBox, "This is the r factor that will be used by scrypt");
    
    GtkWidget *pFactorLabel = gtk_label_new ("p Factor");
    GtkAdjustment *pFactorSpinButtonAdj = gtk_adjustment_new (DEFAULT_SCRYPT_P, 0, 10, 1, 0, 0);
    st.pFactorTextBox = gtk_spin_button_new (GTK_ADJUSTMENT (pFactorSpinButtonAdj), 0, 0);
    gtk_widget_set_tooltip_text (st.pFactorTextBox, "This is the p factor that will be used by scrypt");
    
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
    st.keySizeComboBox = gtk_combo_box_text_new ();
    gtk_widget_set_tooltip_text (st.keySizeComboBox, "This controls the size of the key that will be derived from the password");
    gtk_combo_box_text_append_text (GTK_COMBO_BOX_TEXT (st.keySizeComboBox), "16 bytes");
    gtk_combo_box_text_append_text (GTK_COMBO_BOX_TEXT (st.keySizeComboBox), "32 bytes");
    gtk_combo_box_text_append_text (GTK_COMBO_BOX_TEXT (st.keySizeComboBox), "64 bytes");
    gtk_combo_box_text_append_text (GTK_COMBO_BOX_TEXT (st.keySizeComboBox), "128 bytes");
    gtk_combo_box_text_append_text (GTK_COMBO_BOX_TEXT (st.keySizeComboBox), "256 bytes");
    gtk_combo_box_text_append_text (GTK_COMBO_BOX_TEXT (st.keySizeComboBox), "512 bytes");
    gtk_combo_box_text_append_text (GTK_COMBO_BOX_TEXT (st.keySizeComboBox), "2 Kb");
    gtk_combo_box_text_append_text (GTK_COMBO_BOX_TEXT (st.keySizeComboBox), "4 Kb");
    gtk_combo_box_text_append_text (GTK_COMBO_BOX_TEXT (st.keySizeComboBox), "8 Kb");
    gtk_combo_box_text_append_text (GTK_COMBO_BOX_TEXT (st.keySizeComboBox), "16 Kb");
    gtk_combo_box_text_append_text (GTK_COMBO_BOX_TEXT (st.keySizeComboBox), "32 Kb");
    gtk_combo_box_text_append_text (GTK_COMBO_BOX_TEXT (st.keySizeComboBox), "64 Kb");
    gtk_combo_box_text_append_text (GTK_COMBO_BOX_TEXT (st.keySizeComboBox), "128 Kb");
    gtk_combo_box_text_append_text (GTK_COMBO_BOX_TEXT (st.keySizeComboBox), "256 Kb");
    gtk_combo_box_text_append_text (GTK_COMBO_BOX_TEXT (st.keySizeComboBox), "512 Kb");
    gtk_combo_box_text_append_text (GTK_COMBO_BOX_TEXT (st.keySizeComboBox), "1 Mb");
    gtk_combo_box_text_append_text (GTK_COMBO_BOX_TEXT (st.keySizeComboBox), "2 Mb");
    gtk_combo_box_text_append_text (GTK_COMBO_BOX_TEXT (st.keySizeComboBox), "4 Mb");
    gtk_combo_box_text_append_text (GTK_COMBO_BOX_TEXT (st.keySizeComboBox), "8 Mb");
    gtk_combo_box_text_append_text (GTK_COMBO_BOX_TEXT (st.keySizeComboBox), "16 Mb");
    gtk_combo_box_text_append_text (GTK_COMBO_BOX_TEXT (st.keySizeComboBox), "32 Mb");
    gtk_combo_box_text_append_text (GTK_COMBO_BOX_TEXT (st.keySizeComboBox), "64 Mb");
    gtk_combo_box_text_append_text (GTK_COMBO_BOX_TEXT (st.keySizeComboBox), "128 Mb");
    gtk_combo_box_text_append_text (GTK_COMBO_BOX_TEXT (st.keySizeComboBox), "256 Mb");
    gtk_combo_box_text_append_text (GTK_COMBO_BOX_TEXT (st.keySizeComboBox), "512 Mb");
    gtk_combo_box_set_active (GTK_COMBO_BOX (st.keySizeComboBox), 20);
    
    GtkWidget *visibilityButton = gtk_check_button_new_with_label ("Show Password");
    gtk_widget_set_tooltip_text (visibilityButton, "Hint: Use this to avoid typos");
    gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON (visibilityButton), FALSE);
    g_signal_connect (visibilityButton, "toggled", G_CALLBACK (passVisibilityToggle),(gpointer)&st);
    
    GtkWidget *keyFileLabel = gtk_label_new ("Key File Path");
    st.keyFileNameBox = gtk_entry_new ();
    //FIXME Disabling these entries no longer works with pointers to structs
    //g_signal_connect (st.keyFileNameBox, "insert-text", G_CALLBACK (otpFileEntryDisable), (gpointer)&st);
    //g_signal_connect (st.keyFileNameBox, "delete-text", G_CALLBACK (otpFileEntryEnable), (gpointer)&st);
    gtk_widget_set_tooltip_text (st.keyFileNameBox, "Enter the full path to the key you want to use here");
    st.keyFileButton = gtk_button_new_with_label ("Select File");
    gtk_widget_set_tooltip_text (st.keyFileButton, "Select the key file you want to use here");
    g_signal_connect (st.keyFileButton, "clicked", G_CALLBACK (keyFileSelect), (gpointer)&st);
    //FIXME Disabling these entries no longer works with pointers to structs
    //g_signal_connect (st.keyFileButton, "clicked", G_CALLBACK (otpFileEntryDisable), (gpointer)&st);
    
    GtkWidget *otpFileLabel = gtk_label_new ("One-Time-Pad File Path");
    st.otpFileNameBox = gtk_entry_new ();
    //FIXME Disabling these entries no longer works with pointers to structs
    //g_signal_connect (st.otpFileNameBox, "insert-text", G_CALLBACK (keyFileEntryDisable), (gpointer)&st);
    //g_signal_connect (st.otpFileNameBox, "delete-text", G_CALLBACK (keyFileEntryEnable), (gpointer)&st);
    st.otpFileButton = gtk_button_new_with_label ("Select File");
    gtk_widget_set_tooltip_text (st.otpFileButton, "Select the one-time-pad file you want to use here");
    g_signal_connect (st.otpFileButton, "clicked", G_CALLBACK (otpFileSelect), (gpointer)&st);
    //FIXME Disabling these entries no longer works with pointers to structs
    //g_signal_connect (st.otpFileButton, "clicked", G_CALLBACK (keyFileEntryDisable), (gpointer)&st);
    
    gtk_widget_set_tooltip_text (st.otpFileNameBox, "Enter the full path to the one-time-pad you want to use here\
    \n\n\
    Using a one-time-pad means using something like /dev/urandom or another random-number generator\
    to produce a keystream that will be as long as the file being encrypted is. This cannot be used\
    in conjunction with a regular key, and the one-time-pad will be saved in the same directory as\
    the input file, under the same name, but with a .pad extension\
    \n***Very Important:*** Must use same size buffers between encryption and decryption");
    
    GtkWidget *macBufSizeLabel = gtk_label_new ("Authentication Buffer Size");
    st.macBufSizeComboBox = gtk_combo_box_text_new ();
    gtk_widget_set_tooltip_text (st.macBufSizeComboBox, "This controls the size of the buffer used for authenticating data");
    gtk_combo_box_text_append_text (GTK_COMBO_BOX_TEXT (st.macBufSizeComboBox), "1 byte");
    gtk_combo_box_text_append_text (GTK_COMBO_BOX_TEXT (st.macBufSizeComboBox), "2 bytes");
    gtk_combo_box_text_append_text (GTK_COMBO_BOX_TEXT (st.macBufSizeComboBox), "4 bytes");
    gtk_combo_box_text_append_text (GTK_COMBO_BOX_TEXT (st.macBufSizeComboBox), "8 bytes");
    gtk_combo_box_text_append_text (GTK_COMBO_BOX_TEXT (st.macBufSizeComboBox), "16 bytes");
    gtk_combo_box_text_append_text (GTK_COMBO_BOX_TEXT (st.macBufSizeComboBox), "32 bytes");
    gtk_combo_box_text_append_text (GTK_COMBO_BOX_TEXT (st.macBufSizeComboBox), "64 bytes");
    gtk_combo_box_text_append_text (GTK_COMBO_BOX_TEXT (st.macBufSizeComboBox), "128 bytes");
    gtk_combo_box_text_append_text (GTK_COMBO_BOX_TEXT (st.macBufSizeComboBox), "256 bytes");
    gtk_combo_box_text_append_text (GTK_COMBO_BOX_TEXT (st.macBufSizeComboBox), "512 bytes");
    gtk_combo_box_text_append_text (GTK_COMBO_BOX_TEXT (st.macBufSizeComboBox), "1 Kb");
    gtk_combo_box_text_append_text (GTK_COMBO_BOX_TEXT (st.macBufSizeComboBox), "2 Kb");
    gtk_combo_box_text_append_text (GTK_COMBO_BOX_TEXT (st.macBufSizeComboBox), "4 Kb");
    gtk_combo_box_text_append_text (GTK_COMBO_BOX_TEXT (st.macBufSizeComboBox), "8 Kb");
    gtk_combo_box_text_append_text (GTK_COMBO_BOX_TEXT (st.macBufSizeComboBox), "16 Kb");
    gtk_combo_box_text_append_text (GTK_COMBO_BOX_TEXT (st.macBufSizeComboBox), "32 Kb");
    gtk_combo_box_text_append_text (GTK_COMBO_BOX_TEXT (st.macBufSizeComboBox), "64 Kb");
    gtk_combo_box_text_append_text (GTK_COMBO_BOX_TEXT (st.macBufSizeComboBox), "128 Kb");
    gtk_combo_box_text_append_text (GTK_COMBO_BOX_TEXT (st.macBufSizeComboBox), "256 Kb");
    gtk_combo_box_text_append_text (GTK_COMBO_BOX_TEXT (st.macBufSizeComboBox), "512 Kb");
    gtk_combo_box_text_append_text (GTK_COMBO_BOX_TEXT (st.macBufSizeComboBox), "1 Mb");
    gtk_combo_box_text_append_text (GTK_COMBO_BOX_TEXT (st.macBufSizeComboBox), "2 Mb");
    gtk_combo_box_text_append_text (GTK_COMBO_BOX_TEXT (st.macBufSizeComboBox), "4 Mb");
    gtk_combo_box_text_append_text (GTK_COMBO_BOX_TEXT (st.macBufSizeComboBox), "8 Mb");
    gtk_combo_box_text_append_text (GTK_COMBO_BOX_TEXT (st.macBufSizeComboBox), "16 Mb");
    gtk_combo_box_text_append_text (GTK_COMBO_BOX_TEXT (st.macBufSizeComboBox), "32 Mb");
    gtk_combo_box_text_append_text (GTK_COMBO_BOX_TEXT (st.macBufSizeComboBox), "64 Mb");
    gtk_combo_box_text_append_text (GTK_COMBO_BOX_TEXT (st.macBufSizeComboBox), "128 Mb");
    gtk_combo_box_text_append_text (GTK_COMBO_BOX_TEXT (st.macBufSizeComboBox), "256 Mb");
    gtk_combo_box_text_append_text (GTK_COMBO_BOX_TEXT (st.macBufSizeComboBox), "512 Mb");
    gtk_combo_box_text_append_text (GTK_COMBO_BOX_TEXT (st.macBufSizeComboBox), "1 Gb");
    gtk_combo_box_text_append_text (GTK_COMBO_BOX_TEXT (st.macBufSizeComboBox), "2 Gb");
    gtk_combo_box_text_append_text (GTK_COMBO_BOX_TEXT (st.macBufSizeComboBox), "4 Gb");
    gtk_combo_box_text_append_text (GTK_COMBO_BOX_TEXT (st.macBufSizeComboBox), "8 Gb");
    gtk_combo_box_set_active (GTK_COMBO_BOX (st.macBufSizeComboBox), 20);
    
    GtkWidget *msgBufSizeLabel = gtk_label_new ("File Buffer Size");
    st.msgBufSizeComboBox = gtk_combo_box_text_new ();
    gtk_widget_set_tooltip_text (st.msgBufSizeComboBox, "This controls the size of the buffer used for encryption/decryption data");
    gtk_combo_box_text_append_text (GTK_COMBO_BOX_TEXT (st.msgBufSizeComboBox), "1 byte");
    gtk_combo_box_text_append_text (GTK_COMBO_BOX_TEXT (st.msgBufSizeComboBox), "2 bytes");
    gtk_combo_box_text_append_text (GTK_COMBO_BOX_TEXT (st.msgBufSizeComboBox), "4 bytes");
    gtk_combo_box_text_append_text (GTK_COMBO_BOX_TEXT (st.msgBufSizeComboBox), "8 bytes");
    gtk_combo_box_text_append_text (GTK_COMBO_BOX_TEXT (st.msgBufSizeComboBox), "16 bytes");
    gtk_combo_box_text_append_text (GTK_COMBO_BOX_TEXT (st.msgBufSizeComboBox), "32 bytes");
    gtk_combo_box_text_append_text (GTK_COMBO_BOX_TEXT (st.msgBufSizeComboBox), "64 bytes");
    gtk_combo_box_text_append_text (GTK_COMBO_BOX_TEXT (st.msgBufSizeComboBox), "128 bytes");
    gtk_combo_box_text_append_text (GTK_COMBO_BOX_TEXT (st.msgBufSizeComboBox), "256 bytes");
    gtk_combo_box_text_append_text (GTK_COMBO_BOX_TEXT (st.msgBufSizeComboBox), "512 bytes");
    gtk_combo_box_text_append_text (GTK_COMBO_BOX_TEXT (st.msgBufSizeComboBox), "1 Kb");
    gtk_combo_box_text_append_text (GTK_COMBO_BOX_TEXT (st.msgBufSizeComboBox), "2 Kb");
    gtk_combo_box_text_append_text (GTK_COMBO_BOX_TEXT (st.msgBufSizeComboBox), "4 Kb");
    gtk_combo_box_text_append_text (GTK_COMBO_BOX_TEXT (st.msgBufSizeComboBox), "8 Kb");
    gtk_combo_box_text_append_text (GTK_COMBO_BOX_TEXT (st.msgBufSizeComboBox), "16 Kb");
    gtk_combo_box_text_append_text (GTK_COMBO_BOX_TEXT (st.msgBufSizeComboBox), "32 Kb");
    gtk_combo_box_text_append_text (GTK_COMBO_BOX_TEXT (st.msgBufSizeComboBox), "64 Kb");
    gtk_combo_box_text_append_text (GTK_COMBO_BOX_TEXT (st.msgBufSizeComboBox), "128 Kb");
    gtk_combo_box_text_append_text (GTK_COMBO_BOX_TEXT (st.msgBufSizeComboBox), "256 Kb");
    gtk_combo_box_text_append_text (GTK_COMBO_BOX_TEXT (st.msgBufSizeComboBox), "512 Kb");
    gtk_combo_box_text_append_text (GTK_COMBO_BOX_TEXT (st.msgBufSizeComboBox), "1 Mb");
    gtk_combo_box_text_append_text (GTK_COMBO_BOX_TEXT (st.msgBufSizeComboBox), "2 Mb");
    gtk_combo_box_text_append_text (GTK_COMBO_BOX_TEXT (st.msgBufSizeComboBox), "4 Mb");
    gtk_combo_box_text_append_text (GTK_COMBO_BOX_TEXT (st.msgBufSizeComboBox), "8 Mb");
    gtk_combo_box_text_append_text (GTK_COMBO_BOX_TEXT (st.msgBufSizeComboBox), "16 Mb");
    gtk_combo_box_text_append_text (GTK_COMBO_BOX_TEXT (st.msgBufSizeComboBox), "32 Mb");
    gtk_combo_box_text_append_text (GTK_COMBO_BOX_TEXT (st.msgBufSizeComboBox), "64 Mb");
    gtk_combo_box_text_append_text (GTK_COMBO_BOX_TEXT (st.msgBufSizeComboBox), "128 Mb");
    gtk_combo_box_text_append_text (GTK_COMBO_BOX_TEXT (st.msgBufSizeComboBox), "256 Mb");
    gtk_combo_box_text_append_text (GTK_COMBO_BOX_TEXT (st.msgBufSizeComboBox), "512 Mb");
    gtk_combo_box_text_append_text (GTK_COMBO_BOX_TEXT (st.msgBufSizeComboBox), "1 Gb");
    gtk_combo_box_text_append_text (GTK_COMBO_BOX_TEXT (st.msgBufSizeComboBox), "2 Gb");
    gtk_combo_box_text_append_text (GTK_COMBO_BOX_TEXT (st.msgBufSizeComboBox), "4 Gb");
    gtk_combo_box_text_append_text (GTK_COMBO_BOX_TEXT (st.msgBufSizeComboBox), "8 Gb");
    gtk_combo_box_set_active (GTK_COMBO_BOX (st.msgBufSizeComboBox), 20);
    
    GtkWidget *encryptButton = gtk_button_new_with_label ("Encrypt");
    g_signal_connect (encryptButton, "clicked", G_CALLBACK (choseEncrypt), (gpointer)&st);
    g_signal_connect (encryptButton, "clicked", G_CALLBACK (on_cryptButton_clicked), (gpointer)&st);
        
    GtkWidget *decryptButton = gtk_button_new_with_label ("Decrypt");
    g_signal_connect (decryptButton, "clicked", G_CALLBACK (choseDecrypt), (gpointer)&st);
    g_signal_connect (decryptButton, "clicked", G_CALLBACK (on_cryptButton_clicked), (gpointer)&st);
    
    st.progressBar = gtk_progress_bar_new ();
    gtk_progress_bar_set_text (GTK_PROGRESS_BAR (st.progressBar), "Step Progress");
    gtk_progress_bar_set_show_text (GTK_PROGRESS_BAR (st.progressBar), TRUE);
    *(st.progressFraction) = 0.0;
    g_timeout_add (50, updateProgress, (gpointer)&st);
    
    st.overallProgressBar = gtk_progress_bar_new ();
    gtk_progress_bar_set_text (GTK_PROGRESS_BAR (st.overallProgressBar), "Overall Progress");
    gtk_progress_bar_set_show_text (GTK_PROGRESS_BAR (st.overallProgressBar), TRUE);
    *(st.overallProgressFraction) = 0.0;
    g_timeout_add (50, updateOverallProgress, (gpointer)&st);
    
    st.statusBar = gtk_statusbar_new ();
    gtk_widget_set_tooltip_text (st.statusBar, "Program will show status updates here");
    strcpy(st.statusMessage,"Ready");
    g_timeout_add (50, updateStatus, (gpointer)&st);
    
    GtkWidget *grid = gtk_grid_new();
    gtk_widget_set_hexpand (inputFileLabel, TRUE);
    gtk_grid_attach (GTK_GRID (grid), inputFileLabel, 0, 0, 1, 1);
    gtk_grid_attach (GTK_GRID (grid), st.inputFileNameBox, 0, 2, 1, 1);
    gtk_grid_attach (GTK_GRID (grid), inputFileButton, 1, 2, 1, 1);
    gtk_grid_attach (GTK_GRID (grid), outputFileLabel, 0, 4, 1, 1);
    gtk_grid_attach (GTK_GRID (grid), st.outputFileNameBox, 0, 5, 1, 1);
    gtk_grid_attach (GTK_GRID (grid), outputFileButton, 1, 5, 1, 1);
    gtk_grid_attach (GTK_GRID (grid), passwordLabel, 0, 7, 1, 1);
    gtk_grid_attach (GTK_GRID (grid), st.passwordBox, 0, 8, 1, 1);
    gtk_grid_attach (GTK_GRID (grid), visibilityButton, 1, 8, 1, 1);
    gtk_grid_attach (GTK_GRID (grid), verificationLabel, 0, 9, 1, 1);
    gtk_grid_attach (GTK_GRID (grid), keySizeLabel, 0, 11, 1, 1);
    gtk_grid_attach (GTK_GRID (grid), st.keySizeComboBox, 1, 11, 1, 1);
    gtk_grid_attach (GTK_GRID (grid), st.passwordVerificationBox, 0, 10, 1, 1);
    gtk_grid_attach (GTK_GRID (grid), scryptWorkFactorsLabel, 0, 12, 1, 1);
    gtk_grid_attach (GTK_GRID (grid), nFactorLabel, 0, 13, 1, 1);
    gtk_grid_attach (GTK_GRID (grid), st.nFactorTextBox, 1, 13, 1, 1);
    gtk_grid_attach (GTK_GRID (grid), rFactorLabel, 0, 15, 1, 1);
    gtk_grid_attach (GTK_GRID (grid), st.rFactorTextBox, 1, 15, 1, 1);
    gtk_grid_attach (GTK_GRID (grid), pFactorLabel, 0, 17, 1, 1);
    gtk_grid_attach (GTK_GRID (grid), st.pFactorTextBox, 1, 17, 1, 1);
    gtk_grid_attach (GTK_GRID (grid), keyFileLabel, 0, 18, 1, 1);
    gtk_grid_attach (GTK_GRID (grid), st.keyFileNameBox, 0, 19, 1, 1);
    gtk_grid_attach (GTK_GRID (grid), st.keyFileButton, 1, 19, 1, 1);
    gtk_grid_attach (GTK_GRID (grid), otpFileLabel, 0, 20, 1, 1);
    gtk_grid_attach (GTK_GRID (grid), st.otpFileNameBox, 0, 21, 1, 1);
    gtk_grid_attach (GTK_GRID (grid), st.otpFileButton, 1, 21, 1, 1);
    gtk_grid_attach (GTK_GRID (grid), macBufSizeLabel, 0, 24, 1, 1);
    gtk_grid_attach (GTK_GRID (grid), st.macBufSizeComboBox, 0, 25, 1, 1);
    gtk_grid_attach (GTK_GRID (grid), msgBufSizeLabel, 1, 24, 1, 1);
    gtk_grid_attach (GTK_GRID (grid), st.msgBufSizeComboBox, 1, 25, 1, 1);
    gtk_grid_attach (GTK_GRID (grid), encryptButton, 0, 26, 2, 1);
    gtk_grid_attach (GTK_GRID (grid), decryptButton, 0, 27, 2, 1);
    gtk_grid_attach (GTK_GRID (grid), st.progressBar, 0, 28, 2, 1);
    gtk_grid_attach (GTK_GRID (grid), st.overallProgressBar, 0, 29, 2, 1);
    gtk_grid_attach (GTK_GRID (grid), st.statusBar, 0, 30, 2, 1);
    
    
    gtk_container_add (GTK_CONTAINER (win), grid);
    
    g_signal_connect (win, "delete_event", G_CALLBACK (gtk_main_quit), NULL);
    
    gtk_widget_show_all (win);
    gtk_main ();

    exit(EXIT_SUCCESS);
}

static gboolean updateStatus(gpointer user_data)
{
    struct dataStruct *st = (struct dataStruct *)user_data;
    st->statusContextID = gtk_statusbar_get_context_id (GTK_STATUSBAR (st->statusBar), "Statusbar");
    gtk_statusbar_push (GTK_STATUSBAR (st->statusBar), GPOINTER_TO_INT (st->statusContextID), st->statusMessage);
    
    return TRUE;
}

static gboolean updateProgress(gpointer user_data)
{
    struct dataStruct *st = (struct dataStruct *)user_data;
    gtk_progress_bar_set_fraction (GTK_PROGRESS_BAR (st->progressBar), *(st->progressFraction));
    if(*(st->progressFraction) > 1)
        *(st->progressFraction) = 0.0;
        
    return TRUE;
}

static gboolean updateOverallProgress(gpointer user_data)
{
    struct dataStruct *st = (struct dataStruct *)user_data;
    gtk_progress_bar_set_fraction (GTK_PROGRESS_BAR (st->overallProgressBar), *(st->overallProgressFraction));
    if(*(st->overallProgressFraction) > 1)
        *(st->overallProgressFraction) = 0.0;
        
    return TRUE;
}

void choseEncrypt(GtkWidget *wid, gpointer ptr) {
    struct dataStruct *st = (struct dataStruct *) ptr;
    strcpy(st->encryptOrDecrypt,"encrypt");
}

void choseDecrypt(GtkWidget *wid, gpointer ptr) {
    struct dataStruct *st = (struct dataStruct *) ptr;
    strcpy(st->encryptOrDecrypt,"decrypt");
}

void on_cryptButton_clicked(GtkWidget *wid, gpointer ptr) {
    struct dataStruct *st = ptr;
    
    //FIXME Disabling these entries no longer works with pointers to structs
    //keyFileEntryEnable(wid, st);
    //otpFileEntryEnable(wid, st);
    
    gboolean passwordsMatch = FALSE;
    gboolean error = FALSE;
    
    st->inputFilePath = gtk_entry_get_text (GTK_ENTRY (st->inputFileNameBox));
    st->outputFilePath = gtk_entry_get_text (GTK_ENTRY (st->outputFileNameBox));
    st->passWord = gtk_entry_get_text (GTK_ENTRY (st->passwordBox));
    st->verificationPass = gtk_entry_get_text (GTK_ENTRY (st->passwordVerificationBox));
    st->keyFilePath = gtk_entry_get_text (GTK_ENTRY (st->keyFileNameBox));
    st->otpFilePath = gtk_entry_get_text (GTK_ENTRY (st->otpFileNameBox));
    st->keySizeComboBoxText = gtk_combo_box_text_get_active_text (GTK_COMBO_BOX_TEXT (st->keySizeComboBox));
    st->macBufSizeComboBoxText = gtk_combo_box_text_get_active_text (GTK_COMBO_BOX_TEXT (st->macBufSizeComboBox));
    st->msgBufSizeComboBoxText = gtk_combo_box_text_get_active_text (GTK_COMBO_BOX_TEXT (st->msgBufSizeComboBox));
    
    if(strlen(st->inputFilePath)) {
        st->inputFileGiven = true;
        strcpy(st->inputFileName,st->inputFilePath);
    } else {
        strcpy(st->statusMessage,"Need input file...");
        error = TRUE;
    }
    
    if(strlen(st->outputFilePath)) {
        st->outputFileGiven = true;
        strcpy(st->outputFileName,st->outputFilePath);
    } else {
        strcpy(st->statusMessage,"Need output file...");
        error = TRUE;
    }
    
    if(!strcmp(st->inputFilePath,st->outputFilePath)) {
        strcpy(st->statusMessage,"Input and output file are the same...");
        error = TRUE;
    }
        
    st->nFactor = gtk_spin_button_get_value_as_int (GTK_SPIN_BUTTON(st->nFactorTextBox));
    st->rFactor = gtk_spin_button_get_value_as_int (GTK_SPIN_BUTTON(st->rFactorTextBox));
    st->pFactor = gtk_spin_button_get_value_as_int (GTK_SPIN_BUTTON(st->pFactorTextBox));
    
    st->keyBufSize = atol(st->keySizeComboBoxText) * sizeof(uint8_t) * getBufSizeMultiple((char *)st->keySizeComboBoxText);
    st->yaxaSaltSize = st->keyBufSize / YAXA_KEY_CHUNK_SIZE;

    st->genHmacBufSize = atol(st->macBufSizeComboBoxText) * sizeof(uint8_t) * getBufSizeMultiple((char *)st->macBufSizeComboBoxText);
    makeMultipleOf(&st->genHmacBufSize,sizeof(cryptint_t));
    
    st->msgBufSize = atol(st->msgBufSizeComboBoxText) * sizeof(uint8_t) * getBufSizeMultiple((char *)st->msgBufSizeComboBoxText);
    makeMultipleOf(&st->msgBufSize,sizeof(cryptint_t));
    
    if(strlen(st->passWord)) {
        st->passWordGiven = true;
    } else {
        st->passWordGiven = false;
    }
    
    if(strlen(st->keyFilePath)) {
        st->keyFileGiven = true;
        strcpy(st->keyFileName,st->keyFilePath);
        st->keyFileSize = getFileSize(st->keyFileName);
        st->keyBufSize = st->keyFileSize;
        st->yaxaSaltSize = st->keyBufSize / YAXA_KEY_CHUNK_SIZE;
    } else {
        st->keyFileGiven = false;
    }
    
    if(strlen(st->otpFilePath)) {
        st->oneTimePad = true;
        st->yaxaSaltSize = 0;
        strcpy(st->otpInFileName,st->otpFilePath);
        snprintf(st->otpOutFileName, NAME_MAX, "%s", st->otpFilePath);
        sprintf(st->otpOutFileName,"%s.pad", st->outputFilePath);
    } else {
        st->oneTimePad = false;
    }
    
    if((st->passWordGiven && st->keyFileGiven) || (st->passWordGiven && st->oneTimePad)) {
        st->yaxaSaltSize = st->keyBufSize / YAXA_KEY_CHUNK_SIZE;
    } else if (st->oneTimePad || st->keyFileGiven) {
        st->yaxaSaltSize = 0;
    }
    
    if(!st->passWordGiven && !st->keyFileGiven && !st->oneTimePad) {
        strcpy(st->statusMessage,"Need at least password, keyfile or one-time-pad");
        error = TRUE;
    }
    
    if(strcmp(st->encryptOrDecrypt,"encrypt") == 0) {
        if(st->passWordGiven) {
            st->verificationPass = gtk_entry_get_text (GTK_ENTRY (st->passwordVerificationBox));
            if(strcmp(st->passWord,st->verificationPass) == 0)
                passwordsMatch = TRUE;
            
            if (passwordsMatch == FALSE) {
                strcpy(st->statusMessage,"Passwords didn't match");
                error = TRUE;
            } else if(passwordsMatch == TRUE) {
                snprintf(st->userPass,MAX_PASS_SIZE,"%s",st->passWord);
            
                gtk_entry_set_text(GTK_ENTRY (st->passwordBox), "");
                OPENSSL_cleanse((void *)st->passWord, strlen(st->passWord));
                gtk_entry_set_text(GTK_ENTRY (st->passwordBox), st->passWord);
                
                gtk_entry_set_text(GTK_ENTRY (st->passwordVerificationBox), "");
                OPENSSL_cleanse((void *)st->verificationPass, strlen(st->verificationPass));
                gtk_entry_set_text(GTK_ENTRY (st->passwordVerificationBox), st->verificationPass);
            }
        }
    } else if (strcmp(st->encryptOrDecrypt,"decrypt") == 0) {
        snprintf(st->userPass,MAX_PASS_SIZE,"%s",st->passWord);
    
        gtk_entry_set_text(GTK_ENTRY (st->passwordBox), "");
        OPENSSL_cleanse((void *)st->passWord, strlen(st->passWord));
        gtk_entry_set_text(GTK_ENTRY (st->passwordBox), st->passWord);
        
        if(strlen(st->verificationPass)) {
            gtk_entry_set_text(GTK_ENTRY (st->passwordVerificationBox), "");
            OPENSSL_cleanse((void *)st->verificationPass, strlen(st->verificationPass));
            gtk_entry_set_text(GTK_ENTRY (st->passwordVerificationBox), st->verificationPass);
        }
    }
    
    if(st->keyFileGiven && st->oneTimePad) {
        strcpy(st->statusMessage,"Can only use keyfile OR one-time-pad");
        error = TRUE;
    }
    
    if(error != TRUE) {
        if(strcmp(st->encryptOrDecrypt,"encrypt") == 0) {
            strcpy(st->statusMessage,"Starting encryption...");
            workThread('e',st);
        } else if (strcmp(st->encryptOrDecrypt,"decrypt") == 0) {
            strcpy(st->statusMessage,"Starting decryption...");
            workThread('d',st);
        }
    }
    
    OPENSSL_cleanse((void *)st->userPass, strlen(st->userPass));
}

static void inputFileSelect (GtkWidget *wid, gpointer ptr)
{
    struct dataStruct *st = (struct dataStruct *)ptr;
    GtkWidget *dialog;
    GtkFileChooserAction action = GTK_FILE_CHOOSER_ACTION_OPEN;
    gint res;
    char *fileName;
    
    dialog = gtk_file_chooser_dialog_new ("Open File",
                                          GTK_WINDOW (st),
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
        gtk_entry_set_text(GTK_ENTRY (st->inputFileNameBox), fileName);
      }
    
    gtk_widget_destroy (dialog);
}

static void outputFileSelect (GtkWidget *wid, gpointer ptr)
{
    struct dataStruct *st = (struct dataStruct *)ptr;
    GtkWidget *dialog;
    GtkFileChooserAction action = GTK_FILE_CHOOSER_ACTION_SAVE;
    gint res;
    char *fileName;
    
    dialog = gtk_file_chooser_dialog_new ("Save File",
                                          GTK_WINDOW (st),
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
        gtk_entry_set_text(GTK_ENTRY (st->outputFileNameBox), fileName);
      }
    
    gtk_widget_destroy (dialog);
}

static void keyFileSelect (GtkWidget *wid, gpointer ptr)
{
    struct dataStruct *st = (struct dataStruct *)ptr;
    GtkWidget *dialog;
    GtkFileChooserAction action = GTK_FILE_CHOOSER_ACTION_OPEN;
    gint res;
    char *fileName;
    
    dialog = gtk_file_chooser_dialog_new ("Open File",
                                          GTK_WINDOW (st),
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
        gtk_entry_set_text(GTK_ENTRY (st->keyFileNameBox), fileName);
      }
    
    gtk_widget_destroy (dialog);
}

static void otpFileSelect (GtkWidget *wid, gpointer ptr)
{
    struct dataStruct *st = (struct dataStruct *)ptr;
    GtkWidget *dialog;
    GtkFileChooserAction action = GTK_FILE_CHOOSER_ACTION_OPEN;
    gint res;
    char *fileName;
    
    dialog = gtk_file_chooser_dialog_new ("Open File",
                                          GTK_WINDOW (st),
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
        gtk_entry_set_text(GTK_ENTRY (st->otpFileNameBox), fileName);
      }
    
    gtk_widget_destroy (dialog);
}

void passVisibilityToggle (GtkWidget *wid, gpointer ptr)
{
    struct dataStruct *st = (struct dataStruct *)ptr;
    gtk_entry_set_visibility(GTK_ENTRY (st->passwordBox), gtk_toggle_button_get_active (GTK_TOGGLE_BUTTON (wid)));
    gtk_entry_set_visibility(GTK_ENTRY (st->passwordVerificationBox), gtk_toggle_button_get_active (GTK_TOGGLE_BUTTON (wid)));
}

void otpFileEntryDisable (GtkWidget *wid, gpointer ptr)
{
    struct dataStruct *st = (struct dataStruct *)ptr;
    gtk_editable_set_editable(GTK_EDITABLE(st->otpFileNameBox), FALSE);
    gtk_widget_set_sensitive (GTK_WIDGET(st->otpFileButton), FALSE);

}

void keyFileEntryDisable (GtkWidget *wid, gpointer ptr)
{
    struct dataStruct *st = (struct dataStruct *)ptr;
    gtk_editable_set_editable(GTK_EDITABLE(st->keyFileNameBox), FALSE);
    gtk_widget_set_sensitive (GTK_WIDGET(st->keyFileButton), FALSE);

}

void otpFileEntryEnable (GtkWidget *wid, gpointer ptr)
{
    struct dataStruct *st = (struct dataStruct *)ptr;
    gtk_editable_set_editable(GTK_EDITABLE(st->otpFileNameBox), TRUE);
    gtk_widget_set_sensitive (GTK_WIDGET(st->otpFileButton), TRUE);

}

void keyFileEntryEnable (GtkWidget *wid, gpointer ptr)
{
    struct dataStruct *st = (struct dataStruct *)ptr;
    gtk_editable_set_editable(GTK_EDITABLE(st->keyFileNameBox), TRUE);
    gtk_widget_set_sensitive (GTK_WIDGET(st->keyFileButton), TRUE);

}

