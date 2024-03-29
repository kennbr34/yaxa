/*
  This product includes software developed by the OpenSSL Project
  for use in the OpenSSL Toolkit (http://www.openssl.org/)
*/
#include "headers.h"


void on_cryptButton_clicked(GtkWidget *wid, gpointer ptr);
void choseEncrypt(GtkWidget *wid, gpointer ptr);
void choseDecrypt(GtkWidget *wid, gpointer ptr);
static void inputFileSelect (GtkWidget *wid, gpointer ptr);
static void outputFileSelect (GtkWidget *wid, gpointer ptr);
static void keyFileSelect (GtkWidget *wid, gpointer ptr);
static void otpFileSelect (GtkWidget *wid, gpointer ptr);
void passVisibilityToggle (GtkWidget *wid, gpointer ptr);
void keyFileEntryDisableFromInsert (GtkEditable* self, gchar* new_text, gint new_text_length, gint* position, gpointer user_data);
void keyFileEntryEnableFromDelete (GtkEditable* self, gint start_pos, gint end_pos, gpointer user_data);
void keyFileEntryDisableButtonFromClick (GtkWidget *wid, gpointer ptr);
void otpFileEntryDisableFromInsert (GtkEditable* self, gchar* new_text, gint new_text_length, gint* position, gpointer user_data);
void otpFileEntryEnableFromDelete (GtkEditable* self, gint start_pos, gint end_pos, gpointer user_data);
void otpFileEntryDisableButtonFromClick (GtkWidget *wid, gpointer ptr);
void otpFileEntryEnable (GtkWidget *wid, gpointer ptr);
void keyFileEntryEnable (GtkWidget *wid, gpointer ptr);
static gboolean updateStatus(gpointer user_data);
static gboolean updateProgress(gpointer user_data);
static gboolean updateOverallProgress(gpointer user_data);

int main(int argc, char *argv[])
{
    
    unsigned long long int number = 1;
    
    /*Catch SIGCONT to kill GUI if -q was used for testing*/
    signal(SIGCONT,signalHandler);
    
    static struct dataStruct st = {0};
    
    //struct dataStruct *st = g_new0(struct dataStruct, 1);
    
    st.cryptSt.nFactor = DEFAULT_SCRYPT_N;
    st.cryptSt.pFactor = DEFAULT_SCRYPT_P;
    st.cryptSt.rFactor = DEFAULT_SCRYPT_R;
    st.cryptSt.k = 0;
    
    st.cryptSt.keyBufSize = YAXA_KEYBUF_SIZE;
    st.cryptSt.genHmacBufSize = 1024 * 1024;
    st.cryptSt.msgBufSize = 1024 * 1024;
    st.cryptSt.yaxaSaltSize = YAXA_KEYBUF_SIZE / YAXA_KEY_CHUNK_SIZE;

    /*These must be mapped as shared memory for the worker thread to manipulate their values in the main thread*/
    st.guiSt.statusMessage = mmap(NULL, 256, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    st.guiSt.progressFraction = mmap(NULL, sizeof(double), PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    st.guiSt.overallProgressFraction = mmap(NULL, sizeof(double), PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    
    if(argc > 1) {
        parseOptions(argc, argv, &st);
    }

    allocateBuffers(&st);

    OpenSSL_add_all_algorithms();
    
    gtk_init (&argc, &argv);
    
    st.guiSt.win = gtk_window_new (GTK_WINDOW_TOPLEVEL);
    
    gtk_window_set_title(GTK_WINDOW (st.guiSt.win), "YAXA File Encryption Utility");
    
    GtkWidget *inputFileLabel = gtk_label_new ("Input File Path");
    st.guiSt.inputFileNameBox = gtk_entry_new ();
    gtk_widget_set_tooltip_text (st.guiSt.inputFileNameBox, "Enter the full path to the file you want to encrypt/decrypt here");
    GtkWidget *inputFileButton = gtk_button_new_with_label ("Select File");
    gtk_widget_set_tooltip_text (inputFileButton, "Select the file you want to encrypt/decrypt to fill in this path");
    g_signal_connect (inputFileButton, "clicked", G_CALLBACK (inputFileSelect), (gpointer)&st);
    
    GtkWidget *outputFileLabel = gtk_label_new ("Output File Path");
    st.guiSt.outputFileNameBox = gtk_entry_new ();
    gtk_widget_set_tooltip_text (st.guiSt.outputFileNameBox, "Enter the full path to where you want to save the result of encryption/decryption");
    GtkWidget *outputFileButton = gtk_button_new_with_label ("Select File");
    gtk_widget_set_tooltip_text (outputFileButton, "Select where you want to save the result of encryption/decryption to fill in this path");
    g_signal_connect (outputFileButton, "clicked", G_CALLBACK (outputFileSelect), (gpointer)&st);
    
    GtkWidget *passwordLabel = gtk_label_new ("Password");
    st.guiSt.passwordBox = gtk_entry_new ();
    gtk_widget_set_tooltip_text (st.guiSt.passwordBox, "Password to derive key from");
    gtk_entry_set_invisible_char(GTK_ENTRY (st.guiSt.passwordBox),'*');
    gtk_entry_set_visibility(GTK_ENTRY (st.guiSt.passwordBox), FALSE);
    
    GtkWidget *verificationLabel = gtk_label_new ("Verify Password");
    st.guiSt.passwordVerificationBox = gtk_entry_new ();
    gtk_widget_set_tooltip_text (st.guiSt.passwordVerificationBox, "Note: Not needed for decryption");
    gtk_entry_set_invisible_char(GTK_ENTRY (st.guiSt.passwordVerificationBox),'*');
    gtk_entry_set_visibility(GTK_ENTRY (st.guiSt.passwordVerificationBox), FALSE);
    
    GtkWidget *scryptWorkFactorsLabel = gtk_label_new ("scrypt work factors:");
    
    GtkWidget *nFactorLabel = gtk_label_new ("N Factor");
    GtkAdjustment *nFactorSpinButtonAdj = gtk_adjustment_new (DEFAULT_SCRYPT_N, 0, DEFAULT_SCRYPT_N * 8, 1048576, 0, 0);
    st.guiSt.nFactorTextBox = gtk_spin_button_new (GTK_ADJUSTMENT (nFactorSpinButtonAdj), 0, 0);
    gtk_widget_set_tooltip_text (st.guiSt.nFactorTextBox, "This is the N factor that will be used by scrypt");
    
    GtkWidget *rFactorLabel = gtk_label_new ("r Factor");
    GtkAdjustment *rFactorSpinButtonAdj = gtk_adjustment_new (DEFAULT_SCRYPT_R, 0, 10, 1, 0, 0);
    st.guiSt.rFactorTextBox = gtk_spin_button_new (GTK_ADJUSTMENT (rFactorSpinButtonAdj), 0, 0);
    gtk_widget_set_tooltip_text (st.guiSt.rFactorTextBox, "This is the r factor that will be used by scrypt");
    
    GtkWidget *pFactorLabel = gtk_label_new ("p Factor");
    GtkAdjustment *pFactorSpinButtonAdj = gtk_adjustment_new (DEFAULT_SCRYPT_P, 0, 10, 1, 0, 0);
    st.guiSt.pFactorTextBox = gtk_spin_button_new (GTK_ADJUSTMENT (pFactorSpinButtonAdj), 0, 0);
    gtk_widget_set_tooltip_text (st.guiSt.pFactorTextBox, "This is the p factor that will be used by scrypt");
    
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
    st.guiSt.keySizeComboBox = gtk_combo_box_text_new ();
    char keySizeComboBoxTextString[15] = {0};
    number = 64;
    gtk_widget_set_tooltip_text (st.guiSt.keySizeComboBox, "This controls the size of the key that will be derived from the password");
    for(int i = 0; i < 34; i++) {
        bytesPrefixed(keySizeComboBoxTextString, number);
        gtk_combo_box_text_append_text (GTK_COMBO_BOX_TEXT (st.guiSt.keySizeComboBox), keySizeComboBoxTextString);
        number = number << 1;
    }
    gtk_combo_box_set_active (GTK_COMBO_BOX (st.guiSt.keySizeComboBox), 19);
    
    GtkWidget *visibilityButton = gtk_check_button_new_with_label ("Show Password");
    gtk_widget_set_tooltip_text (visibilityButton, "Hint: Use this to avoid typos");
    gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON (visibilityButton), FALSE);
    g_signal_connect (visibilityButton, "toggled", G_CALLBACK (passVisibilityToggle),(gpointer)&st);
    
    GtkWidget *keyFileLabel = gtk_label_new ("Key File Path");
    st.guiSt.keyFileNameBox = gtk_entry_new ();
    g_signal_connect (st.guiSt.keyFileNameBox, "insert-text", G_CALLBACK (otpFileEntryDisableFromInsert), (gpointer)&st);
    g_signal_connect (st.guiSt.keyFileNameBox, "delete-text", G_CALLBACK (otpFileEntryEnableFromDelete), (gpointer)&st);
    gtk_widget_set_tooltip_text (st.guiSt.keyFileNameBox, "Enter the full path to the key you want to use here");
    st.guiSt.keyFileButton = gtk_button_new_with_label ("Select File");
    gtk_widget_set_tooltip_text (st.guiSt.keyFileButton, "Select the key file you want to use here");
    g_signal_connect (st.guiSt.keyFileButton, "clicked", G_CALLBACK (keyFileSelect), (gpointer)&st);
    g_signal_connect (st.guiSt.keyFileButton, "clicked", G_CALLBACK (otpFileEntryDisableButtonFromClick), (gpointer)&st);
    
    GtkWidget *otpFileLabel = gtk_label_new ("One-Time-Pad File Path");
    st.guiSt.otpFileNameBox = gtk_entry_new ();
    g_signal_connect (st.guiSt.otpFileNameBox, "insert-text", G_CALLBACK (keyFileEntryDisableFromInsert), (gpointer)&st);
    g_signal_connect (st.guiSt.otpFileNameBox, "delete-text", G_CALLBACK (keyFileEntryEnableFromDelete), (gpointer)&st);
    st.guiSt.otpFileButton = gtk_button_new_with_label ("Select File");
    gtk_widget_set_tooltip_text (st.guiSt.otpFileButton, "Select the one-time-pad file you want to use here");
    g_signal_connect (st.guiSt.otpFileButton, "clicked", G_CALLBACK (otpFileSelect), (gpointer)&st);
    g_signal_connect (st.guiSt.otpFileButton, "clicked", G_CALLBACK (keyFileEntryDisableButtonFromClick), (gpointer)&st);
    
    gtk_widget_set_tooltip_text (st.guiSt.otpFileNameBox, "Enter the full path to the one-time-pad you want to use here\
    \n\n\
    Using a one-time-pad means using something like /dev/urandom or another random-number generator\
    to produce a keystream that will be as long as the file being encrypted is. This cannot be used\
    in conjunction with a regular key, and the one-time-pad will be saved in the same directory as\
    the input file, under the same name, but with a .pad extension\
    \n***Very Important:*** Must use same size buffers between encryption and decryption");
    
    GtkWidget *macBufSizeLabel = gtk_label_new ("Authentication Buffer Size");
    st.guiSt.macBufSizeComboBox = gtk_combo_box_text_new ();
    gtk_widget_set_tooltip_text (st.guiSt.macBufSizeComboBox, "This controls the size of the buffer used for authenticating data");
    char macBufSizeComboBoxTextString[15] = {0};
    number = 1;
    for(int i = 0; i < 34; i++) {
        bytesPrefixed(macBufSizeComboBoxTextString, number);
        gtk_combo_box_text_append_text (GTK_COMBO_BOX_TEXT (st.guiSt.macBufSizeComboBox), macBufSizeComboBoxTextString);
        number = number << 1;
    }
    gtk_combo_box_set_active (GTK_COMBO_BOX (st.guiSt.macBufSizeComboBox), 20);
    
    GtkWidget *msgBufSizeLabel = gtk_label_new ("File Buffer Size");
    st.guiSt.msgBufSizeComboBox = gtk_combo_box_text_new ();
    gtk_widget_set_tooltip_text (st.guiSt.msgBufSizeComboBox, "This controls the size of the buffer used for encryption/decryption data");
    char msgBufSizeComboBoxTextString[15] = {0};
    number = 1;
    for(int i = 0; i < 34; i++) {
        bytesPrefixed(msgBufSizeComboBoxTextString, number);
        gtk_combo_box_text_append_text (GTK_COMBO_BOX_TEXT (st.guiSt.msgBufSizeComboBox), msgBufSizeComboBoxTextString);
        number = number << 1;
    }
    gtk_combo_box_set_active (GTK_COMBO_BOX (st.guiSt.msgBufSizeComboBox), 20);
    
    GtkWidget *encryptButton = gtk_button_new_with_label ("Encrypt");
    g_signal_connect (encryptButton, "clicked", G_CALLBACK (choseEncrypt), (gpointer)&st);
    g_signal_connect (encryptButton, "clicked", G_CALLBACK (on_cryptButton_clicked), (gpointer)&st);
        
    GtkWidget *decryptButton = gtk_button_new_with_label ("Decrypt");
    g_signal_connect (decryptButton, "clicked", G_CALLBACK (choseDecrypt), (gpointer)&st);
    g_signal_connect (decryptButton, "clicked", G_CALLBACK (on_cryptButton_clicked), (gpointer)&st);
    
    st.guiSt.progressBar = gtk_progress_bar_new ();
    gtk_progress_bar_set_text (GTK_PROGRESS_BAR (st.guiSt.progressBar), "Step Progress");
    gtk_progress_bar_set_show_text (GTK_PROGRESS_BAR (st.guiSt.progressBar), TRUE);
    *(st.guiSt.progressFraction) = 0.0;
    g_timeout_add (50, updateProgress, (gpointer)&st);
    
    st.guiSt.overallProgressBar = gtk_progress_bar_new ();
    gtk_progress_bar_set_text (GTK_PROGRESS_BAR (st.guiSt.overallProgressBar), "Overall Progress");
    gtk_progress_bar_set_show_text (GTK_PROGRESS_BAR (st.guiSt.overallProgressBar), TRUE);
    *(st.guiSt.overallProgressFraction) = 0.0;
    g_timeout_add (50, updateOverallProgress, (gpointer)&st);
    
    st.guiSt.statusBar = gtk_statusbar_new ();
    gtk_widget_set_tooltip_text (st.guiSt.statusBar, "Program will show status updates here");
    strcpy(st.guiSt.statusMessage,"Ready");
    g_timeout_add (50, updateStatus, (gpointer)&st);
    
    if(st.optSt.inputFileGiven) {
        gtk_entry_set_text ( GTK_ENTRY(st.guiSt.inputFileNameBox), (const gchar*) st.fileNameSt.inputFileName);
    }
    
    if(st.optSt.outputFileGiven) {
        gtk_entry_set_text ( GTK_ENTRY(st.guiSt.outputFileNameBox), (const gchar*) st.fileNameSt.outputFileName);
    }
    
    if(st.optSt.keyFileGiven) {
        gtk_entry_set_text ( GTK_ENTRY(st.guiSt.keyFileNameBox), (const gchar*) st.fileNameSt.keyFileName);
    }
    
    if(st.optSt.oneTimePad) {
        gtk_entry_set_text ( GTK_ENTRY(st.guiSt.otpFileNameBox), (const gchar*) st.fileNameSt.otpInFileName);
    }
    
    if(st.optSt.passWordGiven) {
        gtk_entry_set_text ( GTK_ENTRY(st.guiSt.passwordBox), (const gchar*) st.cryptSt.userPass);
        if(st.optSt.encrypt) {
            gtk_entry_set_text ( GTK_ENTRY(st.guiSt.passwordVerificationBox) , (const gchar*) st.cryptSt.userPass);
        }
    }
    
    if(st.optSt.nFactorGiven) {
        gtk_adjustment_set_value ( GTK_ADJUSTMENT (nFactorSpinButtonAdj), (gdouble)st.cryptSt.nFactor);
    }
    
    if(st.optSt.rFactorGiven) {
        gtk_adjustment_set_value ( GTK_ADJUSTMENT (rFactorSpinButtonAdj), (gdouble)st.cryptSt.rFactor);
    }
    
    if(st.optSt.pFactorGiven) {
        gtk_adjustment_set_value ( GTK_ADJUSTMENT (pFactorSpinButtonAdj), (gdouble)st.cryptSt.pFactor);
    }
    
    if(st.optSt.keyBufSizeGiven) {
        char size_string[15];
        bytesPrefixed(size_string,st.cryptSt.keyBufSize);
        gtk_combo_box_text_prepend ( GTK_COMBO_BOX_TEXT (st.guiSt.keySizeComboBox), 0, (const gchar*) size_string);
        gtk_combo_box_set_active (GTK_COMBO_BOX (st.guiSt.keySizeComboBox), 0);
    }
    
    if(st.optSt.macBufSizeGiven) {
        char size_string[15];
        bytesPrefixed(size_string,st.cryptSt.genHmacBufSize);
        gtk_combo_box_text_prepend ( GTK_COMBO_BOX_TEXT (st.guiSt.macBufSizeComboBox), 0, (const gchar*) size_string);
        gtk_combo_box_set_active (GTK_COMBO_BOX (st.guiSt.macBufSizeComboBox), 0);
    }
    
    if(st.optSt.msgBufSizeGiven) {
        char size_string[15];
        bytesPrefixed(size_string,st.cryptSt.msgBufSize);
        gtk_combo_box_text_prepend ( GTK_COMBO_BOX_TEXT (st.guiSt.msgBufSizeComboBox), 0, (const gchar*) size_string);
        gtk_combo_box_set_active (GTK_COMBO_BOX (st.guiSt.msgBufSizeComboBox), 0);
    }
    
    GtkWidget *grid = gtk_grid_new();
    gtk_widget_set_hexpand (inputFileLabel, TRUE);
    gtk_grid_attach (GTK_GRID (grid), inputFileLabel, 0, 0, 1, 1);
    gtk_grid_attach (GTK_GRID (grid), st.guiSt.inputFileNameBox, 0, 2, 1, 1);
    gtk_grid_attach (GTK_GRID (grid), inputFileButton, 1, 2, 1, 1);
    gtk_grid_attach (GTK_GRID (grid), outputFileLabel, 0, 4, 1, 1);
    gtk_grid_attach (GTK_GRID (grid), st.guiSt.outputFileNameBox, 0, 5, 1, 1);
    gtk_grid_attach (GTK_GRID (grid), outputFileButton, 1, 5, 1, 1);
    gtk_grid_attach (GTK_GRID (grid), passwordLabel, 0, 7, 1, 1);
    gtk_grid_attach (GTK_GRID (grid), st.guiSt.passwordBox, 0, 8, 1, 1);
    gtk_grid_attach (GTK_GRID (grid), visibilityButton, 1, 8, 1, 1);
    gtk_grid_attach (GTK_GRID (grid), verificationLabel, 0, 9, 1, 1);
    gtk_grid_attach (GTK_GRID (grid), keySizeLabel, 0, 11, 1, 1);
    gtk_grid_attach (GTK_GRID (grid), st.guiSt.keySizeComboBox, 1, 11, 1, 1);
    gtk_grid_attach (GTK_GRID (grid), st.guiSt.passwordVerificationBox, 0, 10, 1, 1);
    gtk_grid_attach (GTK_GRID (grid), scryptWorkFactorsLabel, 0, 12, 1, 1);
    gtk_grid_attach (GTK_GRID (grid), nFactorLabel, 0, 13, 1, 1);
    gtk_grid_attach (GTK_GRID (grid), st.guiSt.nFactorTextBox, 1, 13, 1, 1);
    gtk_grid_attach (GTK_GRID (grid), rFactorLabel, 0, 15, 1, 1);
    gtk_grid_attach (GTK_GRID (grid), st.guiSt.rFactorTextBox, 1, 15, 1, 1);
    gtk_grid_attach (GTK_GRID (grid), pFactorLabel, 0, 17, 1, 1);
    gtk_grid_attach (GTK_GRID (grid), st.guiSt.pFactorTextBox, 1, 17, 1, 1);
    gtk_grid_attach (GTK_GRID (grid), keyFileLabel, 0, 18, 1, 1);
    gtk_grid_attach (GTK_GRID (grid), st.guiSt.keyFileNameBox, 0, 19, 1, 1);
    gtk_grid_attach (GTK_GRID (grid), st.guiSt.keyFileButton, 1, 19, 1, 1);
    gtk_grid_attach (GTK_GRID (grid), otpFileLabel, 0, 20, 1, 1);
    gtk_grid_attach (GTK_GRID (grid), st.guiSt.otpFileNameBox, 0, 21, 1, 1);
    gtk_grid_attach (GTK_GRID (grid), st.guiSt.otpFileButton, 1, 21, 1, 1);
    gtk_grid_attach (GTK_GRID (grid), macBufSizeLabel, 0, 24, 1, 1);
    gtk_grid_attach (GTK_GRID (grid), st.guiSt.macBufSizeComboBox, 0, 25, 1, 1);
    gtk_grid_attach (GTK_GRID (grid), msgBufSizeLabel, 1, 24, 1, 1);
    gtk_grid_attach (GTK_GRID (grid), st.guiSt.msgBufSizeComboBox, 1, 25, 1, 1);
    gtk_grid_attach (GTK_GRID (grid), encryptButton, 0, 26, 2, 1);
    gtk_grid_attach (GTK_GRID (grid), decryptButton, 0, 27, 2, 1);
    gtk_grid_attach (GTK_GRID (grid), st.guiSt.progressBar, 0, 28, 2, 1);
    gtk_grid_attach (GTK_GRID (grid), st.guiSt.overallProgressBar, 0, 29, 2, 1);
    gtk_grid_attach (GTK_GRID (grid), st.guiSt.statusBar, 0, 30, 2, 1);
    
    
    gtk_container_add (GTK_CONTAINER (st.guiSt.win), grid);
    
    g_signal_connect (st.guiSt.win, "delete_event", G_CALLBACK (gtk_main_quit), NULL);
    
    gtk_widget_show_all (st.guiSt.win);
    
    if(argc > 1) {
        if(st.optSt.encrypt) {
            strcpy(st.guiSt.encryptOrDecrypt,"encrypt");
            on_cryptButton_clicked(NULL,&st);
        } else if(st.optSt.decrypt) {
            strcpy(st.guiSt.encryptOrDecrypt,"decrypt");
            on_cryptButton_clicked(NULL,&st);
        }
    }
    
    gtk_main ();
        
    cleanUpBuffers(&st);

    exit(EXIT_SUCCESS);
}

static gboolean updateStatus(gpointer user_data)
{
    struct dataStruct *st = (struct dataStruct *)user_data;
    st->guiSt.statusContextID = gtk_statusbar_get_context_id (GTK_STATUSBAR (st->guiSt.statusBar), "Statusbar");
    gtk_statusbar_push (GTK_STATUSBAR (st->guiSt.statusBar), GPOINTER_TO_INT (st->guiSt.statusContextID), st->guiSt.statusMessage);
    
    return TRUE;
}

static gboolean updateProgress(gpointer user_data)
{
    struct dataStruct *st = (struct dataStruct *)user_data;
    gtk_progress_bar_set_fraction (GTK_PROGRESS_BAR (st->guiSt.progressBar), *(st->guiSt.progressFraction));
    if(*(st->guiSt.progressFraction) > 1)
        *(st->guiSt.progressFraction) = 0.0;
        
    return TRUE;
}

static gboolean updateOverallProgress(gpointer user_data)
{
    struct dataStruct *st = (struct dataStruct *)user_data;
    gtk_progress_bar_set_fraction (GTK_PROGRESS_BAR (st->guiSt.overallProgressBar), *(st->guiSt.overallProgressFraction));
    if(*(st->guiSt.overallProgressFraction) > 1)
        *(st->guiSt.overallProgressFraction) = 0.0;
        
    return TRUE;
}

void choseEncrypt(GtkWidget *wid, gpointer ptr) {
    struct dataStruct *st = (struct dataStruct *) ptr;
    strcpy(st->guiSt.encryptOrDecrypt,"encrypt");
}

void choseDecrypt(GtkWidget *wid, gpointer ptr) {
    struct dataStruct *st = (struct dataStruct *) ptr;
    strcpy(st->guiSt.encryptOrDecrypt,"decrypt");
}

void on_cryptButton_clicked(GtkWidget *wid, gpointer ptr) {
    struct dataStruct *st = ptr;
    
    gboolean passwordsMatch = FALSE;
    gboolean error = FALSE;
    
    st->guiSt.inputFilePath = gtk_entry_get_text (GTK_ENTRY (st->guiSt.inputFileNameBox));
    st->guiSt.outputFilePath = gtk_entry_get_text (GTK_ENTRY (st->guiSt.outputFileNameBox));
    st->guiSt.passWord = gtk_entry_get_text (GTK_ENTRY (st->guiSt.passwordBox));
    st->guiSt.verificationPass = gtk_entry_get_text (GTK_ENTRY (st->guiSt.passwordVerificationBox));
    st->guiSt.keyFilePath = gtk_entry_get_text (GTK_ENTRY (st->guiSt.keyFileNameBox));
    st->guiSt.otpFilePath = gtk_entry_get_text (GTK_ENTRY (st->guiSt.otpFileNameBox));
    st->guiSt.keySizeComboBoxText = gtk_combo_box_text_get_active_text (GTK_COMBO_BOX_TEXT (st->guiSt.keySizeComboBox));
    st->guiSt.macBufSizeComboBoxText = gtk_combo_box_text_get_active_text (GTK_COMBO_BOX_TEXT (st->guiSt.macBufSizeComboBox));
    st->guiSt.msgBufSizeComboBoxText = gtk_combo_box_text_get_active_text (GTK_COMBO_BOX_TEXT (st->guiSt.msgBufSizeComboBox));
    
    if(strlen(st->guiSt.inputFilePath)) {
        st->optSt.inputFileGiven = true;
        st->fileNameSt.inputFileName = strdup(st->guiSt.inputFilePath);
    } else {
        strcpy(st->guiSt.statusMessage,"Need input file...");
        error = TRUE;
    }
    
    if(strlen(st->guiSt.outputFilePath)) {
        st->optSt.outputFileGiven = true;
        st->fileNameSt.outputFileName = strdup(st->guiSt.outputFilePath);
    } else {
        strcpy(st->guiSt.statusMessage,"Need output file...");
        error = TRUE;
    }
    
    if(!strcmp(st->guiSt.inputFilePath,st->guiSt.outputFilePath)) {
        strcpy(st->guiSt.statusMessage,"Input and output file are the same...");
        error = TRUE;
    }
        
    st->cryptSt.nFactor = gtk_spin_button_get_value_as_int (GTK_SPIN_BUTTON(st->guiSt.nFactorTextBox));
    st->cryptSt.rFactor = gtk_spin_button_get_value_as_int (GTK_SPIN_BUTTON(st->guiSt.rFactorTextBox));
    st->cryptSt.pFactor = gtk_spin_button_get_value_as_int (GTK_SPIN_BUTTON(st->guiSt.pFactorTextBox));
    
    st->cryptSt.keyBufSize = atol(st->guiSt.keySizeComboBoxText) * sizeof(uint8_t) * getBufSizeMultiple((char *)st->guiSt.keySizeComboBoxText);
    st->cryptSt.yaxaSaltSize = st->cryptSt.keyBufSize / YAXA_KEY_CHUNK_SIZE;

    st->cryptSt.genHmacBufSize = atol(st->guiSt.macBufSizeComboBoxText) * sizeof(uint8_t) * getBufSizeMultiple((char *)st->guiSt.macBufSizeComboBoxText);
    makeMultipleOf(&st->cryptSt.genHmacBufSize,sizeof(cryptint_t));
    
    st->cryptSt.msgBufSize = atol(st->guiSt.msgBufSizeComboBoxText) * sizeof(uint8_t) * getBufSizeMultiple((char *)st->guiSt.msgBufSizeComboBoxText);
    makeMultipleOf(&st->cryptSt.msgBufSize,sizeof(cryptint_t));
    
    if(strlen(st->guiSt.passWord)) {
        st->optSt.passWordGiven = true;
    } else {
        st->optSt.passWordGiven = false;
    }
    
    if(strlen(st->guiSt.keyFilePath)) {
        st->optSt.keyFileGiven = true;
        st->fileNameSt.keyFileName = strdup(st->guiSt.keyFilePath);
        st->cryptSt.keyFileSize = getFileSize(st->fileNameSt.keyFileName);
        st->cryptSt.keyBufSize = st->cryptSt.keyFileSize;
        st->cryptSt.yaxaSaltSize = st->cryptSt.keyBufSize / YAXA_KEY_CHUNK_SIZE;
    } else {
        st->optSt.keyFileGiven = false;
    }
    
    if(strlen(st->guiSt.otpFilePath)) {
        st->optSt.oneTimePad = true;
        st->cryptSt.yaxaSaltSize = 0;
        st->fileNameSt.otpInFileName = strdup(st->guiSt.otpFilePath);
        st->fileNameSt.otpOutFileName = malloc(((strlen(st->guiSt.outputFilePath)+1) + (strlen(".pad")+1) +1 ) * sizeof(uint8_t));
        sprintf(st->fileNameSt.otpOutFileName, "%s.pad", st->guiSt.outputFilePath);
    } else {
        st->optSt.oneTimePad = false;
    }
    
    if((st->optSt.passWordGiven && st->optSt.keyFileGiven) || (st->optSt.passWordGiven && st->optSt.oneTimePad)) {
        st->cryptSt.yaxaSaltSize = st->cryptSt.keyBufSize / YAXA_KEY_CHUNK_SIZE;
    } else if (st->optSt.oneTimePad || st->optSt.keyFileGiven) {
        st->cryptSt.yaxaSaltSize = 0;
    }
    
    if(!st->optSt.passWordGiven && !st->optSt.keyFileGiven && !st->optSt.oneTimePad) {
        strcpy(st->guiSt.statusMessage,"Need at least password, keyfile or one-time-pad");
        error = TRUE;
    }
    
    if(strcmp(st->guiSt.encryptOrDecrypt,"encrypt") == 0) {
        if(st->optSt.passWordGiven) {
            st->guiSt.verificationPass = gtk_entry_get_text (GTK_ENTRY (st->guiSt.passwordVerificationBox));
            if(strcmp(st->guiSt.passWord,st->guiSt.verificationPass) == 0)
                passwordsMatch = TRUE;
            
            if (passwordsMatch == FALSE) {
                strcpy(st->guiSt.statusMessage,"Passwords didn't match");
                error = TRUE;
            } else if(passwordsMatch == TRUE) {
                snprintf(st->cryptSt.userPass,MAX_PASS_SIZE,"%s",st->guiSt.passWord);
            
                gtk_entry_set_text(GTK_ENTRY (st->guiSt.passwordBox), "");
                OPENSSL_cleanse((void *)st->guiSt.passWord, strlen(st->guiSt.passWord));
                gtk_entry_set_text(GTK_ENTRY (st->guiSt.passwordBox), st->guiSt.passWord);
                
                gtk_entry_set_text(GTK_ENTRY (st->guiSt.passwordVerificationBox), "");
                OPENSSL_cleanse((void *)st->guiSt.verificationPass, strlen(st->guiSt.verificationPass));
                gtk_entry_set_text(GTK_ENTRY (st->guiSt.passwordVerificationBox), st->guiSt.verificationPass);
            }
        }
    } else if (strcmp(st->guiSt.encryptOrDecrypt,"decrypt") == 0) {
        snprintf(st->cryptSt.userPass,MAX_PASS_SIZE,"%s",st->guiSt.passWord);
    
        gtk_entry_set_text(GTK_ENTRY (st->guiSt.passwordBox), "");
        OPENSSL_cleanse((void *)st->guiSt.passWord, strlen(st->guiSt.passWord));
        gtk_entry_set_text(GTK_ENTRY (st->guiSt.passwordBox), st->guiSt.passWord);
        
        if(strlen(st->guiSt.verificationPass)) {
            gtk_entry_set_text(GTK_ENTRY (st->guiSt.passwordVerificationBox), "");
            OPENSSL_cleanse((void *)st->guiSt.verificationPass, strlen(st->guiSt.verificationPass));
            gtk_entry_set_text(GTK_ENTRY (st->guiSt.passwordVerificationBox), st->guiSt.verificationPass);
        }
    }
    
    if(st->optSt.keyFileGiven && st->optSt.oneTimePad) {
        strcpy(st->guiSt.statusMessage,"Can only use keyfile OR one-time-pad");
        error = TRUE;
    }
    
    if(error != TRUE) {
        if(strcmp(st->guiSt.encryptOrDecrypt,"encrypt") == 0) {
            strcpy(st->guiSt.statusMessage,"Starting encryption...");
            workThread('e',st);
        } else if (strcmp(st->guiSt.encryptOrDecrypt,"decrypt") == 0) {
            strcpy(st->guiSt.statusMessage,"Starting decryption...");
            workThread('d',st);
        }
    }
    
    OPENSSL_cleanse((void *)st->cryptSt.userPass, strlen(st->cryptSt.userPass));
}

static void inputFileSelect (GtkWidget *wid, gpointer ptr)
{
    struct dataStruct *st = (struct dataStruct *)ptr;
    GtkWidget *dialog;
    GtkFileChooserAction action = GTK_FILE_CHOOSER_ACTION_OPEN;
    gint res;
    char *fileName;
    
    dialog = gtk_file_chooser_dialog_new ("Open File",
                                          GTK_WINDOW (st->guiSt.win),
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
        gtk_entry_set_text(GTK_ENTRY (st->guiSt.inputFileNameBox), fileName);
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
                                          GTK_WINDOW (st->guiSt.win),
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
        gtk_entry_set_text(GTK_ENTRY (st->guiSt.outputFileNameBox), fileName);
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
                                          GTK_WINDOW (st->guiSt.win),
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
        gtk_entry_set_text(GTK_ENTRY (st->guiSt.keyFileNameBox), fileName);
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
                                          GTK_WINDOW (st->guiSt.win),
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
        gtk_entry_set_text(GTK_ENTRY (st->guiSt.otpFileNameBox), fileName);
      }
    
    gtk_widget_destroy (dialog);
}

void passVisibilityToggle (GtkWidget *wid, gpointer ptr)
{
    struct dataStruct *st = (struct dataStruct *)ptr;
    gtk_entry_set_visibility(GTK_ENTRY (st->guiSt.passwordBox), gtk_toggle_button_get_active (GTK_TOGGLE_BUTTON (wid)));
    gtk_entry_set_visibility(GTK_ENTRY (st->guiSt.passwordVerificationBox), gtk_toggle_button_get_active (GTK_TOGGLE_BUTTON (wid)));
}

void keyFileEntryDisableFromInsert (GtkEditable* self,
  gchar* new_text,
  gint new_text_length,
  gint* position,
  gpointer user_data)
{
    struct dataStruct *st = (struct dataStruct *)user_data;
    gtk_editable_set_editable(GTK_EDITABLE(st->guiSt.keyFileNameBox), FALSE);
    gtk_widget_set_sensitive (GTK_WIDGET(st->guiSt.keyFileButton), FALSE);
}

void keyFileEntryEnableFromDelete (GtkEditable* self,
  gint start_pos,
  gint end_pos,
  gpointer user_data)
{
    struct dataStruct *st = (struct dataStruct *)user_data;
    gtk_editable_set_editable(GTK_EDITABLE(st->guiSt.keyFileNameBox), TRUE);
    gtk_widget_set_sensitive (GTK_WIDGET(st->guiSt.keyFileButton), TRUE);
}

void otpFileEntryEnable (GtkWidget *wid, gpointer ptr)
{
    struct dataStruct *st = (struct dataStruct *)ptr;
    gtk_editable_set_editable(GTK_EDITABLE(st->guiSt.otpFileNameBox), TRUE);
    gtk_widget_set_sensitive (GTK_WIDGET(st->guiSt.otpFileButton), TRUE);

}

void keyFileEntryDisableButtonFromClick (GtkWidget *wid, gpointer ptr)
{
    struct dataStruct *st = (struct dataStruct *)ptr;
    gtk_editable_set_editable(GTK_EDITABLE(st->guiSt.keyFileNameBox), FALSE);
    gtk_widget_set_sensitive (GTK_WIDGET(st->guiSt.keyFileButton), FALSE);
}

void otpFileEntryDisableFromInsert (GtkEditable* self,
  gchar* new_text,
  gint new_text_length,
  gint* position,
  gpointer user_data)
{
    struct dataStruct *st = (struct dataStruct *)user_data;
    gtk_editable_set_editable(GTK_EDITABLE(st->guiSt.otpFileNameBox), FALSE);
    gtk_widget_set_sensitive (GTK_WIDGET(st->guiSt.otpFileButton), FALSE);
}

void otpFileEntryEnableFromDelete (GtkEditable* self,
  gint start_pos,
  gint end_pos,
  gpointer user_data)
{
    struct dataStruct *st = (struct dataStruct *)user_data;
    gtk_editable_set_editable(GTK_EDITABLE(st->guiSt.otpFileNameBox), TRUE);
    gtk_widget_set_sensitive (GTK_WIDGET(st->guiSt.otpFileButton), TRUE);
}

void otpFileEntryDisableButtonFromClick (GtkWidget *wid, gpointer ptr)
{
    struct dataStruct *st = (struct dataStruct *)ptr;
    gtk_editable_set_editable(GTK_EDITABLE(st->guiSt.otpFileNameBox), FALSE);
    gtk_widget_set_sensitive (GTK_WIDGET(st->guiSt.otpFileButton), FALSE);
}

void keyFileEntryEnable (GtkWidget *wid, gpointer ptr)
{
    struct dataStruct *st = (struct dataStruct *)ptr;
    gtk_editable_set_editable(GTK_EDITABLE(st->guiSt.keyFileNameBox), TRUE);
    gtk_widget_set_sensitive (GTK_WIDGET(st->guiSt.keyFileButton), TRUE);

}
