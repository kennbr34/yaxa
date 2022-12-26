struct cryptoStruct {
    cryptint_t counterInt;
    uint8_t counterBytes[16];
    
    cryptint_t nonceInt;
    uint8_t nonceBytes[16];
    
    cryptint_t keyInt;
    uint8_t keyBytes[16];
    
    uint8_t *yaxaKeyChunk;
    uint8_t *yaxaKey;
    uint8_t *yaxaSalt;
    
    char userPass[MAX_PASS_SIZE];
    char userPassToVerify[MAX_PASS_SIZE];
    uint8_t passKeyedHash[PASS_KEYED_HASH_SIZE], passKeyedHashFromFile[PASS_KEYED_HASH_SIZE];
    
    size_t nFactor;
    size_t pFactor;
    size_t rFactor;
    
    uint8_t generatedMAC[MAC_SIZE];
    uint8_t fileMAC[MAC_SIZE];
    uint8_t *hmacKey;
    uint32_t *HMACLengthPtr;
    
    size_t keyBufSize;
    size_t genHmacBufSize;
    size_t msgBufSize;
    size_t yaxaSaltSize;
    size_t keyFileSize;
    
    /*Iterator for indexing yaxaKey array*/
    uint32_t k;
};

struct fileNames {
    char inputFileName[NAME_MAX];
    char outputFileName[NAME_MAX];
    char keyFileName[NAME_MAX];
    char otpInFileName[NAME_MAX];
    char otpOutFileName[NAME_MAX];
};

struct optionsStruct {
    bool encrypt;
    bool decrypt;
    bool inputFileGiven;
    bool outputFileGiven;
    bool keyFileGiven;
    bool oneTimePad;
    bool passWordGiven;
    bool keyBufSizeGiven;
    bool macBufSizeGiven;
    bool msgBufSizeGiven;
    bool gotPassFromCmdLine;
};

struct miscStruct {
    uint64_t returnVal;
};

#ifdef gui
struct guiStruct {
    char encryptOrDecrypt[8];

    GtkWidget *win;

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

    double *progressFraction;
    char *statusMessage;
    
    GtkWidget *statusBar;
    guint statusContextID;
    
    GtkWidget *overallProgressBar;
    double *overallProgressFraction;
    
    GtkWidget *progressBar;

};
#endif

struct dataStruct {
    struct cryptoStruct cryptSt;
    struct fileNames fileNameSt;
    struct optionsStruct optSt;
    struct miscStruct miscSt;
    #ifdef gui
    struct guiStruct guiSt;
    #endif
};
