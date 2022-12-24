struct termios termiosOld, termiosNew;

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

struct optionsStruct optSt = {0};

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
    
    /*Iterator for indexing yaxaKey array*/
    uint32_t k;
};

struct cryptoStruct cryptSt = {0};

struct fileStruct {
    char inputFileName[NAME_MAX];
    char outputFileName[NAME_MAX];
    char keyFileName[NAME_MAX];
    char otpInFileName[NAME_MAX];
    char otpOutFileName[NAME_MAX];
};

struct fileStruct fileSt = {0};

struct sizesStruct {
    size_t keyBufSize;
    size_t genHmacBufSize;
    size_t msgBufSize;
    size_t yaxaSaltSize;
    size_t keyFileSize;
};

struct sizesStruct sizesSt = {0};

struct miscStruct {
    uint64_t returnVal;
    uint8_t *otpBuffer;
};

struct miscStruct miscSt = {0};

#ifdef gui

struct progressStruct {
    double *progressFraction;
    char *statusMessage;
    
    GtkWidget *statusBar;
    guint statusContextID;
    
    GtkWidget *overallProgressBar;
    double *overallProgressFraction;
    
    GtkWidget *progressBar;
};

struct progressStruct progressSt = {0};
#endif
