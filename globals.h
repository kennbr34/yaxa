struct termios termiosOld, termiosNew;

struct optionsStruct {
    bool encrypt;
    bool decrypt;
    bool inputFileGiven;
    bool outputFileGiven;
    bool keyFileGiven;
    bool passWordGiven;
    bool keyBufSizeGiven;
    bool macBufSizeGiven;
    bool msgBufSizeGiven;
};

cryptint_t counterInt;
uint8_t counterBytes[16];

cryptint_t keyInt;
uint8_t keyBytes[16];

uint8_t *yaxaKeyChunk = NULL;
uint8_t *yaxaKey = NULL;
uint8_t *yaxaSalt = NULL;

char *userPass = NULL;
char *userPassToVerify = NULL;
uint8_t passKeyedHash[PASS_KEYED_HASH_SIZE], passKeyedHashFromFile[PASS_KEYED_HASH_SIZE];

uint8_t generatedMAC[MAC_SIZE];
uint8_t fileMAC[MAC_SIZE];
uint8_t *hmacKey = NULL;
uint32_t *HMACLengthPtr = NULL;

char inputFileName[NAME_MAX];
char outputFileName[NAME_MAX];
char keyFileName[NAME_MAX];

size_t keyBufSize = YAXA_KEYBUF_SIZE;
size_t genHmacBufSize = 1024 * 1024;
size_t msgBufSize = 1024 * 1024;
size_t yaxaSaltSize = YAXA_KEYBUF_SIZE / YAXA_KEY_CHUNK_SIZE;

/*Iterator for indexing yaxaKey array*/
uint32_t k = 0;

uint64_t returnVal;
bool gotPassFromCmdLine = false;

double *progressFraction;
char *statusMessage;

