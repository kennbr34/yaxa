struct termios termiosOld, termiosNew;

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

/*Iterator for indexing yaxaKey array*/
uint32_t k = 0;

uint64_t returnVal;
bool gotPassFromCmdLine = false;

double *progressFraction;
char *statusMessage;

