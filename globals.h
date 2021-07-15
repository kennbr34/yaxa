struct termios termisOld, termiosNew;

cryptint_t counterInt;
uint8_t counterBytes[16];


cryptint_t keyInt;
uint8_t keyBytes[16];

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
int k = 0;

int returnVal;
int gotPassFromCmdLine = false;

double *progressFraction;
char *statusMessage;

