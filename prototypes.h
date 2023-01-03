/*Prototype functions*/
void allocateBuffers(struct dataStruct *st);                                                  /*Allocates all the buffers used*/
void cleanUpBuffers(struct dataStruct *st);                                                   /*Writes zeroes to all the buffers when done*/
void doCrypt(FILE *inFile, FILE *outFile, cryptint_t fileSize, FILE *oneTimePad, FILE *otpOutFile, struct dataStruct *st);   /*Encryption/Decryption routines*/
uint64_t freadWErrCheck(void *ptr, size_t size, size_t nmemb, FILE *stream, struct dataStruct *st);  /*fread() error checking wrapper*/
uint64_t fwriteWErrCheck(void *ptr, size_t size, size_t nmemb, FILE *stream, struct dataStruct *st); /*fwrite() error checking wrapper*/
void genHMAC(FILE *dataFile, cryptint_t fileSize, struct dataStruct *st);                /*Generate HMAC*/
void genHMACKey(struct dataStruct *st);                                                       /*Generate key for HMAC*/
void genPassTag(struct dataStruct *st);                                                       /*Generate passKeyedHash*/
void genYaxaSalt(struct dataStruct *st);                                                      /*Generates YAXA salt*/
void genYaxaKey(struct dataStruct *st);                                                       /*YAXA key deriving function*/
void genCtrStart(struct dataStruct *st);	                                                     /*Derive starting point for Ctr from key*/
void genNonce(struct dataStruct *st);
cryptint_t getFileSize(const char *filename);                     /*Returns filesize using stat()*/
char *getPass(const char *prompt, char *paddedPass);                                      /*Function to retrive passwords with no echo*/
uint8_t printSyntax(char *arg);                                              /*Print program usage and help*/
void signalHandler(int signum);                                          /*Signal handler for Ctrl+C*/
cryptint_t yaxa(cryptint_t messageInt, uint8_t *otpBuffer, struct dataStruct *st);                    /*YAXA encryption/decryption function*/
void makeMultipleOf(size_t *numberToChange, size_t multiple);
int workThread(char action, struct dataStruct *st);
void parseOptions(int argc, char *argv[], struct dataStruct *st);
void bytesPrefixed(char *prefixedString, unsigned long long bytes);
