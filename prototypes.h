/*Prototype functions*/
void allocateBuffers();                                                  /*Allocates all the buffers used*/
void cleanUpBuffers();                                                   /*Writes zeroes to all the buffers when done*/
void doCrypt(FILE *inFile, FILE *outFile, cryptint_t fileSize);   /*Encryption/Decryption routines*/
int freadWErrCheck(void *ptr, size_t size, size_t nmemb, FILE *stream);  /*fread() error checking wrapper*/
int fwriteWErrCheck(void *ptr, size_t size, size_t nmemb, FILE *stream); /*fwrite() error checking wrapper*/
void genHMAC(FILE *dataFile, cryptint_t fileSize);                /*Generate HMAC*/
void genHMACKey();                                                       /*Generate key for HMAC*/
void genPassTag();                                                       /*Generate passKeyedHash*/
void genYaxaSalt();                                                      /*Generates YAXA salt*/
void genYaxaKey();                                                       /*YAXA key deriving function*/
void genCtrStart();	                                                     /*Derive starting point for Ctr from key*/
cryptint_t getFileSize(const char *filename);                     /*Returns filesize using stat()*/
char *getPass(const char *prompt);                                       /*Function to retrive passwords with no echo*/
int printSyntax(char *arg);                                              /*Print program usage and help*/
void signalHandler(int signum);                                          /*Signal handler for Ctrl+C*/
cryptint_t yaxa(cryptint_t messageInt);                    /*YAXA encryption/decryption function*/
