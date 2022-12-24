#include <errno.h>
#include <openssl/err.h>
#include <openssl/hmac.h>
#include <openssl/kdf.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <termios.h>
#include <stdbool.h>
#ifdef gui
#include <gtk/gtk.h>
#endif
#include <sys/mman.h>
#include <getopt.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>


/*Define the size of the integer to be used in XOR operations*/

#ifdef __64bit
typedef uint64_t cryptint_t;
#else
typedef unsigned __int128 cryptint_t;
#endif

/*Do NOT change the order of these*/

/*Macro defintions*/
#include "macros.h"

/*Global variable defintions*/
#include "globals.h"

/*Structure definitions*/
//#include "structs.h"

/*Function prototypes*/
#include "prototypes.h"
