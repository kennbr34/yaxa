//void signalHandler(int signum)
//{
    //printf("\nCaught signal %d\nCleaning up buffers...\n", signum);

    ///* Restore terminal. */
    //if (st->gotPassFromCmdLine == false) {
        //tcgetattr(fileno(stdin), &termiosOld);
        //termiosNew = termiosOld;
        //termiosNew.c_lflag &= ~ECHO;
    //}
    //(void)tcsetattr(fileno(stdin), TCSAFLUSH, &termiosOld);

    //exit(EXIT_FAILURE);
//}

uint64_t freadWErrCheck(void *ptr, size_t size, size_t nmemb, FILE *stream, struct dataStruct *st)
{
    if (fread(ptr, size, nmemb, stream) != nmemb / size) {
        if (feof(stream)) {
            st->returnVal = EBADMSG;
            return EBADMSG;
        } else if (ferror(stream)) {
            st->returnVal = errno;
            return errno;
        }
    }

    return 0;
}

uint64_t fwriteWErrCheck(void *ptr, size_t size, size_t nmemb, FILE *stream, struct dataStruct *st)
{
    if (fwrite(ptr, size, nmemb, stream) != nmemb / size) {
        if (feof(stream)) {
            st->returnVal = EBADMSG;
            return EBADMSG;
        } else if (ferror(stream)) {
            st->returnVal = errno;
            return errno;
        }
    }

    return 0;
}

cryptint_t getFileSize(const char *filename)
{
    struct stat st;
    stat(filename, &st);
    return st.st_size;
}

size_t getBufSizeMultiple(char *value) { 
    
    #define MAX_DIGITS 13
    char valString[MAX_DIGITS] = {0};
    /* Compiling without optimization results in extremely slow speeds, but this will be optimized 
     * out if not set to volatile.
     */
    volatile int valueLength = 0;
    volatile int multiple = 1;
    
    /* value from getsubopt is not null-terminated so must copy and get the length manually without
     * string functions
     */
    for(valueLength = 0;valueLength < MAX_DIGITS;valueLength++) {
        if(isdigit(value[valueLength])) {
            valString[valueLength] = value[valueLength];
            continue;
        }
        else if(isalpha(value[valueLength])) {
            valString[valueLength] = value[valueLength];
            valueLength++;
            break;
        }
    }
    
    if(valString[valueLength-1] == 'b' || valString[valueLength-1] == 'B')
        multiple = 1;
    if(valString[valueLength-1] == 'k' || valString[valueLength-1] == 'K')
        multiple = 1024;
    if(valString[valueLength-1] == 'm' || valString[valueLength-1] == 'M')
        multiple = 1024*1024;
    if(valString[valueLength-1] == 'g' || valString[valueLength-1] == 'G')
        multiple = 1024*1024*1024;
        
    return multiple;
}

void makeMultipleOf(size_t *numberToChange, size_t multiple) {
	 if(*numberToChange > multiple && *numberToChange % multiple != 0) {
                *numberToChange = *numberToChange - (*numberToChange % multiple);
        } else if (*numberToChange > multiple && *numberToChange % multiple == 0) {
                *numberToChange = *numberToChange;
        }
}

