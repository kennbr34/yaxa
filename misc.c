void signalHandler(int signum)
{
    printf("\nCaught signal %d\nCleaning up buffers...\n", signum);

    /* Restore terminal. */
    if (gotPassFromCmdLine == false) {
        tcgetattr(fileno(stdin), &termisOld);
        termiosNew = termisOld;
        termiosNew.c_lflag &= ~ECHO;
    }
    (void)tcsetattr(fileno(stdin), TCSAFLUSH, &termisOld);

    exit(EXIT_FAILURE);
}

int freadWErrCheck(void *ptr, size_t size, size_t nmemb, FILE *stream)
{
    if (fread(ptr, size, nmemb, stream) != nmemb / size) {
        if (feof(stream)) {
            returnVal = EBADMSG;
            return EBADMSG;
        } else if (ferror(stream)) {
            returnVal = errno;
            return errno;
        }
    }

    return 0;
}

int fwriteWErrCheck(void *ptr, size_t size, size_t nmemb, FILE *stream)
{
    if (fwrite(ptr, size, nmemb, stream) != nmemb / size) {
        if (feof(stream)) {
            returnVal = EBADMSG;
            return EBADMSG;
        } else if (ferror(stream)) {
            returnVal = errno;
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
