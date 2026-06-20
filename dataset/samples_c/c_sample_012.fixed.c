#include <stdio.h>
#include <string.h>
FILE* open_file(char *filename) {
    if (filename == NULL || strstr(filename, "..") != NULL) {
        fprintf(stderr, "Invalid path\n");
        return NULL;
    }
    return fopen(filename, "r");
}
