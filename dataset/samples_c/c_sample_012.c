#include <stdio.h>
FILE* open_file(char *filename) {
    return fopen(filename, "r");  // VULN: path traversal
}
