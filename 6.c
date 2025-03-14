#include <stdio.h>
#include <stdlib.h>

int main() {
    void *ptr = NULL;

    ptr = realloc(ptr, 10);
    if (ptr != NULL) {
        printf("Memory allocated with size 10\n");
    }

    ptr = realloc(ptr, 0);
    if (ptr == NULL) {
        printf("Memory freed with size 0\n");
    }

    if (ptr != NULL) {
        free(ptr);
    }

    return 0;
}
