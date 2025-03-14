#include <stdio.h>
#include <stdlib.h>

int main() {
    void *ptr = malloc(16);
    int i = 0;

    if (!ptr) {
        printf("Memory allocation failed\n");
        return 1;
    }

    while (i < 5) {
        printf("Using allocated memory at: %p\n", ptr);
        i++;
    }

    free(ptr);

    return 0;
}
