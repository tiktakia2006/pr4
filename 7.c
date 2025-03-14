#include <stdio.h>
#include <stdlib.h>

struct sbar {
    int data;
};

int main() {
    struct sbar *ptr, *newptr;

    ptr = reallocarray(NULL, 1000, sizeof(struct sbar));
    newptr = reallocarray(ptr, 500, sizeof(struct sbar));

    if (newptr != NULL) {
        printf("Memory successfully allocated and resized\n");
        free(newptr);
    } else {
        printf("Memory allocation failed\n");
    }

    return 0;
}
