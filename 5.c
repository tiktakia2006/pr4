#include <stdio.h>
#include <stdlib.h>

int main() {
    size_t huge_size = (size_t)-1;
    void *ptr = malloc(10);

    if (!ptr) {
        printf("Initial allocation failed\n");
        return 1;
    }

    void *new_ptr = realloc(ptr, huge_size);

    if (!new_ptr) {
        printf("Realloc failed: not enough memory\n");
        free(ptr);
    } else {
        printf("Realloc succeeded unexpectedly\n");
        free(new_ptr);
    }

    return 0;
}
