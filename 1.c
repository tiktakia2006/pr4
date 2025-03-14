#include <stdio.h>
#include <stdlib.h>

int main() {
    size_t max_size = (size_t) -1;
    void *ptr = malloc(max_size);

    if (ptr == NULL) {
        printf("Memory allocation failed\n");
        return 1;
    } else {
        printf("Memory successfully allocated\n");
        free(ptr);
    }

    return 0;
}
