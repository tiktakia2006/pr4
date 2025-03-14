#include <stdio.h>
#include <stdlib.h>
#include <malloc.h>

int main() {
    mallopt(M_MXFAST, 1024 * 1024);

    void *ptr1 = malloc(100);
    void *ptr2 = malloc(5000);
    void *ptr3 = malloc(10000);

    if (ptr1 == NULL || ptr2 == NULL || ptr3 == NULL) {
        printf("Memory allocation failed\n");
    } else {
        printf("Memory successfully allocated\n");

        printf("Allocated memory at ptr1: %p\n", ptr1);
        printf("Allocated memory at ptr2: %p\n", ptr2);
        printf("Allocated memory at ptr3: %p\n", ptr3);

        free(ptr1);
        free(ptr2);
        free(ptr3);
    }

    return 0;
}
