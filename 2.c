#include <stdio.h>
#include <stdlib.h>

int main() {
    int xa = 1000000000;
    int xb = 3000;
    int num = xa * xb;

    if (num < 0) {
        printf("Multiplication overflow occurred\n");
    } else {
        void *ptr = malloc(num);
        if (ptr == NULL) {
            printf("Memory allocation failed\n");
        } else {
            printf("Memory successfully allocated\n");
            free(ptr);
        }
    }

    return 0;
}
