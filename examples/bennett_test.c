#include <stdio.h>
#include <syscall.h>

int main (int argc, char **argv) {
    int i;

    for (i = 0; i < 10; i++) {
        printf("%d\n", i);
    }

    return EXIT_SUCCESS;
}