#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

int x = 0;

int main(int argc, char *argv[])
{
    printf("Hello %d\n", x++);

    return 0;
}
