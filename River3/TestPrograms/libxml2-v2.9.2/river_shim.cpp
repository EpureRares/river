#include <iostream>

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdint.h>

#include <fcntl.h> /* O_RDWR, O_CREAT, O_TRUNC, O_WRONLY */

extern "C" {
    int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size);
    __attribute__((weak)) int LLVMFuzzerInitialize(int *argc, char ***argv);
}

// Input buffer.
static const size_t kMaxInputSize = 1 << 20;
static uint8_t inputBuf[kMaxInputSize];
int main(int argc, char** argv)
{
    int fd1;

    if (LLVMFuzzerInitialize)
        LLVMFuzzerInitialize(&argc, &argv);

    while (1) {
        printf("Here with %d\n", 42);
        fd1 = open("out.txt", O_RDWR | O_CREAT, 0644);
        dprintf(fd1, "Here %d\n", 42);

        ssize_t n_read = read(0, inputBuf, kMaxInputSize);
        write(1, inputBuf, n_read);
        if (n_read > 0) {
            ////char len[2] = {(char)inputBuf[0], 0};
            ////size_t river_in_len = (size_t) atoi(len);
            //size_t river_in_len = (size_t) inputBuf[0];
            //uint8_t *copy = new uint8_t[river_in_len + 1];
            //memcpy(copy, inputBuf + 1, river_in_len);
            //copy[river_in_len] = 0;
            ////std::cout << copy << " " << river_in_len << "\n";
            //LLVMFuzzerTestOneInput(copy, river_in_len);

            //char len[2] = {(char)inputBuf[0], 0};
            //size_t river_in_len = (size_t) atoi(len);
            size_t river_in_len = (size_t) inputBuf[0];
            //uint8_t *copy = new uint8_t[river_in_len + 1];
            //memcpy(copy, inputBuf + 1, river_in_len);
            //copy[river_in_len] = 0;
            //std::cout << copy << " " << river_in_len << "\n";
            LLVMFuzzerTestOneInput(&inputBuf[1], river_in_len);
            //delete[] copy;
        }
    }
}
