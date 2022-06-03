#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

static uint8_t inputBuf[1 << 20];

char *Funct(uint8_t *ptr) {
	if (ptr[0] & 101) {
		return "a";
	}
	printf("%s\n", ptr);
	return "b";
}

char *Func(char *ptr) {
	ptr[1] = 1;
	return ptr;
}

void TestInput(uint8_t *ptr, size_t size) {
	uint8_t *new_ptr = (uint8_t*) malloc(sizeof(uint8_t) * size);
	memcpy(new_ptr, ptr, size);
	printf("%d\n", (int) new_ptr); 

	if (new_ptr[1] == 32) {
		free(new_ptr);
		free(new_ptr);
	}

	new_ptr[2] = 3;
	new_ptr[1] = 1;

	if (size == 1) {
		free(ptr);
	}

	printf("%s\n", "Nan");

	if (size == 2) {
		free(ptr);
	}
	
	if (ptr[1] & 100) {
		ptr = Funct(&ptr[1]);
	} else {
		ptr = Funct(&ptr[0]);
	}
	
	printf("%s\n", ptr);
}

int main(int argc, char *argv[]) {
	
	size_t size = (size_t) inputBuf[0];
	TestInput(&inputBuf[1], size);
	return 0;
}
