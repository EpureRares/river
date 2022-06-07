#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

static uint8_t inputBuf[1 << 20];

char *Funct(uint8_t *ptr) {
	if (ptr[0] & 101) {
		return "a";
	}
	return "b";
}

char *Func(char *ptr) {
	ptr[1] = 1;
	return ptr;
}

void TestInput(uint8_t *ptr, size_t size) {
	uint8_t *new_ptr = (uint8_t*) malloc(sizeof(uint8_t) * size);
	memcpy(new_ptr, ptr, size);
	printf("START\n"); 

	if (new_ptr[1] == 32) {
		printf("%s\n\n", "First vulnerability");
		free(new_ptr);
		free(new_ptr);
	}
	
	printf("%s\n", "First stage");

	new_ptr[2] = 3;
	new_ptr[1] = 1;

	if (size == 1) {
		printf("%s\n\n", "Second vulnerability");
		free(ptr);
	}

	printf("%s\n", "Second stage");

	if (size == 2) {
		printf("%s\n\n", "Third vulnerability");
		free(ptr);
	}
	
	printf("%s\n", "Third stage");

	if (ptr[1] & 100) {
		ptr = Funct(&ptr[1]);
	} else {
		ptr = Funct(&ptr[0]);
	}

	printf("\n");
	
}

int main(int argc, char *argv[]) {
	
	size_t size = (size_t) inputBuf[0];
	printf("Injected input: ");
	for(int i = 0; i < 4; i++) {
		printf("%d ", inputBuf[i]);
	}
	printf("\n====================\n");
	TestInput(&inputBuf[1], size);
	return 0;
}
