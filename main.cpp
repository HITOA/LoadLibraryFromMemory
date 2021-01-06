#include <iostream>
#include <fstream>
#include "LoadLibraryFromMemory.h"

int main(int argc, char* argv[]) {

	if (argc < 2) {
		std::cout << "No path specified" << std::endl;
		return EXIT_FAILURE;
	}

	std::ifstream file(argv[1], std::ios::binary);

	if (!file.is_open()) {
		return EXIT_FAILURE;
	}

	file.seekg(0, file.end);
	int size = file.tellg();
	file.seekg(0, file.beg);

	char* buffer = (char*)malloc(sizeof(char) * size);
	file.read(buffer, size);

	file.close();

	HMODULE module = LoadLibraryFromMemory((LPVOID)buffer);

	if (!module) {
		return GetLastError();
	}

	std::cout << "Module address : 0x" << module << std::endl;

	return EXIT_SUCCESS;
}