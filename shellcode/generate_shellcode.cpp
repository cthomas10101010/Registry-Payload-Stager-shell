//Purpose: Tool to generate or modify shellcode as needed.
#include "generate_shellcode.h"
#include <fstream>
#include <iostream>
#include <vector>

std::vector<uint8_t> GenerateShellcode(const std::string & filePath) {
    std::ifstream shellcodeFile(filePath, std::ios::binary);
    std::vector<uint8_t> shellcode;

    if (!shellcodeFile) {
        std::cerr << "Failed to open shellcode file: " << filePath << "\n";
        return shellcode;  // Return an empty vector on failure.
    }

    shellcodeFile.seekg(0, std::ios::end);
    size_t fileSize = shellcodeFile.tellg();
    shellcodeFile.seekg(0, std::ios::beg);

    shellcode.resize(fileSize);
    shellcodeFile.read(reinterpret_cast<char*>(shellcode.data()), fileSize);

    shellcodeFile.close();
    std::cout << "Shellcode loaded from " << filePath << "\n";
    return shellcode;
}
