#ifndef CONFIG_H
#define CONFIG_H

#include <string>
#include <vector>

namespace config {
    const std::string registryKey = "Software\\MyApp\\Payload";
    const std::string valueName = "Shellcode";
    const std::vector<uint8_t> encryptionKey = { 0x01, 0x02, 0x03, 0x04 };  // Simple RC4 encryption key
    const std::string binaryFilePath = "Registry-Payload-Stager.exe";  // Binary path for signing
}

#endif
