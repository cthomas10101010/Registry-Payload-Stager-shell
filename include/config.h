#ifndef CONFIG_H
#define CONFIG_H

#include <vector>
#include <cstdint>  // Include this to define uint8_t
#include <string>   // Include this to define std::string

namespace config {
    const std::vector<uint8_t> encryptionKey = { 0x01, 0x02, 0x03, 0x04 };  // RC4 encryption key
    const std::string registryKey = "SOFTWARE\\YourRegistryKey";  // Update to your actual registry path
    const std::string valueName = "YourPayloadValue";  // Update to your actual value name
    const std::string binaryFilePath = "build/RegistryPayloadStager.exe";  // Path to the binary file for signing
}

#endif  // CONFIG_H