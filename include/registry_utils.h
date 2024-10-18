#ifndef REGISTRY_UTILS_H
#define REGISTRY_UTILS_H

#include <windows.h>
#include <string>

// Write shellcode to the registry
bool WriteShellcodeToRegistry(const std::string& key, const std::string& valueName, const BYTE* data, DWORD dataSize);

// Read shellcode from the registry
bool ReadShellcodeFromRegistry(const std::string& key, const std::string& valueName, BYTE* buffer, DWORD bufferSize);

#endif
