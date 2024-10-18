#pragma once
#ifndef SHELLCODE_HANDLER_H
#define SHELLCODE_HANDLER_H

#include <windows.h>

void ExecuteShellcode(const BYTE* shellcode, size_t size);

#endif
