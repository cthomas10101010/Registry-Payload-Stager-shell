#include "shellcode_handler.h"
#include <windows.h>
#include <iostream>

void ExecuteShellcode(const BYTE* shellcode, size_t size) {
    LPVOID execMemory = VirtualAlloc(NULL, size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!execMemory) {
        std::cerr << "Failed to allocate memory for shellcode.\n";
        return;
    }

    memcpy(execMemory, shellcode, size);

    // Cast the memory to a function pointer and execute the shellcode
    void (*func)() = (void (*)())execMemory;
    func();
}
