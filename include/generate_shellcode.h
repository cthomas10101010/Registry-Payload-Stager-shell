#pragma once
#ifndef GENERATE_SHELLCODE_H
#define GENERATE_SHELLCODE_H

#include <vector>

std::vector<uint8_t> GenerateShellcode(const std::string& filePath);

#endif
