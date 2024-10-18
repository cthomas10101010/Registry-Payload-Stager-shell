#pragma once
#ifndef REGISTRY_UTILS_H
#define REGISTRY_UTILS_H

#include <windows.h>
#include <string>

bool WriteShellcodeToRegistry(const std::string& key, const std::string& valueName, const BYTE* data, DWORD dataSize);
bool ReadShellcodeFromRegistry(const std::string& key, const std::string& valueName, BYTE* buffer, DWORD bufferSize);

#endif
