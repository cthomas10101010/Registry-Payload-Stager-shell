#pragma once
#ifndef RC4_H
#define RC4_H

#include <cstdint>
#include <vector>

void RC4EncryptDecrypt(std::vector<uint8_t>& data, const std::vector<uint8_t>& key);

#endif
