Purpose: Implements the RC4 encryption and decryption algorithm.
#include "rc4.h"

void RC4EncryptDecrypt(std::vector<uint8_t>& data, const std::vector<uint8_t>& key) {
    std::vector<uint8_t> s(256);
    uint8_t j = 0;

    for (int i = 0; i < 256; ++i) {
        s[i] = i;
    }

    for (int i = 0, k = 0; i < 256; ++i) {
        k = (k + s[i] + key[i % key.size()]) % 256;
        std::swap(s[i], s[k]);
    }

    for (int i = 0, k = 0, l = 0; i < data.size(); ++i) {
        k = (k + 1) % 256;
        l = (l + s[k]) % 256;
        std::swap(s[k], s[l]);
        data[i] ^= s[(s[k] + s[l]) % 256];
    }
}
