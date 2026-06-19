#ifndef CRYPTO_INTERFACE_H
#define CRYPTO_INTERFACE_H

#include <cstdint>
#include <string>
#include <vector>

#if defined(_WIN32)
#define EXPORT_API __declspec(dllexport)
#else
#define EXPORT_API __attribute__((visibility("default")))
#endif

extern "C" {
    typedef std::vector<uint8_t> (*EncryptFunc)(const std::vector<uint8_t>& data, const std::string& key);
    typedef std::vector<uint8_t> (*DecryptFunc)(const std::vector<uint8_t>& data, const std::string& key);
    typedef std::string (*GetNameFunc)();
    typedef void (*GenerateKeysFunc)(std::string& publicKey, std::string& privateKey);
}

#endif
