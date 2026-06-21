#ifndef BASE64_UTILS_H
#define BASE64_UTILS_H

#include <cstdint>
#include <string>
#include <vector>

std::string BytesToBase64(const std::vector<uint8_t>& data);
std::vector<uint8_t> Base64ToBytes(const std::string& text);

#endif
