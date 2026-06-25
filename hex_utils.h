#ifndef HEX_UTILS_H
#define HEX_UTILS_H

#include <cstdint>
#include <string>
#include <vector>

std::string BytesToHex(const std::vector<uint8_t>& data);
std::vector<uint8_t> HexToBytes(const std::string& text);

#endif
