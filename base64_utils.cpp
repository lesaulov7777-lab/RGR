#include "base64_utils.h"

#include <array>
#include <cctype>
#include <stdexcept>

static const std::string BASE64_ALPHABET =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "abcdefghijklmnopqrstuvwxyz"
    "0123456789+/";

std::string BytesToBase64(const std::vector<uint8_t>& data) {
    std::string result;
    int value = 0;
    int bits = -6;

    for (uint8_t byte : data) {
        value = (value << 8) + byte;
        bits += 8;

        while (bits >= 0) {
            result.push_back(BASE64_ALPHABET[(value >> bits) & 0x3F]);
            bits -= 6;
        }
    }

    if (bits > -6) {
        result.push_back(BASE64_ALPHABET[((value << 8) >> (bits + 8)) & 0x3F]);
    }

    while (result.size() % 4 != 0) {
        result.push_back('=');
    }

    return result;
}

std::vector<uint8_t> Base64ToBytes(const std::string& text) {
    std::array<int, 256> table{};
    table.fill(-1);

    for (int i = 0; i < 64; ++i) {
        table[static_cast<unsigned char>(BASE64_ALPHABET[i])] = i;
    }

    std::vector<uint8_t> result;
    int value = 0;
    int bits = -8;

    for (unsigned char symbol : text) {
        if (std::isspace(symbol)) {
            continue;
        }

        if (symbol == '=') {
            break;
        }

        int decoded = table[symbol];
        if (decoded == -1) {
            throw std::invalid_argument("Некорректная Base64-строка");
        }

        value = (value << 6) + decoded;
        bits += 6;

        if (bits >= 0) {
            result.push_back(static_cast<uint8_t>((value >> bits) & 0xFF));
            bits -= 8;
        }
    }

    return result;
}
