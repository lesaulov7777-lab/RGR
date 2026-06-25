#include "hex_utils.h"

#include <stdexcept>

char ToHexDigit(uint8_t value) {
    if (value < 10) {
        return static_cast<char>('0' + value);
    }

    return static_cast<char>('A' + value - 10);
}

uint8_t FromHexDigit(char symbol) {
    if (symbol >= '0' && symbol <= '9') {
        return static_cast<uint8_t>(symbol - '0');
    }

    if (symbol >= 'A' && symbol <= 'F') {
        return static_cast<uint8_t>(symbol - 'A' + 10);
    }

    if (symbol >= 'a' && symbol <= 'f') {
        return static_cast<uint8_t>(symbol - 'a' + 10);
    }

    throw std::invalid_argument("Некорректный HEX-символ");
}

std::string BytesToHex(const std::vector<uint8_t>& data) {
    std::string result;
    result.reserve(data.size() * 2);

    for (uint8_t byte : data) {
        result.push_back(ToHexDigit(static_cast<uint8_t>(byte >> 4)));
        result.push_back(ToHexDigit(static_cast<uint8_t>(byte & 15)));
    }

    return result;
}

std::vector<uint8_t> HexToBytes(const std::string& text) {
    if (text.size() % 2 != 0) {
        throw std::invalid_argument("HEX-строка должна иметь чётную длину");
    }

    std::vector<uint8_t> result;
    result.reserve(text.size() / 2);

    for (std::size_t i = 0; i < text.size(); i += 2) {
        uint8_t high = FromHexDigit(text[i]);
        uint8_t low = FromHexDigit(text[i + 1]);

        result.push_back(static_cast<uint8_t>((high << 4) | low));
    }

    return result;
}
