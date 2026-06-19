#include "crypto_interface.h"

#include <stdexcept>
#include <string>
#include <vector>
#include <random>

namespace {
    const std::string RUS_UPPER = "АБВГДЕЁЖЗИЙКЛМНОПРСТУФХЦЧШЩЪЫЬЭЮЯ";
    const std::string RUS_LOWER = "абвгдеёжзийклмнопрстуфхцчшщъыьэюя";
    const std::string LATIN_UPPER = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    const std::string LATIN_LOWER = "abcdefghijklmnopqrstuvwxyz";

    std::size_t Utf8CharLength(unsigned char c) {
        if ((c & 0x80) == 0) return 1;
        if ((c & 0xE0) == 0xC0) return 2;
        if ((c & 0xF0) == 0xE0) return 3;
        if ((c & 0xF8) == 0xF0) return 4;
        return 1;
    }

    std::vector<std::string> SplitUtf8(const std::string& text) {
        std::vector<std::string> result;

        for (std::size_t i = 0; i < text.size();) {
            std::size_t len = Utf8CharLength(static_cast<unsigned char>(text[i]));
            result.push_back(text.substr(i, len));
            i += len;
        }

        return result;
    }

    int FindIndex(const std::string& alphabet, const std::string& symbol) {
        int index = 0;

        for (std::size_t i = 0; i < alphabet.size();) {
            std::size_t len = Utf8CharLength(static_cast<unsigned char>(alphabet[i]));

            if (alphabet.substr(i, len) == symbol) {
                return index;
            }

            i += len;
            ++index;
        }

        return -1;
    }

    std::string CharByIndex(const std::string& alphabet, int index) {
        int current = 0;

        for (std::size_t i = 0; i < alphabet.size();) {
            std::size_t len = Utf8CharLength(static_cast<unsigned char>(alphabet[i]));

            if (current == index) {
                return alphabet.substr(i, len);
            }

            i += len;
            ++current;
        }

        return "";
    }

    bool IsLetter(const std::string& symbol) {
        return FindIndex(RUS_UPPER, symbol) >= 0 ||
               FindIndex(RUS_LOWER, symbol) >= 0 ||
               FindIndex(LATIN_UPPER, symbol) >= 0 ||
               FindIndex(LATIN_LOWER, symbol) >= 0;
    }

    int GetShiftValue(const std::string& keySymbol) {
        int index = FindIndex(LATIN_UPPER, keySymbol);
        if (index >= 0) return index;

        index = FindIndex(LATIN_LOWER, keySymbol);
        if (index >= 0) return index;

        index = FindIndex(RUS_UPPER, keySymbol);
        if (index >= 0) return index;

        index = FindIndex(RUS_LOWER, keySymbol);
        if (index >= 0) return index;

        if (keySymbol.size() == 1 && keySymbol[0] >= '0' && keySymbol[0] <= '9') {
            return keySymbol[0] - '0';
        }

        return 0;
    }

    std::string EncryptVigenere(const std::string& text, const std::string& key) {
        if (key.empty()) {
            throw std::invalid_argument("Ключ Виженера не должен быть пустым");
        }

        std::vector<std::string> textSymbols = SplitUtf8(text);
        std::vector<std::string> keySymbols = SplitUtf8(key);
        std::vector<int> shifts;

        for (const std::string& symbol : keySymbols) {
            shifts.push_back(GetShiftValue(symbol));
        }

        std::string result;
        int keyPosition = 0;

        for (const std::string& symbol : textSymbols) {
            if (!IsLetter(symbol)) {
                result += symbol;
                continue;
            }

            int shift = shifts[keyPosition % shifts.size()];

            int index = FindIndex(LATIN_UPPER, symbol);
            if (index >= 0) {
                result += CharByIndex(LATIN_UPPER, (index + shift) % 26);
                ++keyPosition;
                continue;
            }

            index = FindIndex(LATIN_LOWER, symbol);
            if (index >= 0) {
                result += CharByIndex(LATIN_LOWER, (index + shift) % 26);
                ++keyPosition;
                continue;
            }

            index = FindIndex(RUS_UPPER, symbol);
            if (index >= 0) {
                result += CharByIndex(RUS_UPPER, (index + shift) % 33);
                ++keyPosition;
                continue;
            }

            index = FindIndex(RUS_LOWER, symbol);
            if (index >= 0) {
                result += CharByIndex(RUS_LOWER, (index + shift) % 33);
                ++keyPosition;
                continue;
            }

            result += symbol;
        }

        return result;
    }

    std::string DecryptVigenere(const std::string& text, const std::string& key) {
        if (key.empty()) {
            throw std::invalid_argument("Ключ Виженера не должен быть пустым");
        }

        std::vector<std::string> textSymbols = SplitUtf8(text);
        std::vector<std::string> keySymbols = SplitUtf8(key);
        std::vector<int> shifts;

        for (const std::string& symbol : keySymbols) {
            shifts.push_back(GetShiftValue(symbol));
        }

        std::string result;
        int keyPosition = 0;

        for (const std::string& symbol : textSymbols) {
            if (!IsLetter(symbol)) {
                result += symbol;
                continue;
            }

            int shift = shifts[keyPosition % shifts.size()];

            int index = FindIndex(LATIN_UPPER, symbol);
            if (index >= 0) {
                result += CharByIndex(LATIN_UPPER, (index - shift + 26) % 26);
                ++keyPosition;
                continue;
            }

            index = FindIndex(LATIN_LOWER, symbol);
            if (index >= 0) {
                result += CharByIndex(LATIN_LOWER, (index - shift + 26) % 26);
                ++keyPosition;
                continue;
            }

            index = FindIndex(RUS_UPPER, symbol);
            if (index >= 0) {
                result += CharByIndex(RUS_UPPER, (index - shift + 33) % 33);
                ++keyPosition;
                continue;
            }

            index = FindIndex(RUS_LOWER, symbol);
            if (index >= 0) {
                result += CharByIndex(RUS_LOWER, (index - shift + 33) % 33);
                ++keyPosition;
                continue;
            }

            result += symbol;
        }

        return result;
    }

    std::vector<uint8_t> StringToBytes(const std::string& text) {
        return std::vector<uint8_t>(text.begin(), text.end());
    }

    std::string BytesToString(const std::vector<uint8_t>& data) {
        return std::string(data.begin(), data.end());
    }
}

extern "C" {
    EXPORT_API std::string get_algorithm_name() {
        return "Шифр Виженера";
    }

    EXPORT_API void generate_keys(std::string& publicKey, std::string& privateKey) {
    std::string alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";

    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dist(0, alphabet.size() - 1);

    std::string key;
    int keyLength = 8;

    for (int i = 0; i < keyLength; ++i) {
        key += alphabet[dist(gen)];
    }

    publicKey = key;
    privateKey = key;
    }

    EXPORT_API std::vector<uint8_t> encrypt_data(const std::vector<uint8_t>& data, const std::string& key) {
        return StringToBytes(EncryptVigenere(BytesToString(data), key));
    }

    EXPORT_API std::vector<uint8_t> decrypt_data(const std::vector<uint8_t>& data, const std::string& key) {
        return StringToBytes(DecryptVigenere(BytesToString(data), key));
    }
}
