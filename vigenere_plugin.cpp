#include "crypto_interface.h"

#include <cstdint>
#include <random>
#include <stdexcept>
#include <string>
#include <vector>

namespace {
    struct LetterInfo {
        bool isLetter;
        bool isLatin;
        bool upper;
        int index;
        int size;
    };

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

    char32_t DecodeUtf8(const std::string& symbol) {
        if (symbol.empty()) {
            return 0;
        }

        const unsigned char* bytes = reinterpret_cast<const unsigned char*>(symbol.data());

        if (symbol.size() == 1) {
            return bytes[0];
        }

        if (symbol.size() == 2) {
            return (static_cast<char32_t>(bytes[0] & 31) << 6) |
                   static_cast<char32_t>(bytes[1] & 63);
        }

        if (symbol.size() == 3) {
            return (static_cast<char32_t>(bytes[0] & 15) << 12) |
                   (static_cast<char32_t>(bytes[1] & 63) << 6) |
                   static_cast<char32_t>(bytes[2] & 63);
        }

        if (symbol.size() == 4) {
            return (static_cast<char32_t>(bytes[0] & 7) << 18) |
                   (static_cast<char32_t>(bytes[1] & 63) << 12) |
                   (static_cast<char32_t>(bytes[2] & 63) << 6) |
                   static_cast<char32_t>(bytes[3] & 63);
        }

        return 0;
    }

    std::string EncodeUtf8(char32_t code) {
        std::string result;

        if (code <= 0x7F) {
            result.push_back(static_cast<char>(code));
            return result;
        }

        if (code <= 0x7FF) {
            result.push_back(static_cast<char>(0xC0 | (code >> 6)));
            result.push_back(static_cast<char>(0x80 | (code & 0x3F)));
            return result;
        }

        if (code <= 0xFFFF) {
            result.push_back(static_cast<char>(0xE0 | (code >> 12)));
            result.push_back(static_cast<char>(0x80 | ((code >> 6) & 0x3F)));
            result.push_back(static_cast<char>(0x80 | (code & 0x3F)));
            return result;
        }

        result.push_back(static_cast<char>(0xF0 | (code >> 18)));
        result.push_back(static_cast<char>(0x80 | ((code >> 12) & 0x3F)));
        result.push_back(static_cast<char>(0x80 | ((code >> 6) & 0x3F)));
        result.push_back(static_cast<char>(0x80 | (code & 0x3F)));
        return result;
    }

    int RussianIndex(char32_t code, bool upper) {
        char32_t start = upper ? 0x0410 : 0x0430;
        char32_t end = upper ? 0x042F : 0x044F;
        char32_t yo = upper ? 0x0401 : 0x0451;

        if (code == yo) {
            return 6;
        }

        if (code >= start && code <= start + 5) {
            return static_cast<int>(code - start);
        }

        if (code >= start + 6 && code <= end) {
            return static_cast<int>(code - start + 1);
        }

        return -1;
    }

    LetterInfo GetLetterInfo(const std::string& symbol) {
        char32_t code = DecodeUtf8(symbol);

        if (code >= static_cast<char32_t>('A') && code <= static_cast<char32_t>('Z')) {
            return {true, true, true, static_cast<int>(code - static_cast<char32_t>('A')), 26};
        }

        if (code >= static_cast<char32_t>('a') && code <= static_cast<char32_t>('z')) {
            return {true, true, false, static_cast<int>(code - static_cast<char32_t>('a')), 26};
        }

        int index = RussianIndex(code, true);
        if (index >= 0) {
            return {true, false, true, index, 33};
        }

        index = RussianIndex(code, false);
        if (index >= 0) {
            return {true, false, false, index, 33};
        }

        return {false, false, false, -1, 0};
    }

    std::string MakeLetter(const LetterInfo& info, int index) {
        if (info.isLatin) {
            char32_t start = info.upper ? static_cast<char32_t>('A') : static_cast<char32_t>('a');
            return EncodeUtf8(start + static_cast<char32_t>(index));
        }

        char32_t start = info.upper ? 0x0410 : 0x0430;
        char32_t yo = info.upper ? 0x0401 : 0x0451;

        if (index == 6) {
            return EncodeUtf8(yo);
        }

        if (index < 6) {
            return EncodeUtf8(start + static_cast<char32_t>(index));
        }

        return EncodeUtf8(start + static_cast<char32_t>(index - 1));
    }

    int PositiveMod(int value, int mod) {
        int result = value % mod;
        if (result < 0) {
            result += mod;
        }
        return result;
    }

    int GetShiftValue(const std::string& keySymbol) {
        LetterInfo info = GetLetterInfo(keySymbol);
        if (info.isLetter) {
            return info.index;
        }

        if (keySymbol.size() == 1 && keySymbol[0] >= '0' && keySymbol[0] <= '9') {
            return keySymbol[0] - '0';
        }

        return 0;
    }

    std::string ProcessVigenere(const std::string& text, const std::string& key, bool encrypt) {
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
            LetterInfo info = GetLetterInfo(symbol);

            if (!info.isLetter) {
                result += symbol;
                continue;
            }

            int shift = shifts[keyPosition % shifts.size()];
            int newIndex = encrypt
                ? PositiveMod(info.index + shift, info.size)
                : PositiveMod(info.index - shift, info.size);

            result += MakeLetter(info, newIndex);
            ++keyPosition;
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
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<int> dist(0, 25);

        std::string key;
        int keyLength = 8;

        for (int i = 0; i < keyLength; ++i) {
            key.push_back(static_cast<char>('A' + dist(gen)));
        }

        publicKey = key;
        privateKey = key;
    }

    EXPORT_API std::vector<uint8_t> encrypt_data(const std::vector<uint8_t>& data, const std::string& key) {
        return StringToBytes(ProcessVigenere(BytesToString(data), key, true));
    }

    EXPORT_API std::vector<uint8_t> decrypt_data(const std::vector<uint8_t>& data, const std::string& key) {
        return StringToBytes(ProcessVigenere(BytesToString(data), key, false));
    }
}
