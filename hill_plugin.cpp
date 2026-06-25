#include "crypto_interface.h"

#include <cstdint>
#include <numeric>
#include <random>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

namespace {
    enum class AlphabetType {
        None,
        Latin,
        Russian
    };

    struct SymbolInfo {
        std::string symbol;
        AlphabetType type;
        bool upper;
        int index;
    };

    struct Matrix2x2 {
        int a;
        int b;
        int c;
        int d;
    };

    std::size_t Utf8CharLength(unsigned char c) {
        if ((c & 0x80) == 0) return 1;
        if ((c & 0xE0) == 0xC0) return 2;
        if ((c & 0xF0) == 0xE0) return 3;
        if ((c & 0xF8) == 0xF0) return 4;
        return 1;
    }

    std::vector<std::string> SplitUtf8(const std::string& text) {
        std::vector<std::string> symbols;

        for (std::size_t i = 0; i < text.size();) {
            std::size_t len = Utf8CharLength(static_cast<unsigned char>(text[i]));
            symbols.push_back(text.substr(i, len));
            i += len;
        }

        return symbols;
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

    int PositiveMod(int value, int mod) {
        int result = value % mod;
        if (result < 0) {
            result += mod;
        }
        return result;
    }

    int ModInverse(int value, int mod) {
        value = PositiveMod(value, mod);

        for (int i = 1; i < mod; ++i) {
            if ((value * i) % mod == 1) {
                return i;
            }
        }

        throw std::runtime_error("Для матрицы Хилла невозможно найти обратную матрицу");
    }

    Matrix2x2 ParseKey(const std::string& key) {
        std::istringstream stream(key);
        Matrix2x2 matrix{};

        if (!(stream >> matrix.a >> matrix.b >> matrix.c >> matrix.d)) {
            throw std::invalid_argument("Ключ Хилла должен иметь формат: a b c d");
        }

        return matrix;
    }

    bool IsValidMatrixForMod(const Matrix2x2& matrix, int mod) {
        int det = matrix.a * matrix.d - matrix.b * matrix.c;
        det = PositiveMod(det, mod);

        return std::gcd(det, mod) == 1;
    }

    bool IsValidHillMatrix(const Matrix2x2& matrix) {
        return IsValidMatrixForMod(matrix, 26) &&
               IsValidMatrixForMod(matrix, 33);
    }

    Matrix2x2 GetInverseMatrix(const Matrix2x2& matrix, int mod) {
        int det = matrix.a * matrix.d - matrix.b * matrix.c;
        det = PositiveMod(det, mod);

        int invDet = ModInverse(det, mod);

        Matrix2x2 inverse{};
        inverse.a = PositiveMod(invDet * matrix.d, mod);
        inverse.b = PositiveMod(invDet * (-matrix.b), mod);
        inverse.c = PositiveMod(invDet * (-matrix.c), mod);
        inverse.d = PositiveMod(invDet * matrix.a, mod);

        return inverse;
    }

    SymbolInfo GetSymbolInfo(const std::string& symbol) {
        char32_t code = DecodeUtf8(symbol);

        if (code >= static_cast<char32_t>('A') && code <= static_cast<char32_t>('Z')) {
            return {symbol, AlphabetType::Latin, true, static_cast<int>(code - static_cast<char32_t>('A'))};
        }

        if (code >= static_cast<char32_t>('a') && code <= static_cast<char32_t>('z')) {
            return {symbol, AlphabetType::Latin, false, static_cast<int>(code - static_cast<char32_t>('a'))};
        }

        int index = RussianIndex(code, true);
        if (index >= 0) {
            return {symbol, AlphabetType::Russian, true, index};
        }

        index = RussianIndex(code, false);
        if (index >= 0) {
            return {symbol, AlphabetType::Russian, false, index};
        }

        return {symbol, AlphabetType::None, false, -1};
    }

    std::string MakeSymbol(AlphabetType type, bool upper, int index) {
        if (type == AlphabetType::Latin) {
            char32_t start = upper ? static_cast<char32_t>('A') : static_cast<char32_t>('a');
            return EncodeUtf8(start + static_cast<char32_t>(index));
        }

        if (type == AlphabetType::Russian) {
            char32_t start = upper ? 0x0410 : 0x0430;
            char32_t yo = upper ? 0x0401 : 0x0451;

            if (index == 6) {
                return EncodeUtf8(yo);
            }

            if (index < 6) {
                return EncodeUtf8(start + static_cast<char32_t>(index));
            }

            return EncodeUtf8(start + static_cast<char32_t>(index - 1));
        }

        return "";
    }

    int GetAlphabetSize(AlphabetType type) {
        if (type == AlphabetType::Latin) {
            return 26;
        }

        if (type == AlphabetType::Russian) {
            return 33;
        }

        return 0;
    }

    void EncryptPair(
        const SymbolInfo& first,
        const SymbolInfo& second,
        const Matrix2x2& matrix,
        std::string& result
    ) {
        int mod = GetAlphabetSize(first.type);

        int x1 = first.index;
        int x2 = second.index;

        int y1 = PositiveMod(matrix.a * x1 + matrix.b * x2, mod);
        int y2 = PositiveMod(matrix.c * x1 + matrix.d * x2, mod);

        result += MakeSymbol(first.type, first.upper, y1);
        result += MakeSymbol(second.type, second.upper, y2);
    }

    void DecryptPair(
        const SymbolInfo& first,
        const SymbolInfo& second,
        const Matrix2x2& matrix,
        std::string& result
    ) {
        int mod = GetAlphabetSize(first.type);
        Matrix2x2 inverse = GetInverseMatrix(matrix, mod);

        int y1 = first.index;
        int y2 = second.index;

        int x1 = PositiveMod(inverse.a * y1 + inverse.b * y2, mod);
        int x2 = PositiveMod(inverse.c * y1 + inverse.d * y2, mod);

        result += MakeSymbol(first.type, first.upper, x1);
        result += MakeSymbol(second.type, second.upper, x2);
    }

    std::string ProcessHill(
        const std::string& text,
        const std::string& key,
        bool encrypt
    ) {
        Matrix2x2 matrix = ParseKey(key);

        if (!IsValidHillMatrix(matrix)) {
            throw std::invalid_argument(
                "Матрица Хилла должна быть обратимой по модулю 26 и 33"
            );
        }

        std::vector<std::string> symbols = SplitUtf8(text);

        std::string result;
        bool hasPending = false;
        SymbolInfo pending{};

        for (const std::string& symbol : symbols) {
            SymbolInfo current = GetSymbolInfo(symbol);

            if (current.type == AlphabetType::None) {
                if (hasPending) {
                    result += pending.symbol;
                    hasPending = false;
                }

                result += symbol;
                continue;
            }

            if (!hasPending) {
                pending = current;
                hasPending = true;
                continue;
            }

            if (pending.type != current.type) {
                result += pending.symbol;
                pending = current;
                hasPending = true;
                continue;
            }

            if (encrypt) {
                EncryptPair(pending, current, matrix, result);
            } else {
                DecryptPair(pending, current, matrix, result);
            }

            hasPending = false;
        }

        if (hasPending) {
            result += pending.symbol;
        }

        return result;
    }

    Matrix2x2 GenerateRandomMatrix() {
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<int> dist(0, 32);

        Matrix2x2 matrix{};

        do {
            matrix.a = dist(gen);
            matrix.b = dist(gen);
            matrix.c = dist(gen);
            matrix.d = dist(gen);
        } while (!IsValidHillMatrix(matrix));

        return matrix;
    }

    std::string MatrixToString(const Matrix2x2& matrix) {
        return std::to_string(matrix.a) + " " +
               std::to_string(matrix.b) + " " +
               std::to_string(matrix.c) + " " +
               std::to_string(matrix.d);
    }
}

extern "C" {
    EXPORT_API std::string get_algorithm_name() {
        return "Шифр Хилла";
    }

    EXPORT_API void generate_keys(std::string& publicKey, std::string& privateKey) {
        Matrix2x2 matrix = GenerateRandomMatrix();
        std::string key = MatrixToString(matrix);

        publicKey = key;
        privateKey = key;
    }

    EXPORT_API std::vector<uint8_t> encrypt_data(
        const std::vector<uint8_t>& data,
        const std::string& key
    ) {
        std::string text(data.begin(), data.end());
        std::string encrypted = ProcessHill(text, key, true);

        return std::vector<uint8_t>(encrypted.begin(), encrypted.end());
    }

    EXPORT_API std::vector<uint8_t> decrypt_data(
        const std::vector<uint8_t>& data,
        const std::string& key
    ) {
        std::string text(data.begin(), data.end());
        std::string decrypted = ProcessHill(text, key, false);

        return std::vector<uint8_t>(decrypted.begin(), decrypted.end());
    }
}
