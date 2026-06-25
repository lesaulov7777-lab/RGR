#include "crypto_interface.h"

#include <cstdint>
#include <cstdlib>
#include <numeric>
#include <random>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

namespace {
    const std::string RUS_UPPER = "АБВГДЕЁЖЗИЙКЛМНОПРСТУФХЦЧШЩЪЫЬЭЮЯ";
    const std::string RUS_LOWER = "абвгдеёжзийклмнопрстуфхцчшщъыьэюя";
    const std::string LATIN_UPPER = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    const std::string LATIN_LOWER = "abcdefghijklmnopqrstuvwxyz";

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
        int currentIndex = 0;

        for (std::size_t i = 0; i < alphabet.size();) {
            std::size_t len = Utf8CharLength(static_cast<unsigned char>(alphabet[i]));

            if (currentIndex == index) {
                return alphabet.substr(i, len);
            }

            i += len;
            ++currentIndex;
        }

        return "";
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
        int index = FindIndex(LATIN_UPPER, symbol);
        if (index >= 0) {
            return {symbol, AlphabetType::Latin, true, index};
        }

        index = FindIndex(LATIN_LOWER, symbol);
        if (index >= 0) {
            return {symbol, AlphabetType::Latin, false, index};
        }

        index = FindIndex(RUS_UPPER, symbol);
        if (index >= 0) {
            return {symbol, AlphabetType::Russian, true, index};
        }

        index = FindIndex(RUS_LOWER, symbol);
        if (index >= 0) {
            return {symbol, AlphabetType::Russian, false, index};
        }

        return {symbol, AlphabetType::None, false, -1};
    }

    std::string MakeSymbol(AlphabetType type, bool upper, int index) {
        if (type == AlphabetType::Latin) {
            if (upper) {
                return CharByIndex(LATIN_UPPER, index);
            }

            return CharByIndex(LATIN_LOWER, index);
        }

        if (type == AlphabetType::Russian) {
            if (upper) {
                return CharByIndex(RUS_UPPER, index);
            }

            return CharByIndex(RUS_LOWER, index);
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