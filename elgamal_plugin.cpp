#include "crypto_interface.h"

#include <cstdint>
#include <random>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

namespace {
    struct ElGamalPair {
        long long a;
        long long b;
    };

    struct PublicKey {
        long long p;
        long long g;
        long long y;
    };

    struct PrivateKey {
        long long p;
        long long x;
    };

    long long PositiveMod(long long value, long long mod) {
        long long result = value % mod;

        if (result < 0) {
            result += mod;
        }

        return result;
    }

    long long ModPow(long long base, long long power, long long mod) {
        long long result = 1;
        base = PositiveMod(base, mod);

        while (power > 0) {
            if (power % 2 == 1) {
                result = (result * base) % mod;
            }

            base = (base * base) % mod;
            power /= 2;
        }

        return result;
    }

    bool IsPrime(long long number) {
        if (number < 2) {
            return false;
        }

        if (number == 2) {
            return true;
        }

        if (number % 2 == 0) {
            return false;
        }

        for (long long i = 3; i * i <= number; i += 2) {
            if (number % i == 0) {
                return false;
            }
        }

        return true;
    }

    PublicKey ParsePublicKey(const std::string& key) {
        std::istringstream stream(key);

        PublicKey publicKey{};

        if (!(stream >> publicKey.p >> publicKey.g >> publicKey.y)) {
            throw std::invalid_argument(
                "Открытый ключ Эль-Гамаля должен иметь формат: p g y"
            );
        }

        if (!IsPrime(publicKey.p)) {
            throw std::invalid_argument("p должно быть простым числом");
        }

        if (publicKey.p <= 255) {
            throw std::invalid_argument(
                "p должно быть больше 255 для шифрования байтов"
            );
        }

        return publicKey;
    }

    PrivateKey ParsePrivateKey(const std::string& key) {
        std::istringstream stream(key);

        PrivateKey privateKey{};

        if (!(stream >> privateKey.p >> privateKey.x)) {
            throw std::invalid_argument(
                "Закрытый ключ Эль-Гамаля должен иметь формат: p x"
            );
        }

        if (!IsPrime(privateKey.p)) {
            throw std::invalid_argument("p должно быть простым числом");
        }

        if (privateKey.p <= 255) {
            throw std::invalid_argument(
                "p должно быть больше 255 для расшифрования байтов"
            );
        }

        return privateKey;
    }

    long long GenerateRandomNumber(long long minValue, long long maxValue) {
        static std::random_device rd;
        static std::mt19937_64 gen(rd());

        std::uniform_int_distribution<long long> dist(minValue, maxValue);
        return dist(gen);
    }

    ElGamalPair EncryptByte(unsigned char byteValue, const PublicKey& key) {
        long long m = static_cast<long long>(byteValue);

        long long k = GenerateRandomNumber(1, key.p - 2);

        long long a = ModPow(key.g, k, key.p);
        long long yPowK = ModPow(key.y, k, key.p);
        long long b = (m * yPowK) % key.p;

        return {a, b};
    }

    unsigned char DecryptByte(const ElGamalPair& pair, const PrivateKey& key) {
        long long sharedSecret = ModPow(pair.a, key.x, key.p);

        long long inverse = ModPow(sharedSecret, key.p - 2, key.p);

        long long m = (pair.b * inverse) % key.p;

        if (m < 0 || m > 255) {
            throw std::runtime_error(
                "Ошибка расшифрования: полученное значение не является байтом"
            );
        }

        return static_cast<unsigned char>(m);
    }

    std::string EncryptBytesToPairsText(
        const std::vector<uint8_t>& data,
        const PublicKey& key
    ) {
        std::ostringstream result;

        for (std::size_t i = 0; i < data.size(); ++i) {
            ElGamalPair pair = EncryptByte(data[i], key);

            if (i > 0) {
                result << ' ';
            }

            result << pair.a << ':' << pair.b;
        }

        return result.str();
    }

    std::vector<uint8_t> DecryptPairsTextToBytes(
        const std::string& encryptedText,
        const PrivateKey& key
    ) {
        std::istringstream stream(encryptedText);
        std::string token;
        std::vector<uint8_t> result;

        while (stream >> token) {
            std::size_t separatorPosition = token.find(':');

            if (separatorPosition == std::string::npos) {
                throw std::invalid_argument(
                    "Шифртекст Эль-Гамаля должен состоять из пар a:b"
                );
            }

            std::string aText = token.substr(0, separatorPosition);
            std::string bText = token.substr(separatorPosition + 1);

            ElGamalPair pair{};
            pair.a = std::stoll(aText);
            pair.b = std::stoll(bText);

            result.push_back(DecryptByte(pair, key));
        }

        return result;
    }
}

extern "C" {
    EXPORT_API std::string get_algorithm_name() {
        return "Эль-Гамаль";
    }

    EXPORT_API void generate_keys(std::string& publicKey, std::string& privateKey) {
        const long long p = 467;
        const long long g = 2;

        long long x = GenerateRandomNumber(2, p - 2);
        long long y = ModPow(g, x, p);

        publicKey =
            std::to_string(p) + " " +
            std::to_string(g) + " " +
            std::to_string(y);

        privateKey =
            std::to_string(p) + " " +
            std::to_string(x);
    }

    EXPORT_API std::vector<uint8_t> encrypt_data(
        const std::vector<uint8_t>& data,
        const std::string& key
    ) {
        PublicKey publicKey = ParsePublicKey(key);

        std::string encryptedText = EncryptBytesToPairsText(data, publicKey);

        return std::vector<uint8_t>(
            encryptedText.begin(),
            encryptedText.end()
        );
    }

    EXPORT_API std::vector<uint8_t> decrypt_data(
        const std::vector<uint8_t>& data,
        const std::string& key
    ) {
        PrivateKey privateKey = ParsePrivateKey(key);

        std::string encryptedText(data.begin(), data.end());

        std::vector<uint8_t> decryptedBytes =
            DecryptPairsTextToBytes(encryptedText, privateKey);

        return decryptedBytes;
    }
}