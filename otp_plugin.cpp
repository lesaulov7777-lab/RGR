#include "crypto_interface.h"

#include <random>
#include <stdexcept>
#include <string>
#include <vector>

namespace {
    const std::string BASE64_ALPHABET =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "abcdefghijklmnopqrstuvwxyz"
        "0123456789+/";

    std::vector<uint8_t> OtpProcess(const std::vector<uint8_t>& data, const std::string& key) {
        if (key.empty()) {
            throw std::invalid_argument("Ключ OTP не должен быть пустым");
        }

        if (key.size() < data.size()) {
            throw std::invalid_argument("Для OTP ключ должен быть не короче данных");
        }

        std::vector<uint8_t> result(data.size());

        for (std::size_t i = 0; i < data.size(); ++i) {
            result[i] = data[i] ^ static_cast<uint8_t>(key[i]);
        }

        return result;
    }

    std::vector<uint8_t> RandomBytes(std::size_t length) {
        static std::random_device rd;
        static std::mt19937 gen(rd());
        std::uniform_int_distribution<int> dist(0, 255);

        std::vector<uint8_t> result(length);

        for (uint8_t& byte : result) {
            byte = static_cast<uint8_t>(dist(gen));
        }

        return result;
    }

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
}

extern "C" {
    EXPORT_API std::string get_algorithm_name() {
        return "OTP";
    }

    EXPORT_API void generate_keys(std::string& publicKey, std::string& privateKey) {
        std::string key = BytesToBase64(RandomBytes(1024));
        publicKey = key;
        privateKey = key;
    }

    EXPORT_API std::vector<uint8_t> encrypt_data(const std::vector<uint8_t>& data, const std::string& key) {
        return OtpProcess(data, key);
    }

    EXPORT_API std::vector<uint8_t> decrypt_data(const std::vector<uint8_t>& data, const std::string& key) {
        return OtpProcess(data, key);
    }
}
