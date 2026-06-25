#include "crypto_interface.h"

#include <algorithm>
#include <array>
#include <random>
#include <stdexcept>
#include <string>
#include <vector>

namespace {
    std::vector<uint8_t> Rc4Process(const std::vector<uint8_t>& data, const std::string& key) {
        if (key.empty()) {
            throw std::invalid_argument("Ключ RC4 не должен быть пустым");
        }

        std::array<uint8_t, 256> s{};
        for (int i = 0; i < 256; ++i) {
            s[i] = static_cast<uint8_t>(i);
        }

        int j = 0;
        for (int i = 0; i < 256; ++i) {
            j = (j + s[i] + static_cast<uint8_t>(key[i % key.size()])) % 256;
            std::swap(s[i], s[j]);
        }

        std::vector<uint8_t> result(data.size());
        int i = 0;
        j = 0;

        for (std::size_t n = 0; n < data.size(); ++n) {
            i = (i + 1) % 256;
            j = (j + s[i]) % 256;
            std::swap(s[i], s[j]);

            uint8_t gamma = s[(s[i] + s[j]) % 256];
            result[n] = data[n] ^ gamma;
        }

        return result;
    }

    char RandomKeySymbol(std::mt19937& gen) {
        std::uniform_int_distribution<int> typeDist(0, 2);
        int type = typeDist(gen);

        if (type == 0) {
            std::uniform_int_distribution<int> dist('a', 'z');
            return static_cast<char>(dist(gen));
        }

        if (type == 1) {
            std::uniform_int_distribution<int> dist('A', 'Z');
            return static_cast<char>(dist(gen));
        }

        std::uniform_int_distribution<int> dist('0', '9');
        return static_cast<char>(dist(gen));
    }

    std::string RandomString(std::size_t length) {
        static std::random_device rd;
        static std::mt19937 gen(rd());

        std::string result;
        result.reserve(length);

        for (std::size_t i = 0; i < length; ++i) {
            result.push_back(RandomKeySymbol(gen));
        }

        return result;
    }
}

extern "C" {
    EXPORT_API std::string get_algorithm_name() {
        return "RC4";
    }

    EXPORT_API void generate_keys(std::string& publicKey, std::string& privateKey) {
        std::string key = RandomString(16);
        publicKey = key;
        privateKey = key;
    }

    EXPORT_API std::vector<uint8_t> encrypt_data(const std::vector<uint8_t>& data, const std::string& key) {
        return Rc4Process(data, key);
    }

    EXPORT_API std::vector<uint8_t> decrypt_data(const std::vector<uint8_t>& data, const std::string& key) {
        return Rc4Process(data, key);
    }
}
