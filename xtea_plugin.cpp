#include "crypto_interface.h"

#include <array>
#include <cstdint>
#include <random>
#include <stdexcept>
#include <string>
#include <vector>

namespace {
    uint32_t ReadUInt32(const uint8_t* data) {
        return static_cast<uint32_t>(data[0]) |
               (static_cast<uint32_t>(data[1]) << 8) |
               (static_cast<uint32_t>(data[2]) << 16) |
               (static_cast<uint32_t>(data[3]) << 24);
    }

    void WriteUInt32(uint32_t value, uint8_t* data) {
        data[0] = static_cast<uint8_t>(value & 0xFF);
        data[1] = static_cast<uint8_t>((value >> 8) & 0xFF);
        data[2] = static_cast<uint8_t>((value >> 16) & 0xFF);
        data[3] = static_cast<uint8_t>((value >> 24) & 0xFF);
    }

    std::array<uint32_t, 4> ParseKey(const std::string& key) {
        if (key.size() != 16) {
            throw std::invalid_argument("Ключ XTEA должен содержать ровно 16 символов");
        }

        std::array<uint32_t, 4> result{};
        const uint8_t* bytes = reinterpret_cast<const uint8_t*>(key.data());

        for (int i = 0; i < 4; ++i) {
            result[i] = ReadUInt32(bytes + i * 4);
        }

        return result;
    }

    void EncryptBlock(uint8_t* block, const std::array<uint32_t, 4>& key) {
        uint32_t v0 = ReadUInt32(block);
        uint32_t v1 = ReadUInt32(block + 4);
        uint32_t sum = 0;
        const uint32_t delta = 0x9E3779B9;

        for (int i = 0; i < 32; ++i) {
            v0 += (((v1 << 4) ^ (v1 >> 5)) + v1) ^ (sum + key[sum & 3]);
            sum += delta;
            v1 += (((v0 << 4) ^ (v0 >> 5)) + v0) ^ (sum + key[(sum >> 11) & 3]);
        }

        WriteUInt32(v0, block);
        WriteUInt32(v1, block + 4);
    }

    void DecryptBlock(uint8_t* block, const std::array<uint32_t, 4>& key) {
        uint32_t v0 = ReadUInt32(block);
        uint32_t v1 = ReadUInt32(block + 4);
        const uint32_t delta = 0x9E3779B9;
        uint32_t sum = delta * 32;

        for (int i = 0; i < 32; ++i) {
            v1 -= (((v0 << 4) ^ (v0 >> 5)) + v0) ^ (sum + key[(sum >> 11) & 3]);
            sum -= delta;
            v0 -= (((v1 << 4) ^ (v1 >> 5)) + v1) ^ (sum + key[sum & 3]);
        }

        WriteUInt32(v0, block);
        WriteUInt32(v1, block + 4);
    }

    std::vector<uint8_t> AddPadding(const std::vector<uint8_t>& data) {
        std::vector<uint8_t> result = data;
        uint8_t padding = static_cast<uint8_t>(8 - (result.size() % 8));

        if (padding == 0) {
            padding = 8;
        }

        result.insert(result.end(), padding, padding);
        return result;
    }

    std::vector<uint8_t> RemovePadding(const std::vector<uint8_t>& data) {
        if (data.empty() || data.size() % 8 != 0) {
            throw std::invalid_argument("Некорректный размер данных XTEA");
        }

        uint8_t padding = data.back();

        if (padding == 0 || padding > 8 || padding > data.size()) {
            throw std::invalid_argument("Некорректное дополнение данных XTEA");
        }

        for (std::size_t i = data.size() - padding; i < data.size(); ++i) {
            if (data[i] != padding) {
                throw std::invalid_argument("Некорректное дополнение данных XTEA");
            }
        }

        return std::vector<uint8_t>(data.begin(), data.end() - padding);
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
        return "XTEA";
    }

    EXPORT_API void generate_keys(std::string& publicKey, std::string& privateKey) {
        std::string key = RandomString(16);
        publicKey = key;
        privateKey = key;
    }

    EXPORT_API std::vector<uint8_t> encrypt_data(const std::vector<uint8_t>& data, const std::string& keyText) {
        std::array<uint32_t, 4> key = ParseKey(keyText);
        std::vector<uint8_t> result = AddPadding(data);

        for (std::size_t i = 0; i < result.size(); i += 8) {
            EncryptBlock(result.data() + i, key);
        }

        return result;
    }

    EXPORT_API std::vector<uint8_t> decrypt_data(const std::vector<uint8_t>& data, const std::string& keyText) {
        if (data.size() % 8 != 0) {
            throw std::invalid_argument("Размер шифртекста XTEA должен быть кратен 8");
        }

        std::array<uint32_t, 4> key = ParseKey(keyText);
        std::vector<uint8_t> result = data;

        for (std::size_t i = 0; i < result.size(); i += 8) {
            DecryptBlock(result.data() + i, key);
        }

        return RemovePadding(result);
    }
}
