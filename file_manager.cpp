#include "file_manager.h"

#include <fstream>
#include <stdexcept>

namespace file_manager {
    std::vector<uint8_t> read_file(const std::string& path) {
        std::ifstream file(path, std::ios::binary);

        if (!file) {
            throw std::runtime_error("Не удалось открыть файл для чтения: " + path);
        }

        return std::vector<uint8_t>(
            std::istreambuf_iterator<char>(file),
            std::istreambuf_iterator<char>()
        );
    }

    void write_file(const std::string& path, const std::vector<uint8_t>& data) {
        std::ofstream file(path, std::ios::binary);

        if (!file) {
            throw std::runtime_error("Не удалось открыть файл для записи: " + path);
        }

        file.write(
            reinterpret_cast<const char*>(data.data()),
            static_cast<std::streamsize>(data.size())
        );

        if (!file) {
            throw std::runtime_error("Ошибка записи файла: " + path);
        }
    }
}
