#ifndef FILE_MANAGER_H
#define FILE_MANAGER_H

#include <cstdint>
#include <string>
#include <vector>

namespace file_manager {
    std::vector<uint8_t> read_file(const std::string& path);
    void write_file(const std::string& path, const std::vector<uint8_t>& data);
}

#endif
