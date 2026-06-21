#include "plugin_manager.h"

#include <dlfcn.h>
#include <filesystem>
#include <iostream>
#include <stdexcept>
#include <utility>

namespace fs = std::filesystem;

Plugin::~Plugin() {
    unload();
}

Plugin::Plugin(Plugin&& other) noexcept {
    *this = std::move(other);
}

Plugin& Plugin::operator=(Plugin&& other) noexcept {
    if (this != &other) {
        unload();

        handle_ = other.handle_;
        filename_ = std::move(other.filename_);
        name_ = std::move(other.name_);
        encrypt_ = other.encrypt_;
        decrypt_ = other.decrypt_;
        getName_ = other.getName_;
        generateKeys_ = other.generateKeys_;

        other.handle_ = nullptr;
        other.encrypt_ = nullptr;
        other.decrypt_ = nullptr;
        other.getName_ = nullptr;
        other.generateKeys_ = nullptr;
    }

    return *this;
}

bool Plugin::load(const std::string& path) {
    handle_ = dlopen(path.c_str(), RTLD_LAZY);

    if (!handle_) {
        std::cerr << "Ошибка загрузки плагина " << path << ": " << dlerror() << '\n';
        return false;
    }

    getName_ = reinterpret_cast<GetNameFunc>(dlsym(handle_, "get_algorithm_name"));
    generateKeys_ = reinterpret_cast<GenerateKeysFunc>(dlsym(handle_, "generate_keys"));
    encrypt_ = reinterpret_cast<EncryptFunc>(dlsym(handle_, "encrypt_data"));
    decrypt_ = reinterpret_cast<DecryptFunc>(dlsym(handle_, "decrypt_data"));

    if (!getName_ || !generateKeys_ || !encrypt_ || !decrypt_) {
        std::cerr << "Ошибка: плагин " << path << " не реализует нужный API.\n";
        unload();
        return false;
    }

    filename_ = fs::path(path).filename().string();
    name_ = getName_();
    return true;
}

void Plugin::unload() {
    if (handle_) {
        dlclose(handle_);
        handle_ = nullptr;
    }
}

const std::string& Plugin::filename() const {
    return filename_;
}

const std::string& Plugin::name() const {
    return name_;
}

std::vector<uint8_t> Plugin::encrypt(const std::vector<uint8_t>& data, const std::string& key) const {
    if (!encrypt_) {
        throw std::runtime_error("Функция шифрования не загружена");
    }

    return encrypt_(data, key);
}

std::vector<uint8_t> Plugin::decrypt(const std::vector<uint8_t>& data, const std::string& key) const {
    if (!decrypt_) {
        throw std::runtime_error("Функция расшифрования не загружена");
    }

    return decrypt_(data, key);
}

void Plugin::generateKeys(std::string& publicKey, std::string& privateKey) const {
    if (!generateKeys_) {
        throw std::runtime_error("Функция генерации ключей не загружена");
    }

    generateKeys_(publicKey, privateKey);
}

void PluginManager::loadFromDirectory(const std::string& directory) {
    plugins_.clear();
    currentIndex_ = -1;

    if (!fs::exists(directory) || !fs::is_directory(directory)) {
        std::cout << "Папка плагинов не найдена: " << directory << '\n';
        return;
    }

    for (const auto& entry : fs::directory_iterator(directory)) {
        if (entry.path().extension() == ".so") {
            Plugin plugin;

            if (plugin.load(entry.path().string())) {
                plugins_.push_back(std::move(plugin));
            }
        }
    }
}

bool PluginManager::empty() const {
    return plugins_.empty();
}

std::size_t PluginManager::count() const {
    return plugins_.size();
}

void PluginManager::printAvailablePlugins() const {
    if (plugins_.empty()) {
        std::cout << "Нет доступных алгоритмов.\n";
        return;
    }

    std::cout << "\nДоступные алгоритмы:\n";

    for (std::size_t i = 0; i < plugins_.size(); ++i) {
        std::cout << i + 1 << ". " << plugins_[i].name()
                  << " (" << plugins_[i].filename() << ")\n";
    }
}

bool PluginManager::selectPlugin(std::size_t numberFromMenu) {
    if (numberFromMenu < 1 || numberFromMenu > plugins_.size()) {
        return false;
    }

    currentIndex_ = static_cast<int>(numberFromMenu - 1);
    return true;
}

Plugin* PluginManager::currentPlugin() {
    if (currentIndex_ < 0) {
        return nullptr;
    }

    return &plugins_[static_cast<std::size_t>(currentIndex_)];
}

const Plugin* PluginManager::currentPlugin() const {
    if (currentIndex_ < 0) {
        return nullptr;
    }

    return &plugins_[static_cast<std::size_t>(currentIndex_)];
}
