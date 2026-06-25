#include "plugin_manager.h"

#include <dlfcn.h>
#include <filesystem>
#include <iostream>
#include <stdexcept>

namespace fs = std::filesystem;

bool LoadPlugin(Plugin& plugin, const std::string& path) {
    plugin.handle = dlopen(path.c_str(), RTLD_LAZY);

    if (!plugin.handle) {
        std::cerr << "Ошибка загрузки плагина " << path << ": " << dlerror() << '\n';
        return false;
    }

    plugin.getName = reinterpret_cast<GetNameFunc>(dlsym(plugin.handle, "get_algorithm_name"));
    plugin.generateKeys = reinterpret_cast<GenerateKeysFunc>(dlsym(plugin.handle, "generate_keys"));
    plugin.encrypt = reinterpret_cast<EncryptFunc>(dlsym(plugin.handle, "encrypt_data"));
    plugin.decrypt = reinterpret_cast<DecryptFunc>(dlsym(plugin.handle, "decrypt_data"));

    if (!plugin.getName || !plugin.generateKeys || !plugin.encrypt || !plugin.decrypt) {
        std::cerr << "Ошибка: плагин " << path << " не реализует нужный API.\n";
        UnloadPlugin(plugin);
        return false;
    }

    plugin.filename = fs::path(path).filename().string();
    plugin.name = plugin.getName();

    return true;
}

void UnloadPlugin(Plugin& plugin) {
    if (plugin.handle) {
        dlclose(plugin.handle);
    }

    plugin.handle = nullptr;
    plugin.filename.clear();
    plugin.name.clear();
    plugin.encrypt = nullptr;
    plugin.decrypt = nullptr;
    plugin.getName = nullptr;
    plugin.generateKeys = nullptr;
}

std::vector<Plugin> LoadPluginsFromDirectory(const std::string& directory) {
    std::vector<Plugin> plugins;

    if (!fs::exists(directory) || !fs::is_directory(directory)) {
        std::cout << "Папка плагинов не найдена: " << directory << '\n';
        return plugins;
    }

    for (const auto& entry : fs::directory_iterator(directory)) {
        if (!entry.is_regular_file()) {
            continue;
        }

        if (entry.path().extension() != ".so") {
            continue;
        }

        Plugin plugin;

        if (LoadPlugin(plugin, entry.path().string())) {
            plugins.push_back(plugin);
        }
    }

    return plugins;
}

void UnloadAllPlugins(std::vector<Plugin>& plugins) {
    for (Plugin& plugin : plugins) {
        UnloadPlugin(plugin);
    }

    plugins.clear();
}

bool HasPlugins(const std::vector<Plugin>& plugins) {
    return !plugins.empty();
}

std::size_t GetPluginsCount(const std::vector<Plugin>& plugins) {
    return plugins.size();
}

void PrintAvailablePlugins(const std::vector<Plugin>& plugins) {
    if (plugins.empty()) {
        std::cout << "Нет доступных алгоритмов.\n";
        return;
    }

    std::cout << "\nДоступные алгоритмы:\n";

    for (std::size_t i = 0; i < plugins.size(); ++i) {
        std::cout << i + 1 << ". " << plugins[i].name
                  << " (" << plugins[i].filename << ")\n";
    }
}

bool SelectPlugin(const std::vector<Plugin>& plugins, int& currentPluginIndex, std::size_t numberFromMenu) {
    if (numberFromMenu < 1 || numberFromMenu > plugins.size()) {
        return false;
    }

    currentPluginIndex = static_cast<int>(numberFromMenu - 1);
    return true;
}

Plugin* GetCurrentPlugin(std::vector<Plugin>& plugins, int currentPluginIndex) {
    if (currentPluginIndex < 0 || currentPluginIndex >= static_cast<int>(plugins.size())) {
        return nullptr;
    }

    return &plugins[static_cast<std::size_t>(currentPluginIndex)];
}

const Plugin* GetCurrentPlugin(const std::vector<Plugin>& plugins, int currentPluginIndex) {
    if (currentPluginIndex < 0 || currentPluginIndex >= static_cast<int>(plugins.size())) {
        return nullptr;
    }

    return &plugins[static_cast<std::size_t>(currentPluginIndex)];
}

std::vector<uint8_t> EncryptByPlugin(const Plugin* plugin, const std::vector<uint8_t>& data, const std::string& key) {
    if (plugin == nullptr || plugin->encrypt == nullptr) {
        throw std::runtime_error("Функция шифрования не загружена");
    }

    return plugin->encrypt(data, key);
}

std::vector<uint8_t> DecryptByPlugin(const Plugin* plugin, const std::vector<uint8_t>& data, const std::string& key) {
    if (plugin == nullptr || plugin->decrypt == nullptr) {
        throw std::runtime_error("Функция расшифрования не загружена");
    }

    return plugin->decrypt(data, key);
}

void GenerateKeysByPlugin(const Plugin* plugin, std::string& publicKey, std::string& privateKey) {
    if (plugin == nullptr || plugin->generateKeys == nullptr) {
        throw std::runtime_error("Функция генерации ключей не загружена");
    }

    plugin->generateKeys(publicKey, privateKey);
}
