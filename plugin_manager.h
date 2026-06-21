#ifndef PLUGIN_MANAGER_H
#define PLUGIN_MANAGER_H

#include <cstddef>
#include <string>
#include <vector>

#include "crypto_interface.h"

class Plugin {
public:
    Plugin() = default;
    ~Plugin();

    Plugin(const Plugin&) = delete;
    Plugin& operator=(const Plugin&) = delete;

    Plugin(Plugin&& other) noexcept;
    Plugin& operator=(Plugin&& other) noexcept;

    bool load(const std::string& path);
    void unload();

    const std::string& filename() const;
    const std::string& name() const;

    std::vector<uint8_t> encrypt(const std::vector<uint8_t>& data, const std::string& key) const;
    std::vector<uint8_t> decrypt(const std::vector<uint8_t>& data, const std::string& key) const;
    void generateKeys(std::string& publicKey, std::string& privateKey) const;

private:
    void* handle_ = nullptr;
    std::string filename_;
    std::string name_;
    EncryptFunc encrypt_ = nullptr;
    DecryptFunc decrypt_ = nullptr;
    GetNameFunc getName_ = nullptr;
    GenerateKeysFunc generateKeys_ = nullptr;
};

class PluginManager {
public:
    void loadFromDirectory(const std::string& directory);

    bool empty() const;
    std::size_t count() const;

    void printAvailablePlugins() const;
    bool selectPlugin(std::size_t numberFromMenu);

    Plugin* currentPlugin();
    const Plugin* currentPlugin() const;

private:
    std::vector<Plugin> plugins_;
    int currentIndex_ = -1;
};

#endif
