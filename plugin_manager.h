#ifndef PLUGIN_MANAGER_H
#define PLUGIN_MANAGER_H

#include <cstddef>
#include <string>
#include <vector>

#include "crypto_interface.h"

struct Plugin {
    void* handle = nullptr;

    std::string filename;
    std::string name;

    EncryptFunc encrypt = nullptr;
    DecryptFunc decrypt = nullptr;
    GetNameFunc getName = nullptr;
    GenerateKeysFunc generateKeys = nullptr;
};

bool LoadPlugin(Plugin& plugin, const std::string& path);
void UnloadPlugin(Plugin& plugin);

std::vector<Plugin> LoadPluginsFromDirectory(const std::string& directory);
void UnloadAllPlugins(std::vector<Plugin>& plugins);

bool HasPlugins(const std::vector<Plugin>& plugins);
std::size_t GetPluginsCount(const std::vector<Plugin>& plugins);

void PrintAvailablePlugins(const std::vector<Plugin>& plugins);
bool SelectPlugin(const std::vector<Plugin>& plugins, int& currentPluginIndex, std::size_t numberFromMenu);

Plugin* GetCurrentPlugin(std::vector<Plugin>& plugins, int currentPluginIndex);
const Plugin* GetCurrentPlugin(const std::vector<Plugin>& plugins, int currentPluginIndex);

std::vector<uint8_t> EncryptByPlugin(const Plugin* plugin, const std::vector<uint8_t>& data, const std::string& key);
std::vector<uint8_t> DecryptByPlugin(const Plugin* plugin, const std::vector<uint8_t>& data, const std::string& key);
void GenerateKeysByPlugin(const Plugin* plugin, std::string& publicKey, std::string& privateKey);

#endif
