#include <dlfcn.h>
#include <filesystem>
#include <iostream>
#include <limits>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

#include "base64_utils.h"
#include "crypto_interface.h"
#include "file_manager.h"

namespace fs = std::filesystem;

struct Plugin {
    void* handle = nullptr;
    std::string filename;
    std::string name;
    EncryptFunc encrypt = nullptr;
    DecryptFunc decrypt = nullptr;
    GetNameFunc get_name = nullptr;
    GenerateKeysFunc generate_keys = nullptr;

    Plugin() = default;

    ~Plugin() {
        unload();
    }

    Plugin(const Plugin&) = delete;
    Plugin& operator=(const Plugin&) = delete;

    Plugin(Plugin&& other) noexcept {
        *this = std::move(other);
    }

    Plugin& operator=(Plugin&& other) noexcept {
        if (this != &other) {
            unload();

            handle = other.handle;
            filename = std::move(other.filename);
            name = std::move(other.name);
            encrypt = other.encrypt;
            decrypt = other.decrypt;
            get_name = other.get_name;
            generate_keys = other.generate_keys;

            other.handle = nullptr;
            other.encrypt = nullptr;
            other.decrypt = nullptr;
            other.get_name = nullptr;
            other.generate_keys = nullptr;
        }

        return *this;
    }

    bool load(const std::string& path) {
        handle = dlopen(path.c_str(), RTLD_LAZY);

        if (!handle) {
            std::cerr << "Ошибка загрузки плагина " << path << ": " << dlerror() << '\n';
            return false;
        }

        get_name = reinterpret_cast<GetNameFunc>(dlsym(handle, "get_algorithm_name"));
        generate_keys = reinterpret_cast<GenerateKeysFunc>(dlsym(handle, "generate_keys"));
        encrypt = reinterpret_cast<EncryptFunc>(dlsym(handle, "encrypt_data"));
        decrypt = reinterpret_cast<DecryptFunc>(dlsym(handle, "decrypt_data"));

        if (!get_name || !generate_keys || !encrypt || !decrypt) {
            std::cerr << "Ошибка: плагин " << path << " не реализует нужный API.\n";
            unload();
            return false;
        }

        filename = fs::path(path).filename().string();
        name = get_name();
        return true;
    }

    void unload() {
        if (handle) {
            dlclose(handle);
            handle = nullptr;
        }
    }
};

enum class MenuCommand {
    Exit = 0,
    SelectAlgorithm = 1,
    GenerateKeys = 2,
    EncryptText = 3,
    DecryptText = 4,
    EncryptFile = 5,
    DecryptFile = 6,
    Unknown = -1
};

MenuCommand ToMenuCommand(int value) {
    switch (value) {
        case static_cast<int>(MenuCommand::Exit):
            return MenuCommand::Exit;
        case static_cast<int>(MenuCommand::SelectAlgorithm):
            return MenuCommand::SelectAlgorithm;
        case static_cast<int>(MenuCommand::GenerateKeys):
            return MenuCommand::GenerateKeys;
        case static_cast<int>(MenuCommand::EncryptText):
            return MenuCommand::EncryptText;
        case static_cast<int>(MenuCommand::DecryptText):
            return MenuCommand::DecryptText;
        case static_cast<int>(MenuCommand::EncryptFile):
            return MenuCommand::EncryptFile;
        case static_cast<int>(MenuCommand::DecryptFile):
            return MenuCommand::DecryptFile;
        default:
            return MenuCommand::Unknown;
    }
}

bool Contains(const std::string& text, const std::string& part) {
    return text.find(part) != std::string::npos;
}

bool IsOtpAlgorithm(const Plugin* plugin) {
    return plugin != nullptr && Contains(plugin->name, "OTP");
}

bool IsElGamalAlgorithm(const Plugin* plugin) {
    return plugin != nullptr && Contains(plugin->name, "Эль-Гамаль");
}

bool NeedsTextEncoding(const Plugin* plugin) {
    if (plugin == nullptr) {
        return false;
    }

    return Contains(plugin->name, "RC4") ||
           Contains(plugin->name, "XTEA") ||
           Contains(plugin->name, "OTP") ||
           Contains(plugin->name, "Хилла");
}

std::vector<uint8_t> StringToBytes(const std::string& text) {
    return std::vector<uint8_t>(text.begin(), text.end());
}

std::string BytesToString(const std::vector<uint8_t>& data) {
    return std::string(data.begin(), data.end());
}

std::string ReadLine(const std::string& message) {
    std::cout << message;

    std::string value;
    std::getline(std::cin, value);
    return value;
}

int ReadInt() {
    int value = 0;

    if (!(std::cin >> value)) {
        std::cin.clear();
        std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
        return -1;
    }

    std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
    return value;
}

bool Authorize() {
    const std::string correctPassword = "12345678";
    int attempts = 3;

    std::cout << "========================================\n";
    std::cout << " СИСТЕМА ШИФРОВАНИЯ ДАННЫХ (РГР)\n";
    std::cout << "========================================\n";

    while (attempts > 0) {
        std::string password = ReadLine(
            "Введите пароль для доступа к системе (осталось попыток: " +
            std::to_string(attempts) + "): "
        );

        if (password == correctPassword) {
            std::cout << "\n[УСПЕШНО] Авторизация прошла успешно!\n";
            return true;
        }

        --attempts;
        std::cout << "[ОШИБКА] Неверный пароль.\n";
    }

    std::cout << "[БЛОКИРОВКА] Превышено количество попыток ввода.\n";
    return false;
}

std::vector<Plugin> LoadPlugins(const std::string& directory) {
    std::vector<Plugin> plugins;

    if (!fs::exists(directory) || !fs::is_directory(directory)) {
        std::cout << "Папка плагинов не найдена: " << directory << '\n';
        return plugins;
    }

    for (const auto& entry : fs::directory_iterator(directory)) {
        if (entry.path().extension() == ".so") {
            Plugin plugin;

            if (plugin.load(entry.path().string())) {
                plugins.push_back(std::move(plugin));
            }
        }
    }

    return plugins;
}

void PrintMenu(const Plugin* currentPlugin) {
    std::cout << "\n=== Менеджер шифрования ===\n";

    if (currentPlugin == nullptr) {
        std::cout << "Текущий алгоритм: не выбран\n";
    } else {
        std::cout << "Текущий алгоритм: " << currentPlugin->name << '\n';
    }

    std::cout << "1. Выбрать алгоритм\n";
    std::cout << "2. Сгенерировать ключи\n";
    std::cout << "3. Зашифровать текст\n";
    std::cout << "4. Расшифровать текст\n";
    std::cout << "5. Зашифровать файл\n";
    std::cout << "6. Расшифровать файл\n";
    std::cout << "0. Выход\n";
    std::cout << "Ваш выбор: ";
}

int SelectPlugin(const std::vector<Plugin>& plugins) {
    if (plugins.empty()) {
        std::cout << "Нет доступных алгоритмов.\n";
        return -1;
    }

    std::cout << "\nДоступные алгоритмы:\n";

    for (std::size_t i = 0; i < plugins.size(); ++i) {
        std::cout << i + 1 << ". " << plugins[i].name
                  << " (" << plugins[i].filename << ")\n";
    }

    std::cout << "Выберите номер: ";
    int index = ReadInt();

    if (index < 1 || static_cast<std::size_t>(index) > plugins.size()) {
        return -1;
    }

    return index - 1;
}

std::string GetKeyMessage(const Plugin* plugin, bool encryptMode) {
    if (IsElGamalAlgorithm(plugin)) {
        if (encryptMode) {
            return "Введите открытый ключ Эль-Гамаля (p g y): ";
        }

        return "Введите закрытый ключ Эль-Гамаля (p x): ";
    }

    if (IsOtpAlgorithm(plugin)) {
        return "Введите ключ OTP (Base64): ";
    }

    if (plugin != nullptr && Contains(plugin->name, "Хилла")) {
        return "Введите ключ Хилла (4 числа, пример: 3 3 2 5): ";
    }

    if (plugin != nullptr && Contains(plugin->name, "XTEA")) {
        return "Введите ключ XTEA (16 символов): ";
    }

    return "Введите ключ: ";
}

std::string PrepareKey(const Plugin* plugin, const std::string& inputKey) {
    if (IsOtpAlgorithm(plugin)) {
        return BytesToString(Base64ToBytes(inputKey));
    }

    return inputKey;
}

void PrintGeneratedKeys(const Plugin* plugin, const std::string& publicKey, const std::string& privateKey) {
    if (publicKey.empty() && privateKey.empty()) {
        std::cout << "Для выбранного алгоритма генерация ключей не требуется.\n";
        return;
    }

    if (publicKey == privateKey) {
        if (IsOtpAlgorithm(plugin)) {
            std::cout << "Ключ OTP (Base64): " << publicKey << '\n';
            std::cout << "Важно: ключ OTP должен быть не короче текста или файла.\n";
        } else {
            std::cout << "Ключ: " << publicKey << '\n';
        }

        return;
    }

    if (IsElGamalAlgorithm(plugin)) {
        std::cout << "Открытый ключ для шифрования: " << publicKey << '\n';
        std::cout << "Закрытый ключ для расшифрования: " << privateKey << '\n';
        return;
    }

    std::cout << "Ключ шифрования: " << publicKey << '\n';
    std::cout << "Ключ расшифрования: " << privateKey << '\n';
}

void EncryptText(const Plugin* plugin) {
    std::string text = ReadLine("Введите текст: ");
    std::string keyInput = ReadLine(GetKeyMessage(plugin, true));
    std::string key = PrepareKey(plugin, keyInput);

    std::vector<uint8_t> encrypted = plugin->encrypt(StringToBytes(text), key);

    std::string visibleCipherText;

    if (NeedsTextEncoding(plugin)) {
        visibleCipherText = BytesToBase64(encrypted);
    } else {
        visibleCipherText = BytesToString(encrypted);
    }

    std::cout << "Зашифрованный текст: " << visibleCipherText << '\n';
}

void DecryptText(const Plugin* plugin) {
    std::string cipherText = ReadLine("Введите зашифрованный текст: ");
    std::string keyInput = ReadLine(GetKeyMessage(plugin, false));
    std::string key = PrepareKey(plugin, keyInput);

    std::vector<uint8_t> encrypted;

    if (NeedsTextEncoding(plugin)) {
        encrypted = Base64ToBytes(cipherText);
    } else {
        encrypted = StringToBytes(cipherText);
    }

    std::vector<uint8_t> decrypted = plugin->decrypt(encrypted, key);

    std::cout << "Расшифрованный текст: " << BytesToString(decrypted) << '\n';
}

void EncryptFile(const Plugin* plugin) {
    std::string inputPath = ReadLine("Введите путь к исходному файлу: ");
    std::string outputPath = ReadLine("Введите путь для сохранения: ");
    std::string keyInput = ReadLine(GetKeyMessage(plugin, true));
    std::string key = PrepareKey(plugin, keyInput);

    std::vector<uint8_t> data = file_manager::read_file(inputPath);
    std::vector<uint8_t> encrypted = plugin->encrypt(data, key);
    file_manager::write_file(outputPath, encrypted);

    std::cout << "Файл успешно зашифрован.\n";
}

void DecryptFile(const Plugin* plugin) {
    std::string inputPath = ReadLine("Введите путь к исходному файлу: ");
    std::string outputPath = ReadLine("Введите путь для сохранения: ");
    std::string keyInput = ReadLine(GetKeyMessage(plugin, false));
    std::string key = PrepareKey(plugin, keyInput);

    std::vector<uint8_t> data = file_manager::read_file(inputPath);
    std::vector<uint8_t> decrypted = plugin->decrypt(data, key);
    file_manager::write_file(outputPath, decrypted);

    std::cout << "Файл успешно расшифрован.\n";
}

int main() {
    if (!Authorize()) {
        return 0;
    }

    const std::string pluginsDirectory = "./plagins";
    std::vector<Plugin> plugins = LoadPlugins(pluginsDirectory);

    if (plugins.empty()) {
        std::cout << "Плагины не найдены. Скомпилируйте .so файлы в папку plagins.\n";
    } else {
        std::cout << "Загружено плагинов: " << plugins.size() << '\n';
    }

    Plugin* currentPlugin = nullptr;
    bool running = true;

    while (running) {
        PrintMenu(currentPlugin);
        MenuCommand command = ToMenuCommand(ReadInt());

        try {
            switch (command) {
                case MenuCommand::SelectAlgorithm: {
                    int index = SelectPlugin(plugins);

                    if (index == -1) {
                        std::cout << "[ОШИБКА] Неверный номер алгоритма.\n";
                    } else {
                        currentPlugin = &plugins[index];
                        std::cout << "[УСПЕШНО] Выбран алгоритм: " << currentPlugin->name << '\n';
                    }

                    break;
                }

                case MenuCommand::GenerateKeys: {
                    if (currentPlugin == nullptr) {
                        std::cout << "[ОШИБКА] Сначала выберите алгоритм.\n";
                        break;
                    }

                    std::string publicKey;
                    std::string privateKey;
                    currentPlugin->generate_keys(publicKey, privateKey);
                    PrintGeneratedKeys(currentPlugin, publicKey, privateKey);
                    break;
                }

                case MenuCommand::EncryptText: {
                    if (currentPlugin == nullptr) {
                        std::cout << "[ОШИБКА] Сначала выберите алгоритм.\n";
                        break;
                    }

                    EncryptText(currentPlugin);
                    break;
                }

                case MenuCommand::DecryptText: {
                    if (currentPlugin == nullptr) {
                        std::cout << "[ОШИБКА] Сначала выберите алгоритм.\n";
                        break;
                    }

                    DecryptText(currentPlugin);
                    break;
                }

                case MenuCommand::EncryptFile: {
                    if (currentPlugin == nullptr) {
                        std::cout << "[ОШИБКА] Сначала выберите алгоритм.\n";
                        break;
                    }

                    EncryptFile(currentPlugin);
                    break;
                }

                case MenuCommand::DecryptFile: {
                    if (currentPlugin == nullptr) {
                        std::cout << "[ОШИБКА] Сначала выберите алгоритм.\n";
                        break;
                    }

                    DecryptFile(currentPlugin);
                    break;
                }

                case MenuCommand::Exit:
                    std::cout << "Выход...\n";
                    running = false;
                    break;

                case MenuCommand::Unknown:
                default:
                    std::cout << "[ОШИБКА] Неверный выбор.\n";
                    break;
            }
        } catch (const std::exception& error) {
            std::cout << "[ОШИБКА] " << error.what() << '\n';
        }
    }

    return 0;
}
