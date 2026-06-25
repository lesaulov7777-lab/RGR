#include <cstdint>
#include <iostream>
#include <limits>
#include <stdexcept>
#include <string>
#include <vector>
#include <sstream>

#include "base64_utils.h"
#include "file_manager.h"
#include "plugin_manager.h"

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
    std::string line;
    std::getline(std::cin, line);

    std::stringstream ss(line);

    int value;
    char extra;

    if (!(ss >> value)) {
        std::cout << "Ошибка: нужно ввести число." << std::endl;
        return -1;
    }

    if (ss >> extra) {
        std::cout << "Ошибка: после числа не должно быть символов." << std::endl;
        return -1;
    }

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

Plugin* RequireCurrentPlugin(std::vector<Plugin>& plugins, int currentPluginIndex) {
    Plugin* plugin = GetCurrentPlugin(plugins, currentPluginIndex);

    if (plugin == nullptr) {
        throw std::runtime_error("Сначала выберите алгоритм");
    }

    return plugin;
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

void SelectAlgorithm(std::vector<Plugin>& plugins, int& currentPluginIndex) {
    PrintAvailablePlugins(plugins);

    if (!HasPlugins(plugins)) {
        return;
    }

    std::cout << "Выберите номер: ";
    int index = ReadInt();

    if (index < 1 || !SelectPlugin(plugins, currentPluginIndex, static_cast<std::size_t>(index))) {
        std::cout << "[ОШИБКА] Неверный номер алгоритма.\n";
        return;
    }

    const Plugin* currentPlugin = GetCurrentPlugin(plugins, currentPluginIndex);
    std::cout << "[УСПЕШНО] Выбран алгоритм: " << currentPlugin->name << '\n';
}

void GenerateKeys(std::vector<Plugin>& plugins, int currentPluginIndex) {
    Plugin* plugin = RequireCurrentPlugin(plugins, currentPluginIndex);

    std::string publicKey;
    std::string privateKey;

    GenerateKeysByPlugin(plugin, publicKey, privateKey);
    PrintGeneratedKeys(plugin, publicKey, privateKey);
}

void EncryptText(std::vector<Plugin>& plugins, int currentPluginIndex) {
    Plugin* plugin = RequireCurrentPlugin(plugins, currentPluginIndex);

    std::string text = ReadLine("Введите текст: ");
    std::string keyInput = ReadLine(GetKeyMessage(plugin, true));
    std::string key = PrepareKey(plugin, keyInput);

    std::vector<uint8_t> encrypted = EncryptByPlugin(plugin, StringToBytes(text), key);

    std::string visibleCipherText;

    if (NeedsTextEncoding(plugin)) {
        visibleCipherText = BytesToBase64(encrypted);
    } else {
        visibleCipherText = BytesToString(encrypted);
    }

    std::cout << "Зашифрованный текст: " << visibleCipherText << '\n';
}

void DecryptText(std::vector<Plugin>& plugins, int currentPluginIndex) {
    Plugin* plugin = RequireCurrentPlugin(plugins, currentPluginIndex);

    std::string cipherText = ReadLine("Введите зашифрованный текст: ");
    std::string keyInput = ReadLine(GetKeyMessage(plugin, false));
    std::string key = PrepareKey(plugin, keyInput);

    std::vector<uint8_t> encrypted;

    if (NeedsTextEncoding(plugin)) {
        encrypted = Base64ToBytes(cipherText);
    } else {
        encrypted = StringToBytes(cipherText);
    }

    std::vector<uint8_t> decrypted = DecryptByPlugin(plugin, encrypted, key);

    std::cout << "Расшифрованный текст: " << BytesToString(decrypted) << '\n';
}

void EncryptFile(std::vector<Plugin>& plugins, int currentPluginIndex) {
    Plugin* plugin = RequireCurrentPlugin(plugins, currentPluginIndex);

    std::string inputPath = ReadLine("Введите путь к исходному файлу: ");
    std::string outputPath = ReadLine("Введите путь для сохранения: ");
    std::string keyInput = ReadLine(GetKeyMessage(plugin, true));
    std::string key = PrepareKey(plugin, keyInput);

    std::vector<uint8_t> data = file_manager::read_file(inputPath);
    std::vector<uint8_t> encrypted = EncryptByPlugin(plugin, data, key);
    file_manager::write_file(outputPath, encrypted);

    std::cout << "Файл успешно зашифрован.\n";
    std::cout << "Путь к результату: " << outputPath << '\n';
}

void DecryptFile(std::vector<Plugin>& plugins, int currentPluginIndex) {
    Plugin* plugin = RequireCurrentPlugin(plugins, currentPluginIndex);

    std::string inputPath = ReadLine("Введите путь к исходному файлу: ");
    std::string outputPath = ReadLine("Введите путь для сохранения: ");
    std::string keyInput = ReadLine(GetKeyMessage(plugin, false));
    std::string key = PrepareKey(plugin, keyInput);

    std::vector<uint8_t> data = file_manager::read_file(inputPath);
    std::vector<uint8_t> decrypted = DecryptByPlugin(plugin, data, key);
    file_manager::write_file(outputPath, decrypted);

    std::cout << "Файл успешно расшифрован.\n";
    std::cout << "Путь к результату: " << outputPath << '\n';
}

int main() {
    if (!Authorize()) {
        return 0;
    }

    const std::string pluginsDirectory = "./plagins";
    std::vector<Plugin> plugins = LoadPluginsFromDirectory(pluginsDirectory);
    int currentPluginIndex = -1;

    if (!HasPlugins(plugins)) {
        std::cout << "Плагины не найдены. Скомпилируйте .so файлы в папку plagins.\n";
    } else {
        std::cout << "Загружено плагинов: " << GetPluginsCount(plugins) << '\n';
    }

    bool running = true;

    while (running) {
        PrintMenu(GetCurrentPlugin(plugins, currentPluginIndex));
        MenuCommand command = ToMenuCommand(ReadInt());

        try {
            switch (command) {
                case MenuCommand::SelectAlgorithm:
                    SelectAlgorithm(plugins, currentPluginIndex);
                    break;

                case MenuCommand::GenerateKeys:
                    GenerateKeys(plugins, currentPluginIndex);
                    break;

                case MenuCommand::EncryptText:
                    EncryptText(plugins, currentPluginIndex);
                    break;

                case MenuCommand::DecryptText:
                    DecryptText(plugins, currentPluginIndex);
                    break;

                case MenuCommand::EncryptFile:
                    EncryptFile(plugins, currentPluginIndex);
                    break;

                case MenuCommand::DecryptFile:
                    DecryptFile(plugins, currentPluginIndex);
                    break;

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

    UnloadAllPlugins(plugins);
    return 0;
}
