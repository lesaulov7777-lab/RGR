#!/bin/bash
set -e

mkdir -p plagins

g++ -std=c++17 -fPIC -shared -o plagins/librc4.so rc4_plugin.cpp
g++ -std=c++17 -fPIC -shared -o plagins/libvigenere.so vigenere_plugin.cpp
g++ -std=c++17 -fPIC -shared -o plagins/libelgamal.so elgamal_plugin.cpp
g++ -std=c++17 -fPIC -shared -o plagins/libxtea.so xtea_plugin.cpp
g++ -std=c++17 -fPIC -shared -o plagins/libhill.so hill_plugin.cpp
g++ -std=c++17 -fPIC -shared -o plagins/libotp.so otp_plugin.cpp

g++ -std=c++17 main.cpp plugin_manager.cpp file_manager.cpp hex_utils.cpp -ldl -o main

echo "Сборка завершена. Запуск: ./main"
