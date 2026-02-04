#!/bin/bash
echo "[*] Compiling C2 Server..."
g++ -std=c++11 -pthread -o c2_server server.cpp
if [ $? -eq 0 ]; then
    echo "[+] Server compiled successfully!"
    echo "[*] Run: ./c2_server"
else
    echo "[-] Compilation failed!"
fi
