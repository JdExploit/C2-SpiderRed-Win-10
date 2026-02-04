# 🕷️ SpiderRed C2  
**Experimental Command & Control Platform for Security Research**

> ⚠️ **AVISO LEGAL**  
> SpiderRed C2 es un proyecto **exclusivamente educativo y de investigación** destinado a **laboratorios controlados**, **pruebas de detección**, **purple team** y **análisis defensivo**.  
> El uso de este software fuera de entornos **explícitamente autorizados** es ilegal.

---

🚀 GUÍA DE IMPLEMENTACIÓN COMPLETA
1. Configurar el Laboratorio
bash
# 1. Máquina Linux (C2 Server)
sudo apt update
sudo apt install python3 python3-pip openssl sqlite3
pip3 install asyncio

# 2. Generar certificados SSL
openssl req -x509 -newkey rsa:4096 \
  -keyout server.key -out server.crt \
  -days 365 -nodes \
  -subj "/C=US/ST=Demo/L=Lab/O=RedTeam/CN=c2.lab.local"

# 3. Configurar firewall
sudo ufw allow 8443/tcp

# 4. Ejecutar servidor
python3 c2_server.py
2. Compilar el Agente Windows
bash
# En Windows con Visual Studio Developer Command Prompt
cl /std:c++17 /O2 /MT /DNDEBUG /EHsc ^
    agent_working.cpp ^
    /link wininet.lib crypt32.lib advapi32.lib ^
    /OUT:windows_update.exe /SUBSYSTEM:WINDOWS
3. Configurar Red
text
# En laboratorio controlado:
C2 Server:   192.168.1.100  (Linux)
Victim PC:   192.168.1.101  (Windows)
Network:     Aislada, sin internet real
4. Prueba de Funcionamiento
Iniciar servidor C2

bash
python3 c2_server.py
Ejecutar agente en Windows

cmd
windows_update.exe
Interactuar desde consola C2

text
C2> agents
C2> tasks WIN10-PC01-Admin-abc123
