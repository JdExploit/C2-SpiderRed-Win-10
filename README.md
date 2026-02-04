# 🕷️ SpiderRed C2  
**Experimental Command & Control Platform for Security Research**

> ⚠️ **AVISO LEGAL**  
> SpiderRed C2 es un proyecto **exclusivamente educativo y de investigación** destinado a **laboratorios controlados**, **pruebas de detección**, **purple team** y **análisis defensivo**.  
> El uso de este software fuera de entornos **explícitamente autorizados** es ilegal.

---

## 📌 Descripción General

**SpiderRed C2** es una plataforma experimental de **Command & Control (C2)** escrita en **C++**, compuesta por:

- Un **agente avanzado para Windows**
- Un **servidor C2 interactivo para Linux**

El proyecto está diseñado para **simular comportamientos reales de malware moderno** con el objetivo de:
- estudiar **detección por EDR**
- analizar **TTPs MITRE ATT&CK**
- entrenar **blue / purple teams**
- experimentar con **arquitecturas C2**

No pretende competir con frameworks profesionales como **Cobalt Strike**, **Sliver** o **Mythic**, sino servir como **base de estudio y evolución controlada**.

---


### Componentes
- **Agent (Windows)**: ejecución remota, persistencia y evasión básica
- **Server (Linux)**: gestión de agentes, cola de tareas y CLI interactiva

---

## ⚙️ Características Implementadas (Reales)

### 🔹 Agente Windows
- Comunicación periódica tipo **beacon con jitter**
- **Cifrado simétrico AES-256 (CryptoAPI)**
  - Clave estática (limitación conocida)
- Identificación única mediante **MachineGuid**
- Ejecución remota de comandos:
  - `cmd.exe`
  - PowerShell (no interactivo)
- Transferencia básica de archivos
- **Persistencia múltiple**:
  - Registry Run / RunOnce
  - Startup Folder
  - Scheduled Task
  - Servicio (requiere privilegios elevados)
- **Evasión básica**:
  - Anti-debug (IsDebuggerPresent, PEB checks)
  - Anti-sandbox (uptime, RAM, CPU)
  - Detección de VM (BIOS / manufacturer strings)
  - Sleep evasivo (busy loop)
- Control de instancia única mediante **mutex global**

---

### 🔹 Servidor C2 (Linux)
- Servidor TCP multi-agente
- Registro y seguimiento de agentes activos
- Heartbeats y detección de agentes inactivos
- **CLI interactiva**
- Cola de tareas por agente
- Historial de comandos ejecutados
- Subida y descarga de archivos
- Interacción directa por agente

---

## 🖥️ Comandos del Servidor

agents Listar agentes conectados
info <id> Información del agente
interact <id> Modo interactivo
exec <id> <cmd> Ejecutar comando
shell <id> Shell remota básica
broadcast <cmd> Ejecutar comando en todos
upload <id> <l> <r> Subir archivo
download <id> <f> Descargar archivo
persist <id> Activar persistencia
tasks <id> Historial de tareas
kill <id> Terminar agente
clear Limpiar pantalla
exit / quit Cerrar servidor


---

## 🔐 Criptografía y Seguridad

- **AES-256 (CryptoAPI)** para cifrado de datos
- Codificación Base64 para transporte
- ⚠️ **Limitaciones conocidas**:
  - No hay TLS real
  - No existe handshake asimétrico
  - Clave simétrica estática
  - Sin autenticación fuerte del servidor

> Estas limitaciones son **intencionadas** para facilitar el análisis defensivo y forense.

---

## 🧪 Casos de Uso Educativos

- 🟣 Ejercicios de **Purple Team**
- 🔵 Desarrollo de detecciones EDR / SIEM
- 🧠 Análisis de tráfico C2
- 🛡️ Threat Hunting
- 📚 Estudio de arquitectura C2
- 🎓 Proyectos académicos de ciberseguridad

---

## 🧭 Mapeo MITRE ATT&CK (Parcial)

| Técnica | ID |
|------|----|
| Command Execution | T1059 |
| PowerShell | T1059.001 |
| Persistence | T1547 |
| Scheduled Task | T1053 |
| Service Creation | T1543 |
| Defense Evasion | T1027 |
| Sandbox Evasion | T1497 |
| C2 Beaconing | T1071 |

---

## 🚧 Limitaciones Conocidas

- ❌ Sin TLS real
- ❌ Sin RSA / ECDH handshake
- ❌ Sin módulos dinámicos
- ❌ Sin inyección de procesos
- ❌ Sin movimiento lateral
- ❌ Protocolo C2 simple y no estandarizado

---

## 🛠️ Compilación

### Servidor (Linux)
```bash
g++ -std=c++17 -pthread server.cpp -o c2_server
cl /EHsc /O2 /MT agent.cpp ^
  ws2_32.lib wininet.lib crypt32.lib bcrypt.lib advapi32.lib ^
  /SUBSYSTEM:WINDOWS
