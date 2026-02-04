@echo off
echo [*] Compiling C2 Agent for Windows...
cl.exe /EHsc /O2 /MT /D_WIN32_WINNT=0x0601 agent.cpp ws2_32.lib wininet.lib urlmon.lib user32.lib advapi32.lib /Fe:agent.exe
if %ERRORLEVEL% EQU 0 (
    echo [+] Agent compiled successfully!
    echo [*] Agent: agent.exe
) else (
    echo [-] Compilation failed!
    echo [*] Try installing Visual Studio Build Tools
)
pause
