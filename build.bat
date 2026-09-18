@echo off
setlocal enabledelayedexpansion

echo ========================================================
echo     MCGuard Standalone Build Script (MSVC x64 Native)
echo ========================================================

set "VS_DEV_CMD=C:\Program Files (x86)\Microsoft Visual Studio\18\BuildTools\VC\Auxiliary\Build\vcvars64.bat"

if not exist "!VS_DEV_CMD!" (
    echo [-] Could not find vcvars64.bat at !VS_DEV_CMD!
    exit /b 1
)

echo [*] Initializing MSVC x64 build environment...
call "!VS_DEV_CMD!" > nul
if %errorlevel% neq 0 (
    echo [-] Failed to initialize MSVC build tools!
    exit /b %errorlevel%
)

echo [*] Compiling Standalone MCGuard.exe...
cl.exe /std:c++17 /EHsc /O2 /W3 /D_UNICODE /DUNICODE /D_WIN32_WINNT=0x0A00 ^
    /I"%~dp0src" ^
    "%~dp0src\main.cpp" ^
    "%~dp0src\util\privilege.cpp" ^
    "%~dp0src\util\string_util.cpp" ^
    "%~dp0src\util\config_loader.cpp" ^
    "%~dp0src\core\process_watcher.cpp" ^
    "%~dp0src\core\wfp_guard.cpp" ^
    "%~dp0src\core\sandbox_launcher.cpp" ^
    "%~dp0src\core\etw_watcher.cpp" ^
    "%~dp0src\core\network_tracker.cpp" ^
    "%~dp0src\core\folder_watcher.cpp" ^
    "%~dp0src\core\module_tracker.cpp" ^
    "%~dp0src\core\correlator.cpp" ^
    "%~dp0src\core\dns_tracker.cpp" ^
    "%~dp0src\core\ipc_broker.cpp" ^
    "%~dp0src\ui\console_view.cpp" ^
    /link /MANIFEST:EMBED /MANIFESTUAC:"level='asInvoker' uiAccess='false'" ^
    Fwpuclnt.lib Advapi32.lib tdh.lib Ws2_32.lib Iphlpapi.lib Shell32.lib Ole32.lib User32.lib Userenv.lib ^
    /out:"%~dp0MCGuard.exe"

if %errorlevel% neq 0 (
    echo [-] Failed to compile MCGuard.exe!
    exit /b %errorlevel%
)

echo.
echo ========================================================
echo [+] Build successful:
echo     - MCGuard.exe (Pure Standalone Executable)
echo     - config\mcguard.json
echo ========================================================
exit /b 0
