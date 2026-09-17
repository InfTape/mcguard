@echo off
setlocal enabledelayedexpansion

set "JAVA_BIN=C:\Program Files\Microsoft\jdk-21.0.11.10-hotspot\bin"
set "CP=C:\Users\Admin\Desktop\HMCL\.minecraft\libraries\net\fabricmc\fabric-loader\0.19.5\fabric-loader-0.19.5.jar;C:\Users\Admin\Desktop\HMCL\.minecraft\versions\1.21.11-Fabric\.fabric\remappedJars\minecraft-1.21.11-0.19.5\client-intermediary.jar;C:\Users\Admin\Desktop\HMCL\.minecraft\versions\1.21.11-Fabric\.fabric\processedMods\fabric-command-api-v2-2.4.7+6b42a6003e-a6d7072552922485.jar;C:\Users\Admin\Desktop\HMCL\.minecraft\versions\1.21.11-Fabric\.fabric\processedMods\fabric-api-base-1.0.5+4ebb5c083e-ccbe8773b96707a4.jar;C:\Users\Admin\Desktop\HMCL\.minecraft\libraries\com\mojang\brigadier\1.3.10\brigadier-1.3.10.jar"

echo [*] Compiling TestMod.java...
"%JAVA_BIN%\javac.exe" -cp "%CP%" -d "%~dp0bin" "%~dp0src\com\mcguard\testmod\TestMod.java"
if %errorlevel% neq 0 (
    echo [-] Compilation failed!
    exit /b %errorlevel%
)

copy /y "%~dp0fabric.mod.json" "%~dp0bin\fabric.mod.json" > nul
echo [*] Packaging mcguard-testmod-1.0.0.jar...
"%JAVA_BIN%\jar.exe" -cvf "%~dp0mcguard-testmod-1.0.0.jar" -C "%~dp0bin" .

echo [*] Deploying to HMCL mods folder...
copy /y "%~dp0mcguard-testmod-1.0.0.jar" "C:\Users\Admin\Desktop\HMCL\.minecraft\versions\1.21.11-Fabric\mods\mcguard-testmod-1.0.0.jar"
echo [+] Done!
