@echo off
cd /d "%~dp0"
if /i "%~1"=="--diagnostico" (
    py -3 "%~dp0iniciar_juego.py" --diagnostico
    exit /b
)
wscript.exe "%~dp0Iniciar Orbita.vbs"
