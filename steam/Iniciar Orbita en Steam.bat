@echo off
setlocal
cd /d "%~dp0.."
wscript.exe "%~dp0..\Iniciar Orbita.vbs"
endlocal
git commit -m "Publica el juego Orbita"