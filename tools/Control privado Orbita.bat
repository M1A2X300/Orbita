@echo off
setlocal
cd /d "%~dp0.."

:menu
cls
echo Control privado de Orbita
echo.
echo 1. Configurar o cambiar contraseña privada
echo 2. Apagar el servidor local (pide contraseña y confirmacion)
echo 3. Iniciar Orbita de nuevo (si el servidor esta apagado)
echo 4. Salir
echo.
choice /c 1234 /n /m "Elige una opcion: "
if errorlevel 4 goto end
if errorlevel 3 goto start
if errorlevel 2 goto stop
if errorlevel 1 goto setup

:setup
py -3 "%~dp0control_servidor.py" --setup-admin
echo.
pause
goto menu

:stop
py -3 "%~dp0control_servidor.py" --stop-server
echo.
pause
goto menu

:start
wscript.exe "%~dp0..\Iniciar Orbita.vbs"
goto end

:end
endlocal
