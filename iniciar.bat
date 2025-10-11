@echo off
setlocal enabledelayedexpansion

if "%1"=="" (
    cmd /k "%~f0" RUN
    exit /b
)

title Dropbox Local

echo Procurando Python...

set PYTHON_FOUND=

for %%C in (py python3 python) do (
    %%C --version >nul 2>&1
    if !errorlevel! equ 0 (
        echo Python encontrado: %%C
        set "PYTHON_FOUND=%%C"
        goto :start_server
    )
)

echo ERRO: Python nao encontrado. Instale o Python e adicione ao PATH.
goto :end

:start_server
echo Iniciando servidor...
!PYTHON_FOUND! servidor.py

:end
echo.
pause