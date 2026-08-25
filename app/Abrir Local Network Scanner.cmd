@REM Copyright (c) 2026 p-darksy-r and Local Network Scanner. Licensed under the MIT License.
@echo off
setlocal

set "UPDATE_SCRIPT=%~dp0..\scripts\update-local-app.ps1"
if not exist "%UPDATE_SCRIPT%" (
    echo Nao foi encontrado o script de atualizacao:
    echo "%UPDATE_SCRIPT%"
    pause
    exit /b 2
)

set "POWERSHELL_HOST=%ProgramFiles%\PowerShell\7\pwsh.exe"
if exist "%POWERSHELL_HOST%" goto run_update
set "POWERSHELL_HOST=%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe"
if not exist "%POWERSHELL_HOST%" (
    echo Nao foi encontrado um PowerShell de sistema suportado.
    pause
    exit /b 2
)

:run_update
"%POWERSHELL_HOST%" -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%UPDATE_SCRIPT%" -Quick -Launch
set "EXIT_CODE=%ERRORLEVEL%"
if not "%EXIT_CODE%"=="0" (
    echo.
    echo Nao foi possivel atualizar ou abrir o Local Network Scanner.
    echo Reveja a mensagem acima; a copia anterior nao foi apagada.
    pause
)

exit /b %EXIT_CODE%
@REM Copyright (c) 2026 p-darksy-r and Local Network Scanner. Licensed under the MIT License.
