@echo off
setlocal enabledelayedexpansion

REM Demander le mot de passe en clair
set /p PASSWORD="Entrez le mot de passe pour Support: "

REM Lancer PowerShell avec le mot de passe dans une variable
powershell -NoProfile -ExecutionPolicy RemoteSigned -Command "& {$password = '%PASSWORD%'; $securePassword = ConvertTo-SecureString $password -AsPlainText -Force; $credentials = New-Object System.Management.Automation.PSCredential('.\Support', $securePassword); Start-Process powershell.exe -Credential $credentials -ArgumentList '-NoProfile -ExecutionPolicy RemoteSigned -File \"%~dp0FixDnscache_Universal.ps1\"' -Wait}"

pause
