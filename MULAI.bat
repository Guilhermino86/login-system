@echo off
title Login System - Server
color 0A
cls

echo =============================================
echo    LOGIN SYSTEM - SERVER OTOMATIS
echo =============================================
echo.

:: Cek apakah Node.js sudah terinstall
node --version >nul 2>&1
IF %ERRORLEVEL% NEQ 0 (
    echo [ERROR] Node.js belum terinstall!
    echo.
    echo Silakan download dan install Node.js di:
    echo https://nodejs.org
    echo.
    pause
    exit /b 1
)

echo [OK] Node.js ditemukan!

:: Cek apakah node_modules sudah ada
IF NOT EXIST "node_modules\" (
    echo.
    echo [INFO] Pertama kali jalan - menginstall library...
    echo Harap tunggu, ini hanya sekali saja...
    echo.
    npm install
    IF %ERRORLEVEL% NEQ 0 (
        echo.
        echo [ERROR] Gagal install library!
        pause
        exit /b 1
    )
    echo.
    echo [OK] Library berhasil diinstall!
)

echo.
echo =============================================
echo  Server sedang berjalan...
echo  Buka browser ketik: http://localhost:3000
echo  Tekan CTRL+C untuk menghentikan server
echo =============================================
echo.

:: Otomatis buka browser setelah 2 detik
start /b cmd /c "timeout /t 2 >nul && start http://localhost:3000"

:: Jalankan server
node server.js

echo.
echo [INFO] Server dihentikan.
pause
