#!/bin/bash

# =============================================
#   LOGIN SYSTEM - SERVER OTOMATIS
#   Untuk Mac & Linux
# =============================================

clear
echo "============================================="
echo "   LOGIN SYSTEM - SERVER OTOMATIS"
echo "============================================="
echo ""

# Cek apakah Node.js sudah terinstall
if ! command -v node &> /dev/null; then
    echo "❌ ERROR: Node.js belum terinstall!"
    echo ""
    echo "Silakan download dan install Node.js di:"
    echo "https://nodejs.org"
    echo ""
    exit 1
fi

echo "✅ Node.js ditemukan: $(node --version)"

# Install library kalau belum ada
if [ ! -d "node_modules" ]; then
    echo ""
    echo "📦 Pertama kali jalan - menginstall library..."
    echo "Harap tunggu, ini hanya sekali saja..."
    echo ""
    npm install

    if [ $? -ne 0 ]; then
        echo ""
        echo "❌ Gagal install library!"
        exit 1
    fi

    echo ""
    echo "✅ Library berhasil diinstall!"
fi

echo ""
echo "============================================="
echo "  🚀 Server sedang berjalan..."
echo "  🌐 Buka browser: http://localhost:3000"
echo "  🛑 Tekan CTRL+C untuk menghentikan"
echo "============================================="
echo ""

# Otomatis buka browser (deteksi OS)
sleep 1.5
if [[ "$OSTYPE" == "darwin"* ]]; then
    open "http://localhost:3000"          # Mac
elif [[ "$OSTYPE" == "linux-gnu"* ]]; then
    xdg-open "http://localhost:3000" 2>/dev/null &   # Linux
fi

# Jalankan server
node server.js
