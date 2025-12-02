#!/bin/bash

# Universal Dependency Installer for QRE
# Supports: Debian/Ubuntu, Fedora/RHEL, Arch/Manjaro, openSUSE, Alpine

echo "🔍 Detecting Linux Distribution..."

if [ -f /etc/os-release ]; then
    . /etc/os-release
    OS=$NAME
    ID=$ID
else
    echo "❌ Cannot detect OS. Please install dependencies manually."
    exit 1
fi

echo "✅ Detected: $OS ($ID)"

install_debian() {
    echo "📦 Installing dependencies for Debian/Ubuntu..."
    sudo apt-get update
    sudo apt-get install -y build-essential cmake libcurl4-openssl-dev libsodium-dev git
}

install_fedora() {
    echo "📦 Installing dependencies for Fedora/RHEL..."
    sudo dnf install -y gcc-c++ cmake libcurl-devel libsodium-devel git
}

install_arch() {
    echo "📦 Installing dependencies for Arch Linux..."
    sudo pacman -S --noconfirm base-devel cmake libcurl libsodium git
}

install_suse() {
    echo "📦 Installing dependencies for openSUSE..."
    sudo zypper install -y gcc-c++ cmake libcurl-devel libsodium-devel git
}

install_alpine() {
    echo "📦 Installing dependencies for Alpine Linux..."
    sudo apk add build-base cmake curl-dev libsodium-dev git
}

case "$ID" in
    ubuntu|debian|kali|pop|linuxmint)
        install_debian
        ;;
    fedora|rhel|centos|almalinux|rocky)
        install_fedora
        ;;
    arch|manjaro|endeavouros)
        install_arch
        ;;
    opensuse*|sles)
        install_suse
        ;;
    alpine)
        install_alpine
        ;;
    *)
        echo "⚠️  Unknown distribution: $ID"
        echo "   Please manually install: g++, cmake, libcurl, libsodium"
        exit 1
        ;;
esac

echo ""
echo "✅ Dependencies installed successfully!"
echo "   You can now build QRE with:"
echo "   mkdir build && cd build && cmake .. && make"
