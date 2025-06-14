#!/bin/bash

detect_package_manager() {
    if command -v apt &>/dev/null; then
        echo "apt"
    elif command -v dnf &>/dev/null; then
        echo "dnf"
    elif command -v yum &>/dev/null; then
        echo "yum"
    elif command -v pacman &>/dev/null; then
        echo "pacman"
    elif command -v zypper &>/dev/null; then
        echo "zypper"
    else
        echo "unknown"
    fi
}

check_pip() {
    if command -v pip3 &>/dev/null; then
        echo "pip3 is already installed"
        return 0
    else
        echo "pip3 is not installed"
        return 1
    fi
}

check_radare2() {
    if command -v radare2 &>/dev/null; then
        echo "radare2 is already installed"
        return 0
    else
        echo "radare2 is not installed"
        return 1
    fi
}

install_packages() {
    pkg_manager=$(detect_package_manager)
    
    case $pkg_manager in
        "apt")
            echo "Detected Debian/Ubuntu based system"
            sudo apt update
            if ! check_pip; then
                sudo apt install -y python3-pip
            fi
            if ! check_radare2; then
                sudo apt install -y radare2
            fi
            ;;
        "dnf"|"yum")
            echo "Detected Red Hat/Fedora based system"
            if ! check_pip; then
                sudo $pkg_manager install -y python3-pip
            fi
            if ! check_radare2; then
                sudo $pkg_manager install -y radare2
            fi
            ;;
        "pacman")
            echo "Detected Arch Linux based system"
            if ! check_pip; then
                sudo pacman -S --noconfirm python-pip
            fi
            if ! check_radare2; then
                sudo pacman -S --noconfirm radare2
            fi
            ;;
        "zypper")
            echo "Detected openSUSE based system"
            if ! check_pip; then
                sudo zypper install -y python3-pip
            fi
            if ! check_radare2; then
                sudo zypper install -y radare2
            fi
            ;;
        *)
            echo "Unsupported package manager"
            exit 1
            ;;
    esac
}

echo "Checking and installing required packages..."
install_packages

echo "Installing r2pipe using pip..."
pip3 install --break-system-packages r2pipe

echo "Installation complete"