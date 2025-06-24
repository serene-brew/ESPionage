#!/bin/bash

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
WHITE='\033[1;37m'
NC='\033[0m' # No Color

# Installation directories
INSTALL_DIR="/usr/bin"
LOCAL_DIR="$HOME/.local/share/espionage"
APP_DIR="$HOME/.local/lib/espionage"  # New: for the actual application files

print_header() {
    clear
    echo -e "${PURPLE}"
    echo "    ███████╗███████╗██████╗ ██╗ ██████╗ ███╗   ██╗ █████╗  ██████╗ ███████╗"
    echo "    ██╔════╝██╔════╝██╔══██╗██║██╔═══██╗████╗  ██║██╔══██╗██╔════╝ ██╔════╝"
    echo "    █████╗  ███████╗██████╔╝██║██║   ██║██╔██╗ ██║███████║██║  ███╗█████╗  "
    echo "    ██╔══╝  ╚════██║██╔═══╝ ██║██║   ██║██║╚██╗██║██╔══██║██║   ██║██╔══╝  "
    echo "    ███████╗███████║██║     ██║╚██████╔╝██║ ╚████║██║  ██║╚██████╔╝███████╗"
    echo "    ╚══════╝╚══════╝╚═╝     ╚═╝ ╚═════╝ ╚═╝  ╚═══╝╚═╝  ╚═╝ ╚═════╝ ╚══════╝"
    echo -e "${NC}"
    echo -e "${CYAN}                           Installation Script${NC}"
    echo
}

print_status() {
    echo -e "${BLUE}▶${NC} $1"
}

print_success() {
    echo -e "${GREEN}✓${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}⚠${NC} $1"
}

print_error() {
    echo -e "${RED}✗${NC} $1"
}

print_info() {
    echo -e "${CYAN}ℹ${NC} $1"
}

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
        print_success "pip3 is already installed"
        return 0
    else
        print_warning "pip3 is not installed"
        return 1
    fi
}

check_radare2() {
    if command -v radare2 &>/dev/null; then
        print_success "radare2 is already installed"
        return 0
    else
        print_warning "radare2 is not installed"
        return 1
    fi
}

install_packages() {
    pkg_manager=$(detect_package_manager)
    
    print_status "Detecting package manager..."
    
    case $pkg_manager in
    "apt")
        print_info "Detected Debian/Ubuntu based system"
        print_status "Updating package lists..."
        sudo apt update > /dev/null 2>&1
        if ! check_pip; then
            print_status "Installing python3-pip..."
            sudo apt install -y python3-pip > /dev/null 2>&1
            print_success "python3-pip installed"
        fi
        if ! check_radare2; then
            print_status "Installing radare2..."
            sudo apt install -y radare2 > /dev/null 2>&1
            print_success "radare2 installed"
        fi
        ;;
    "dnf" | "yum")
        print_info "Detected Red Hat/Fedora based system"
        if ! check_pip; then
            print_status "Installing python3-pip..."
            sudo $pkg_manager install -y python3-pip > /dev/null 2>&1
            print_success "python3-pip installed"
        fi
        if ! check_radare2; then
            print_status "Installing radare2..."
            sudo $pkg_manager install -y radare2 > /dev/null 2>&1
            print_success "radare2 installed"
        fi
        ;;
    "pacman")
        print_info "Detected Arch Linux based system"
        if ! check_pip; then
            print_status "Installing python-pip..."
            sudo pacman -S --noconfirm python-pip > /dev/null 2>&1
            print_success "python-pip installed"
        fi
        if ! check_radare2; then
            print_status "Installing radare2..."
            sudo pacman -S --noconfirm radare2 > /dev/null 2>&1
            print_success "radare2 installed"
        fi
        ;;
    "zypper")
        print_info "Detected openSUSE based system"
        if ! check_pip; then
            print_status "Installing python3-pip..."
            sudo zypper install -y python3-pip > /dev/null 2>&1
            print_success "python3-pip installed"
        fi
        if ! check_radare2; then
            print_status "Installing radare2..."
            sudo zypper install -y radare2 > /dev/null 2>&1
            print_success "radare2 installed"
        fi
        ;;
    *)
        print_error "Unsupported package manager"
        exit 1
        ;;
    esac
}

install_python_packages() {
    print_status "Installing Python dependencies..."
    
    print_status "Installing Textual library..."
    pip install textual --break-system-packages > /dev/null 2>&1
    print_success "Textual installed"
    
    print_status "Installing Rich library..."
    pip install rich --break-system-packages > /dev/null 2>&1
    print_success "Rich installed"
    
    print_status "Installing r2pipe..."
    pip install r2pipe --break-system-packages > /dev/null 2>&1
    print_success "r2pipe installed"
    
    print_status "Installing PySerial..."
    pip install pyserial --break-system-packages > /dev/null 2>&1
    print_success "PySerial installed"
}

setup_directories() {
    print_status "Setting up installation directories..."
    
    # Create installation directories
    mkdir -p "$LOCAL_DIR"
    mkdir -p "$APP_DIR"
    print_success "Created directory: $LOCAL_DIR"
    print_success "Created directory: $APP_DIR"
}

copy_files() {
    print_status "Copying application files..."
    
    # Copy all directories (excluding hidden ones and common build/cache directories)
    for dir in */; do
        if [ -d "$dir" ]; then
            dir_name=$(basename "$dir")
            # Skip common directories that shouldn't be installed
            case "$dir_name" in
                ".git"|"__pycache__"|".pytest_cache"|"node_modules"|"venv"|".venv"|"env"|".env")
                    print_info "Skipping directory: $dir_name"
                    ;;
                *)
                    cp -r "$dir" "$APP_DIR/"
                    print_success "Copied directory: $dir_name"
                    ;;
            esac
        fi
    done
    
    # Verify TUI directory was copied (it's essential)
    if [ ! -d "$APP_DIR/TUI" ]; then
        print_error "TUI directory not found in current directory or failed to copy"
        exit 1
    fi
    
    # Copy the main espionage script
    if [ -f "espionage" ]; then
        cp "espionage" "$APP_DIR/"
        chmod +x "$APP_DIR/espionage"
        print_success "Copied espionage script"
    else
        print_error "espionage script not found in current directory"
        exit 1
    fi
    
    # Copy all Python files
    for file in *.py; do
        if [ -f "$file" ]; then
            cp "$file" "$APP_DIR/"
            print_success "Copied $file"
        fi
    done
    
    # Copy any other important files (but not directories we already handled)
    for file in *; do
        if [ -f "$file" ] && [ "$file" != "espionage" ] && [[ "$file" != *.py ]]; then
            case "$file" in
                "install.sh"|"uninstall.sh")
                    # These will be handled separately
                    ;;
                "VERSION"|"LICENSE"|"LICENSE.txt"|"README.md"|"README.txt"|"README")
                    # These will be copied to both locations later
                    ;;
                *)
                    cp "$file" "$APP_DIR/"
                    print_success "Copied $file"
                    ;;
            esac
        fi
    done
    
    # Create a wrapper script for /usr/bin
    cat > "/tmp/espionage_wrapper" << 'EOF'
#!/bin/bash
export PYTHONPATH="$HOME/.local/lib/espionage:$PYTHONPATH"
cd "$HOME/.local/lib/espionage"
exec python3 espionage "$@"
EOF
    
    sudo mv "/tmp/espionage_wrapper" "$INSTALL_DIR/espionage"
    sudo chmod +x "$INSTALL_DIR/espionage"
    print_success "Created espionage wrapper script"

    # Copy VERSION file
    if [ -f "VERSION" ]; then
        cp "VERSION" "$LOCAL_DIR/"
        cp "VERSION" "$APP_DIR/"
        print_success "Copied VERSION file"
    else
        print_warning "VERSION file not found in current directory"
    fi
    
    # Copy uninstall script
    if [ -f "uninstall.sh" ]; then
        cp "uninstall.sh" "$LOCAL_DIR/"
        chmod +x "$LOCAL_DIR/uninstall.sh"
        print_success "Copied uninstall.sh"
    else
        print_warning "uninstall.sh not found in current directory"
    fi
    
    # Copy LICENSE file
    if [ -f "LICENSE" ]; then
        cp "LICENSE" "$LOCAL_DIR/"
        cp "LICENSE" "$APP_DIR/"
        print_success "Copied LICENSE file"
    elif [ -f "LICENSE.txt" ]; then
        cp "LICENSE.txt" "$LOCAL_DIR/"
        cp "LICENSE.txt" "$APP_DIR/"
        print_success "Copied LICENSE.txt file"
    else
        print_warning "LICENSE file not found in current directory"
    fi
    
    # Copy README file
    if [ -f "README.md" ]; then
        cp "README.md" "$LOCAL_DIR/"
        cp "README.md" "$APP_DIR/"
        print_success "Copied README.md file"
    elif [ -f "README.txt" ]; then
        cp "README.txt" "$LOCAL_DIR/"
        cp "README.txt" "$APP_DIR/"
        print_success "Copied README.txt file"
    elif [ -f "README" ]; then
        cp "README" "$LOCAL_DIR/"
        cp "README" "$APP_DIR/"
        print_success "Copied README file"
    else
        print_warning "README file not found in current directory"
    fi
}

print_completion() {
    print_success "ESPionage has been successfully installed!"
    echo
    print_info "Application directory: $APP_DIR"
    print_info "Data directory: $LOCAL_DIR"
    print_info "To uninstall, run: $LOCAL_DIR/uninstall.sh"
    echo
    print_status "You can now run 'espionage' to start the application"
    echo
}

# Main installation process
main() {
    print_header
    
    print_status "Starting ESPionage installation..."
    echo
    
    install_packages
    echo
    
    install_python_packages
    echo
    
    setup_directories
    echo
    
    copy_files
    echo
    
    print_completion
}

# Run main installation
main