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

# Installation directories (matching the install script)
INSTALL_DIR="/usr/bin"
LOCAL_DIR="$HOME/.local/share/espionage"
APP_DIR="$HOME/.local/lib/espionage"

print_header() {
    clear
    echo -e "${RED}"
    echo "    ███████╗███████╗██████╗ ██╗ ██████╗ ███╗   ██╗ █████╗  ██████╗ ███████╗"
    echo "    ██╔════╝██╔════╝██╔══██╗██║██╔═══██╗████╗  ██║██╔══██╗██╔════╝ ██╔════╝"
    echo "    █████╗  ███████╗██████╔╝██║██║   ██║██╔██╗ ██║███████║██║  ███╗█████╗  "
    echo "    ██╔══╝  ╚════██║██╔═══╝ ██║██║   ██║██║╚██╗██║██╔══██║██║   ██║██╔══╝  "
    echo "    ███████╗███████║██║     ██║╚██████╔╝██║ ╚████║██║  ██║╚██████╔╝███████╗"
    echo "    ╚══════╝╚══════╝╚═╝     ╚═╝ ╚═════╝ ╚═╝  ╚═══╝╚═╝  ╚═╝ ╚═════╝ ╚══════╝"
    echo -e "${NC}"
    echo -e "${YELLOW}                           Uninstallation Script${NC}"
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

confirm_uninstall() {
    print_warning "This will remove ESPionage and its configuration files from your system."
    print_info "Files to be removed:"
    echo "  • Executable: $INSTALL_DIR/espionage"
    echo "  • Application files: $APP_DIR"
    echo "  • Data files: $LOCAL_DIR"
    echo
    echo -n -e "${YELLOW}Are you sure you want to continue? (y/N): ${NC}"
    read -r response
    
    case "$response" in
        [yY][eE][sS]|[yY])
            return 0
            ;;
        *)
            print_info "Uninstallation cancelled by user"
            exit 0
            ;;
    esac
}

remove_executable() {
    print_status "Removing executable..."
    
    if [ -f "$INSTALL_DIR/espionage" ]; then
        sudo rm -f "$INSTALL_DIR/espionage"
        
        if [ ! -f "$INSTALL_DIR/espionage" ]; then
            print_success "Executable removed: $INSTALL_DIR/espionage"
        else
            print_error "Failed to remove executable: $INSTALL_DIR/espionage"
            return 1
        fi
    else
        print_warning "Executable not found: $INSTALL_DIR/espionage"
    fi
}

remove_application_files() {
    print_status "Removing application files..."
    
    if [ -d "$APP_DIR" ]; then
        # List main components being removed
        print_info "Removing files from $APP_DIR:"
        if [ -d "$APP_DIR/TUI" ]; then
            print_info "  • TUI directory"
        fi
        
        if [ -d "$APP_DIR/ROM_rw" ]; then
            print_info "  • ROM_rw directory"
        fi        
        
        if [ -d "$APP_DIR/layout" ]; then
            print_info "  • layout directory"
        fi
        
        if [ -d "$APP_DIR/parser" ]; then
            print_info "  • parser directory"
        fi

        if [ -f "$APP_DIR/espionage" ]; then
            print_info "  • espionage main script"
        fi
        
        if [ -f "$APP_DIR/VERSION" ]; then
            print_info "  • VERSION file"
        fi
        if [ -f "$APP_DIR/LICENSE" ] || [ -f "$APP_DIR/LICENSE.txt" ]; then
            print_info "  • LICENSE file"
        fi
        if [ -f "$APP_DIR/README.md" ] || [ -f "$APP_DIR/README.txt" ] || [ -f "$APP_DIR/README" ]; then
            print_info "  • README file"
        fi
        
        # List any Python files
        for file in "$APP_DIR"/*.py; do
            if [ -f "$file" ]; then
                filename=$(basename "$file")
                print_info "  • $filename"
            fi
        done
        
        # Remove the entire directory
        rm -rf "$APP_DIR"
        
        if [ ! -d "$APP_DIR" ]; then
            print_success "Application files removed successfully"
        else
            print_error "Failed to remove some application files"
            return 1
        fi
    else
        print_warning "Application directory not found: $APP_DIR"
    fi
}

remove_data_files() {
    print_status "Removing data files..."
    
    if [ -d "$LOCAL_DIR" ]; then
        # List files being removed
        print_info "Removing files from $LOCAL_DIR:"
        if [ -f "$LOCAL_DIR/VERSION" ]; then
            print_info "  • VERSION file"
        fi
        if [ -f "$LOCAL_DIR/LICENSE" ] || [ -f "$LOCAL_DIR/LICENSE.txt" ]; then
            print_info "  • LICENSE file"
        fi
        if [ -f "$LOCAL_DIR/README.md" ] || [ -f "$LOCAL_DIR/README.txt" ] || [ -f "$LOCAL_DIR/README" ]; then
            print_info "  • README file"
        fi
        if [ -f "$LOCAL_DIR/uninstall.sh" ]; then
            print_info "  • uninstall.sh script"
        fi
        
        # Check for any additional files
        file_count=$(find "$LOCAL_DIR" -type f 2>/dev/null | wc -l)
        if [ "$file_count" -gt 4 ]; then
            print_info "  • Additional configuration/data files"
        fi
        
        # Remove the entire directory
        rm -rf "$LOCAL_DIR"
        
        if [ ! -d "$LOCAL_DIR" ]; then
            print_success "Data files removed successfully"
        else
            print_error "Failed to remove some data files"
            return 1
        fi
    else
        print_warning "Data directory not found: $LOCAL_DIR"
    fi
}

cleanup_empty_directories() {
    print_status "Cleaning up empty parent directories..."
    
    # Try to remove parent directories if they're empty
    local lib_parent="$HOME/.local/lib"
    local share_parent="$HOME/.local/share"
    
    if [ -d "$lib_parent" ] && [ -z "$(ls -A "$lib_parent" 2>/dev/null)" ]; then
        rmdir "$lib_parent" 2>/dev/null && print_success "Removed empty directory: $lib_parent"
    fi
    
    if [ -d "$share_parent" ] && [ -z "$(ls -A "$share_parent" 2>/dev/null)" ]; then
        rmdir "$share_parent" 2>/dev/null && print_success "Removed empty directory: $share_parent"
    fi
    
    local local_parent="$HOME/.local"
    if [ -d "$local_parent" ] && [ -z "$(ls -A "$local_parent" 2>/dev/null)" ]; then
        rmdir "$local_parent" 2>/dev/null && print_success "Removed empty directory: $local_parent"
    fi
}

print_completion() {
    print_success "ESPionage has been successfully uninstalled!"
    echo
    print_info "The following components have been removed:"
    print_info "  • Executable from system PATH"
    print_info "  • Application files and TUI components"
    print_info "  • Configuration and data files"
    echo
    print_info "Python packages (textual, rich, r2pipe, pyserial) were left installed"
    print_info "as they may be used by other applications."
    echo
    print_info "Thank you for using ESPionage!"
}

print_partial_removal() {
    echo
    print_warning "Uninstallation completed with some warnings"
    echo
    print_info "Some components may still be present on your system."
    print_info "You may need to manually remove remaining files."
    echo
    print_info "Check the following locations:"
    echo "  • $INSTALL_DIR/espionage"
    echo "  • $APP_DIR"
    echo "  • $LOCAL_DIR"
    echo
}

check_sudo_access() {
    print_status "Checking for sudo access..."
    
    if ! sudo -n true 2>/dev/null; then
        print_info "This script needs sudo access to remove the executable from $INSTALL_DIR"
        print_info "You may be prompted for your password."
        echo
    fi
}

# Main uninstallation process
main() {
    print_header
    
    confirm_uninstall
    echo
    
    print_status "Starting ESPionage uninstallation..."
    echo
    
    check_sudo_access
    echo
    
    local errors=0
    
    remove_executable
    if [ $? -ne 0 ]; then
        ((errors++))
    fi
    echo
    
    remove_application_files
    if [ $? -ne 0 ]; then
        ((errors++))
    fi
    echo
    
    remove_data_files
    if [ $? -ne 0 ]; then
        ((errors++))
    fi
    echo
    
    cleanup_empty_directories
    echo
    
    if [ $errors -eq 0 ]; then
        print_completion
    else
        print_partial_removal
    fi
}

# Check if script is being run directly
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi