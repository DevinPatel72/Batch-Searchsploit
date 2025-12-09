#!/bin/bash

shopt -s globstar  # Enable recursive ** globbing (bash 4+)

# Create Bin Dir
os_name=$(grep ^ID= /etc/os-release | cut -d= -f2 | tr -d '"')
if [ -z "$os_name" ]; then
    os_name="unknown"
fi
os_name="${os_name^}"

BIN_DIR="./bin/Linux-$os_name"
mkdir -p "$BIN_DIR"

# Clean
clean() {
    rm -rf "$BIN_DIR"
    mkdir -p "$BIN_DIR"
    clean_build_files
}

# Clean build files only
clean_build_files() {
    find . -name "__pycache__" -exec rm -rf {} \;
    rm -rf build dist logs
}

# Main #
clean

# Exit if only clean is needed
if [[ "$1" == "clean" ]]; then
    exit 0
fi

# Build
pyinstaller --clean searchsploit.spec

# Copy files to bin dir
cp -r dist/. "$BIN_DIR/"

# Cleanup build files
clean_build_files

printf "\n"
echo Build complete. Executables have been copied into $(realpath "$BIN_DIR")
