#!/bin/bash

set -e

echo "🚀 Starting Reconer installation..."

# Detect OS
OS="$(uname)"

echo "[+] Detected OS: $OS"

# ----------------------------
# Install dependencies (Mac)
# ----------------------------
if [[ "$OS" == "Darwin" ]]; then
    echo "[+] Using Homebrew (Mac)..."

    if ! command -v brew &> /dev/null; then
        echo "[!] Homebrew not found. Install from https://brew.sh/"
        exit 1
    fi

    brew update
    brew install jq curl git nmap go

# ----------------------------
# Install dependencies (Linux)
# ----------------------------
elif [[ "$OS" == "Linux" ]]; then
    echo "[+] Using APT (Linux)..."

    sudo apt update
    sudo apt install -y jq curl git nmap golang

else
    echo "[!] Unsupported OS"
    exit 1
fi

# ----------------------------
# Setup Go PATH
# ----------------------------
echo "[+] Setting up Go environment..."

export PATH=$PATH:$(go env GOPATH)/bin

# Make permanent
if ! grep -q 'GOPATH/bin' ~/.bashrc; then
    echo 'export PATH=$PATH:$(go env GOPATH)/bin' >> ~/.bashrc
fi

# ----------------------------
# Install ProjectDiscovery tools
# ----------------------------
echo "[+] Installing ProjectDiscovery tools..."

go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest
go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install github.com/projectdiscovery/katana/cmd/katana@latest

# ----------------------------
# Install Recon tools
# ----------------------------
echo "[+] Installing Recon tools..."

go install github.com/tomnomnom/assetfinder@latest
go install github.com/lc/gau/v2/cmd/gau@latest
go install github.com/tomnomnom/waybackurls@latest
go install github.com/hakluke/hakrawler@latest
go install github.com/haccer/subjack@latest
go install github.com/owasp-amass/amass/v4/...@latest

# ----------------------------
# Update nuclei templates
# ----------------------------
echo "[+] Updating nuclei templates..."

nuclei -update-templates || true

# ----------------------------
# Done
# ----------------------------
echo "✅ Installation complete!"
echo "👉 Restart your terminal or run: source ~/.bashrc"
