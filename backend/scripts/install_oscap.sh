#!/bin/bash
# OpenSCAP Installation Script
# Supports: Ubuntu 18.04, 20.04, 22.04, 24.04, RHEL/CentOS 7-9

set -e

echo "⏳ Installing OpenSCAP"

# Detect OS
if [ ! -f /etc/os-release ]; then
    echo "❌ Cannot detect OS"
    exit 1
fi

. /etc/os-release
OS_NAME=$ID
OS_VERSION=$VERSION_ID

echo "📋 Detected: $PRETTY_NAME"

case "$OS_NAME" in
    rhel|centos|fedora|rocky|almalinux)
        echo "📦 Installing on RHEL-based system..."
        sudo dnf install -y openscap-scanner scap-security-guide 2>/dev/null || \
        sudo yum install -y openscap-scanner scap-security-guide
        ;;
    
    ubuntu|debian)
        echo "📦 Installing on Debian-based system..."
        sudo add-apt-repository universe -y 2>/dev/null || true
        sudo apt-get update -qq
        
        if [[ "$OS_VERSION" == "24.04" ]] || [[ "$OS_VERSION" > "24" ]]; then
            sudo apt-get install -y openscap-scanner libopenscap25t64 || \
            sudo apt-get install -y openscap-scanner libopenscap-dev
            sudo apt-get install -y ssg-base ssg-debderived 2>/dev/null || true
        else
            sudo apt-get install -y libopenscap8
            sudo apt-get install -y ssg-base ssg-debderived 2>/dev/null || \
            sudo apt-get install -y ssg-debian ssg-applications 2>/dev/null || {
                echo "📥 Downloading SCAP content..."
                cd /tmp
                wget -q https://github.com/ComplianceAsCode/content/releases/download/v0.1.73/scap-security-guide-0.1.73.zip || \
                wget -q https://github.com/ComplianceAsCode/content/releases/latest/download/scap-security-guide.zip
                
                if [ -f scap-security-guide*.zip ]; then
                    sudo apt-get install -y unzip
                    unzip -q scap-security-guide*.zip
                    sudo mkdir -p /usr/share/xml/scap/ssg/content
                    sudo cp -r scap-security-guide-*/ssg-* /usr/share/xml/scap/ssg/content/ 2>/dev/null || \
                    sudo cp -r */ssg-* /usr/share/xml/scap/ssg/content/ 2>/dev/null
                    rm -rf scap-security-guide*
                fi
            }
        fi
        ;;
    
    *)
        echo "❌ Unsupported OS: $OS_NAME"
        exit 1
        ;;
esac

# Verify installation
if command -v oscap &> /dev/null; then
    echo "✅ OpenSCAP installed successfully!"
    oscap --version | head -1
    
    # Find SCAP content
    CONTENT_DIRS=(
        "/usr/share/xml/scap/ssg/content"
        "/usr/share/scap-security-guide"
    )
    
    for dir in "${CONTENT_DIRS[@]}"; do
        if [ -d "$dir" ]; then
            CONTENT=$(ls "$dir"/*.xml 2>/dev/null | head -1)
            if [ -n "$CONTENT" ]; then
                echo "✅ SCAP content found: $CONTENT"
                exit 0
            fi
        fi
    done
    
    echo "⚠️  OpenSCAP installed but no SCAP content found"
    exit 0
else
    echo "❌ Installation failed"
    exit 1
fi

