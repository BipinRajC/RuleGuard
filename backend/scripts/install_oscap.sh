#!/bin/bash
# OpenSCAP Installation Script - Backend Automation
# Optimized for: Ubuntu 22.04 LTS (primary), Ubuntu 18.04+, RHEL/CentOS 7-9
# Non-interactive, returns structured output for API parsing

set -e

# Output format for backend parsing
log_info() {
    echo "INFO: $1"
}

log_error() {
    echo "ERROR: $1" >&2
}

log_success() {
    echo "SUCCESS: $1"
}

log_info "Starting OpenSCAP installation"

# Detect OS
if [ ! -f /etc/os-release ]; then
    log_error "Cannot detect OS - /etc/os-release not found"
    exit 1
fi

. /etc/os-release
OS_NAME=$ID
OS_VERSION=$VERSION_ID

log_info "Detected OS: $PRETTY_NAME (ID=$OS_NAME, VERSION=$OS_VERSION)"

case "$OS_NAME" in
    ubuntu|debian)
        log_info "Installing on Debian-based system"
        
        # Ensure universe repository is enabled (non-interactive)
        sudo add-apt-repository universe -y 2>/dev/null || true
        
        # Update package lists
        log_info "Updating package lists..."
        export DEBIAN_FRONTEND=noninteractive
        sudo apt-get update -qq || {
            log_error "Failed to update package lists"
            exit 1
        }
        
        # Install based on Ubuntu version
        if [[ "$OS_VERSION" == "22.04" ]]; then
            # Ubuntu 22.04 LTS - Primary target
            log_info "Installing OpenSCAP for Ubuntu 22.04 LTS"
            sudo apt-get install -y -qq libopenscap8 || {
                log_error "Failed to install libopenscap8"
                exit 1
            }
            
            # Install SCAP Security Guide
            sudo apt-get install -y -qq ssg-base ssg-debderived 2>/dev/null || \
            sudo apt-get install -y -qq ssg-debian ssg-applications 2>/dev/null || {
                log_info "SCAP content not in repos, downloading from GitHub..."
                cd /tmp
                wget -q https://github.com/ComplianceAsCode/content/releases/download/v0.1.73/scap-security-guide-0.1.73.zip || \
                wget -q https://github.com/ComplianceAsCode/content/releases/latest/download/scap-security-guide.zip || {
                    log_error "Failed to download SCAP content"
                    exit 1
                }
                
                if [ -f scap-security-guide*.zip ]; then
                    sudo apt-get install -y -qq unzip
                    unzip -q scap-security-guide*.zip
                    sudo mkdir -p /usr/share/xml/scap/ssg/content
                    sudo cp -r scap-security-guide-*/ssg-* /usr/share/xml/scap/ssg/content/ 2>/dev/null || \
                    sudo cp -r */ssg-* /usr/share/xml/scap/ssg/content/ 2>/dev/null || {
                        log_error "Failed to install SCAP content"
                        exit 1
                    }
                    rm -rf scap-security-guide*
                    log_info "SCAP content installed from GitHub"
                fi
            }
            
        elif [[ "$OS_VERSION" == "20.04" ]] || [[ "$OS_VERSION" == "18.04" ]]; then
            # Ubuntu 20.04 / 18.04
            log_info "Installing OpenSCAP for Ubuntu $OS_VERSION"
            sudo apt-get install -y -qq libopenscap8 || {
                log_error "Failed to install libopenscap8"
                exit 1
            }
            sudo apt-get install -y -qq ssg-base ssg-debderived 2>/dev/null || \
            sudo apt-get install -y -qq ssg-debian ssg-applications 2>/dev/null || true
            
        elif [[ "$OS_VERSION" == "24.04" ]] || [[ "$OS_VERSION" > "24" ]]; then
            # Ubuntu 24.04+ (future-proofing)
            log_info "Installing OpenSCAP for Ubuntu $OS_VERSION"
            sudo apt-get install -y -qq openscap-scanner libopenscap25t64 2>/dev/null || \
            sudo apt-get install -y -qq openscap-scanner libopenscap-dev || {
                log_error "Failed to install OpenSCAP scanner"
                exit 1
            }
            sudo apt-get install -y -qq ssg-base ssg-debderived 2>/dev/null || true
            
        else
            log_error "Unsupported Ubuntu version: $OS_VERSION"
            exit 1
        fi
        ;;
    
    rhel|centos|fedora|rocky|almalinux)
        log_info "Installing on RHEL-based system"
        sudo dnf install -y openscap-scanner scap-security-guide 2>/dev/null || \
        sudo yum install -y openscap-scanner scap-security-guide || {
            log_error "Failed to install OpenSCAP on RHEL-based system"
            exit 1
        }
        ;;
    
    *)
        log_error "Unsupported OS: $OS_NAME"
        exit 1
        ;;
esac

# Verify installation
log_info "Verifying OpenSCAP installation..."

if ! command -v oscap &> /dev/null; then
    log_error "oscap command not found after installation"
    exit 1
fi

OSCAP_VERSION=$(oscap --version | head -1)
log_success "OpenSCAP installed: $OSCAP_VERSION"

# Find and verify SCAP content
CONTENT_DIRS=(
    "/usr/share/xml/scap/ssg/content"
    "/usr/share/scap-security-guide"
)

CONTENT_FOUND=""
for dir in "${CONTENT_DIRS[@]}"; do
    if [ -d "$dir" ]; then
        # Look for Ubuntu 22.04 content first (primary target)
        CONTENT=$(ls "$dir"/ssg-ubuntu2204-ds.xml 2>/dev/null | head -1)
        if [ -n "$CONTENT" ]; then
            CONTENT_FOUND=$CONTENT
            break
        fi
        # Fallback to any SCAP content
        CONTENT=$(ls "$dir"/*.xml 2>/dev/null | head -1)
        if [ -n "$CONTENT" ]; then
            CONTENT_FOUND=$CONTENT
            break
        fi
    fi
done

if [ -n "$CONTENT_FOUND" ]; then
    log_success "SCAP content found: $CONTENT_FOUND"
    
    # List available profiles for Ubuntu 22.04
    if [[ "$OS_VERSION" == "22.04" ]] && [ -f "/usr/share/xml/scap/ssg/content/ssg-ubuntu2204-ds.xml" ]; then
        log_info "Available profiles for Ubuntu 22.04:"
        oscap info /usr/share/xml/scap/ssg/content/ssg-ubuntu2204-ds.xml 2>/dev/null | grep "Profile" | head -5 || true
    fi
    
    log_success "Installation complete"
    exit 0
else
    log_error "OpenSCAP installed but no SCAP content found"
    log_error "Searched in: ${CONTENT_DIRS[*]}"
    exit 1
fi


