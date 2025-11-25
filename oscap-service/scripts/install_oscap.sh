#!/bin/bash
# OpenSCAP Installation Script - HPC Cluster Deployment
# Supported OS: RHEL/CentOS/Rocky/AlmaLinux (7-9), SLES (12-15), Ubuntu LTS (18.04-24.04)
# Non-interactive, structured output for scaprun parsing
# Optimized: Skips installation if already present

set -e

# Output format for scaprun parsing
log_info() {
    echo "INFO: $1"
}

log_error() {
    echo "ERROR: $1" >&2
}

log_success() {
    echo "SUCCESS: $1"
}

log_warning() {
    echo "WARNING: $1"
}

# ============================================================================
# Quick Check: Skip if OpenSCAP already installed
# ============================================================================
if command -v oscap &> /dev/null; then
    OSCAP_VERSION=$(oscap --version | head -1)
    log_success "OpenSCAP already installed: $OSCAP_VERSION"
    
    # Quick check for SCAP content
    for dir in /usr/share/xml/scap/ssg/content /usr/share/scap-security-guide; do
        if [ -d "$dir" ] && ls "$dir"/*.xml &>/dev/null; then
            CONTENT=$(ls "$dir"/*.xml 2>/dev/null | head -1)
            log_success "SCAP content found: $CONTENT"
            log_success "Installation verified - Ready for compliance scanning"
            exit 0
        fi
    done
    
    log_warning "OpenSCAP installed but SCAP content missing - will install content only"
    OSCAP_EXISTS=true
else
    OSCAP_EXISTS=false
    log_info "OpenSCAP not found - proceeding with installation"
fi

# Detect OS
if [ ! -f /etc/os-release ]; then
    log_error "Cannot detect OS - /etc/os-release not found"
    exit 1
fi

. /etc/os-release
OS_ID=$ID
OS_VERSION_ID=$VERSION_ID
OS_PRETTY_NAME=$PRETTY_NAME

log_info "Detected OS: $OS_PRETTY_NAME (ID=$OS_ID, VERSION=$OS_VERSION_ID)"

# Main installation switch based on OS
case "$OS_ID" in
    
    # ============================================================================
    # RHEL Family: RHEL, CentOS, Rocky Linux, AlmaLinux (70-80% of HPC clusters)
    # ============================================================================
    rhel|centos|rocky|almalinux)
        log_info "Installing on RHEL-based system: $OS_ID"
        MAJOR_VERSION=$(echo "$OS_VERSION_ID" | cut -d. -f1)
        
        # Check if packages already installed (rpm -q is fast)
        if rpm -q openscap-scanner scap-security-guide &>/dev/null; then
            log_success "OpenSCAP packages already installed"
        else
            log_info "Installing OpenSCAP packages..."
            case "$MAJOR_VERSION" in
                7)
                    sudo yum install -y -q openscap-scanner scap-security-guide || {
                        log_error "Failed to install OpenSCAP on RHEL 7"
                        exit 1
                    }
                    ;;
                8|9)
                    sudo dnf install -y -q openscap-scanner scap-security-guide || {
                        log_error "Failed to install OpenSCAP on RHEL $MAJOR_VERSION"
                        exit 1
                    }
                    ;;
                *)
                    log_error "Unsupported RHEL family version: $MAJOR_VERSION"
                    exit 1
                    ;;
            esac
            log_success "OpenSCAP installed on RHEL family"
        fi
        ;;
    
    # ============================================================================
    # SUSE Linux Enterprise Server (10-15% of HPC clusters)
    # ============================================================================
    sles|sles_sap|suse)
        log_info "Installing on SUSE Linux Enterprise Server"
        MAJOR_VERSION=$(echo "$OS_VERSION_ID" | cut -d. -f1)
        
        # Check if packages already installed
        if rpm -q openscap-utils scap-security-guide &>/dev/null; then
            log_success "OpenSCAP packages already installed"
        else
            log_info "Installing OpenSCAP packages..."
            case "$MAJOR_VERSION" in
                12|15)
                    sudo zypper install -y -q --no-recommends openscap-utils scap-security-guide || {
                        log_error "Failed to install OpenSCAP on SLES $MAJOR_VERSION"
                        exit 1
                    }
                    ;;
                *)
                    log_error "Unsupported SLES version: $MAJOR_VERSION"
                    exit 1
                    ;;
            esac
            log_success "OpenSCAP installed on SLES"
        fi
        ;;
    
    # ============================================================================
    # Ubuntu Server LTS (5-10% of HPC clusters, primarily cloud-based)
    # ============================================================================
    ubuntu)
        log_info "Installing on Ubuntu Server"
        export DEBIAN_FRONTEND=noninteractive
        
        # Install OpenSCAP if not present (we already checked oscap command at top)
        if [ "$OSCAP_EXISTS" = "false" ]; then
            log_info "Installing OpenSCAP packages..."
            case "$OS_VERSION_ID" in
                18.04|20.04|22.04)
                    sudo apt-get install -y -qq libopenscap8 || {
                        log_error "Failed to install libopenscap8"
                        exit 1
                    }
                    ;;
                24.04)
                    sudo apt-get install -y -qq openscap-scanner libopenscap25t64 2>/dev/null || \
                    sudo apt-get install -y -qq openscap-scanner libopenscap-dev || {
                        log_error "Failed to install OpenSCAP"
                        exit 1
                    }
                    ;;
                *)
                    log_error "Unsupported Ubuntu version: $OS_VERSION_ID (supported: 18.04, 20.04, 22.04, 24.04)"
                    exit 1
                    ;;
            esac
        fi
        
        # Check for SCAP content
        if ls /usr/share/xml/scap/ssg/content/ssg-ubuntu*.xml &>/dev/null; then
            log_success "SCAP Security Guide already installed"
        else
            log_info "Installing SCAP Security Guide..."
            sudo apt-get install -y -qq ssg-base ssg-debderived 2>/dev/null || \
            sudo apt-get install -y -qq ssg-debian ssg-applications 2>/dev/null || {
                # Download from GitHub as fallback
                log_info "Downloading SCAP content from GitHub..."
                cd /tmp
                wget -q --timeout=30 https://github.com/ComplianceAsCode/content/releases/download/v0.1.73/scap-security-guide-0.1.73.zip -O ssg.zip 2>/dev/null || \
                wget -q --timeout=30 https://github.com/ComplianceAsCode/content/releases/latest/download/scap-security-guide.zip -O ssg.zip 2>/dev/null || {
                    log_warning "Failed to download SCAP content"
                }
                if [ -f ssg.zip ]; then
                    command -v unzip &>/dev/null || sudo apt-get install -y -qq unzip
                    unzip -q -o ssg.zip 2>/dev/null || true
                    sudo mkdir -p /usr/share/xml/scap/ssg/content
                    sudo cp -f scap-security-guide-*/ssg-ubuntu*.xml /usr/share/xml/scap/ssg/content/ 2>/dev/null || \
                    sudo cp -f */ssg-ubuntu*.xml /usr/share/xml/scap/ssg/content/ 2>/dev/null || true
                    rm -rf ssg.zip scap-security-guide* 2>/dev/null || true
                    log_success "SCAP content installed from GitHub"
                fi
            }
        fi
        
        log_success "OpenSCAP installed on Ubuntu"
        ;;
    
    # ============================================================================
    # Unsupported OS
    # ============================================================================
    *)
        log_error "Unsupported OS: $OS_ID (supported: RHEL/CentOS/Rocky/AlmaLinux 7-9, SLES 12-15, Ubuntu 18.04-24.04)"
        exit 1
        ;;
esac

# ============================================================================
# Final Verification
# ============================================================================
if ! command -v oscap &> /dev/null; then
    log_error "oscap command not found after installation"
    exit 1
fi

OSCAP_VERSION=$(oscap --version | head -1)
log_success "OpenSCAP verified: $OSCAP_VERSION"

# Quick content check
for dir in /usr/share/xml/scap/ssg/content /usr/share/scap-security-guide; do
    if [ -d "$dir" ] && ls "$dir"/*.xml &>/dev/null 2>&1; then
        log_success "SCAP content available in $dir"
        log_success "Installation complete - Ready for compliance scanning"
        exit 0
    fi
done

log_warning "OpenSCAP installed but SCAP content not found"
exit 0



