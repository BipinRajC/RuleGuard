#!/bin/bash
# OpenSCAP Remediation Script - Backend Automation
# Supported OS: RHEL/CentOS/Rocky/AlmaLinux (7-10), SLES (12-16), Ubuntu LTS (18.04-24.04)
# Non-interactive, returns structured output for scaprun parsing
# Usage: PROFILE=xxx RULE_IDS=rule1,rule2 remediate.sh
#    or: remediate.sh <rule_id1> [rule_id2] ...

set -e

# Get rule IDs from args or RULE_IDS env var
if [ $# -gt 0 ]; then
    RULE_ARGS="$@"
elif [ -n "$RULE_IDS" ]; then
    RULE_ARGS=$(echo "$RULE_IDS" | tr ',' ' ')
else
    echo "ERROR:No rules specified"
    echo "USAGE:PROFILE=xxx RULE_IDS=rule1,rule2 remediate.sh"
    exit 1
fi

# Detect OS and find SCAP content
if [ ! -f /etc/os-release ]; then
    echo "ERROR:Cannot detect OS"
    exit 1
fi

. /etc/os-release
OS_ID=$ID
OS_VERSION=$VERSION_ID

# Determine SCAP content file based on OS
case "$OS_ID" in
    rhel|centos|rocky|almalinux)
        # RHEL family
        MAJOR_VERSION=$(echo "$OS_VERSION" | cut -d. -f1)
        case "$MAJOR_VERSION" in
            7)
                CONTENT="/usr/share/xml/scap/ssg/content/ssg-rhel7-ds.xml"
                [ ! -f "$CONTENT" ] && CONTENT="/usr/share/xml/scap/ssg/content/ssg-centos7-ds.xml"
                [ ! -f "$CONTENT" ] && CONTENT="/usr/share/scap-security-guide/ssg-rhel7-ds.xml"
                DEFAULT_PROFILE="cis_server_l1"
                ;;
            8)
                CONTENT="/usr/share/xml/scap/ssg/content/ssg-rhel8-ds.xml"
                [ ! -f "$CONTENT" ] && CONTENT="/usr/share/xml/scap/ssg/content/ssg-centos8-ds.xml"
                [ ! -f "$CONTENT" ] && CONTENT="/usr/share/scap-security-guide/ssg-rhel8-ds.xml"
                DEFAULT_PROFILE="cis_server_l1"
                ;;
            9)
                # For CentOS Stream 9, prefer cs9 content; for RHEL, prefer rhel9
                if [ "$OS_ID" = "centos" ]; then
                    CONTENT="/usr/share/xml/scap/ssg/content/ssg-cs9-ds.xml"
                    [ ! -f "$CONTENT" ] && CONTENT="/usr/share/xml/scap/ssg/content/ssg-rhel9-ds.xml"
                else
                    CONTENT="/usr/share/xml/scap/ssg/content/ssg-rhel9-ds.xml"
                    [ ! -f "$CONTENT" ] && CONTENT="/usr/share/xml/scap/ssg/content/ssg-cs9-ds.xml"
                fi
                [ ! -f "$CONTENT" ] && CONTENT="/usr/share/scap-security-guide/ssg-rhel9-ds.xml"
                DEFAULT_PROFILE="cis_server_l1"
                ;;
            10)
                CONTENT="/usr/share/xml/scap/ssg/content/ssg-rhel10-ds.xml"
                [ ! -f "$CONTENT" ] && CONTENT="/usr/share/scap-security-guide/ssg-rhel10-ds.xml"
                [ ! -f "$CONTENT" ] && CONTENT="/usr/share/xml/scap/ssg/content/ssg-rhel9-ds.xml"
                [ ! -f "$CONTENT" ] && CONTENT="/usr/share/scap-security-guide/ssg-rhel9-ds.xml"
                DEFAULT_PROFILE="cis_server_l1"
                ;;
            *)
                echo "ERROR:No SCAP content for RHEL family version $MAJOR_VERSION"
                exit 1
                ;;
        esac
        ;;
    
    sles|sles_sap|suse)
        # SLES
        MAJOR_VERSION=$(echo "$OS_VERSION" | cut -d. -f1)
        case "$MAJOR_VERSION" in
            12)
                CONTENT="/usr/share/xml/scap/ssg/content/ssg-sle12-ds.xml"
                [ ! -f "$CONTENT" ] && CONTENT="/usr/share/scap-security-guide/ssg-sle12-ds.xml"
                DEFAULT_PROFILE="standard"
                ;;
            15)
                CONTENT="/usr/share/xml/scap/ssg/content/ssg-sle15-ds.xml"
                [ ! -f "$CONTENT" ] && CONTENT="/usr/share/scap-security-guide/ssg-sle15-ds.xml"
                DEFAULT_PROFILE="standard"
                ;;
            16)
                CONTENT="/usr/share/xml/scap/ssg/content/ssg-sle16-ds.xml"
                [ ! -f "$CONTENT" ] && CONTENT="/usr/share/scap-security-guide/ssg-sle16-ds.xml"
                [ ! -f "$CONTENT" ] && CONTENT="/usr/share/xml/scap/ssg/content/ssg-sle15-ds.xml"
                [ ! -f "$CONTENT" ] && CONTENT="/usr/share/scap-security-guide/ssg-sle15-ds.xml"
                DEFAULT_PROFILE="standard"
                ;;
            *)
                echo "ERROR:No SCAP content for SLES version $MAJOR_VERSION"
                exit 1
                ;;
        esac
        ;;
    
    ubuntu)
        # Ubuntu
        case "$OS_VERSION" in
            18.04)
                CONTENT="/usr/share/xml/scap/ssg/content/ssg-ubuntu1804-ds.xml"
                [ ! -f "$CONTENT" ] && CONTENT="/usr/share/scap-security-guide/ssg-ubuntu1804-ds.xml"
                DEFAULT_PROFILE="standard"
                ;;
            20.04)
                CONTENT="/usr/share/xml/scap/ssg/content/ssg-ubuntu2004-ds.xml"
                [ ! -f "$CONTENT" ] && CONTENT="/usr/share/scap-security-guide/ssg-ubuntu2004-ds.xml"
                DEFAULT_PROFILE="standard"
                ;;
            22.04)
                CONTENT="/usr/share/xml/scap/ssg/content/ssg-ubuntu2204-ds.xml"
                [ ! -f "$CONTENT" ] && CONTENT="/usr/share/scap-security-guide/ssg-ubuntu2204-ds.xml"
                DEFAULT_PROFILE="standard"
                ;;
            24.04)
                CONTENT="/usr/share/xml/scap/ssg/content/ssg-ubuntu2204-ds.xml"
                [ ! -f "$CONTENT" ] && CONTENT="/usr/share/scap-security-guide/ssg-ubuntu2204-ds.xml"
                DEFAULT_PROFILE="standard"
                ;;
            *)
                echo "ERROR:No SCAP content for Ubuntu version $OS_VERSION"
                exit 1
                ;;
        esac
        ;;
    
    *)
        echo "ERROR:Unsupported OS: $OS_ID"
        exit 1
        ;;
esac

# Verify SCAP content exists
if [ ! -f "$CONTENT" ]; then
    echo "ERROR:SCAP content not found: $CONTENT"
    echo "ERROR:Please run install-openscap first"
    exit 1
fi

# Verify oscap command is available
if ! command -v oscap &> /dev/null; then
    echo "ERROR:oscap command not found"
    exit 1
fi

# Profile from env var or use OS-specific default
if [ -n "$PROFILE" ]; then
    # Use provided profile
    :
else
    # Use default profile for this OS
    PROFILE="xccdf_org.ssgproject.content_profile_${DEFAULT_PROFILE}"
fi

TIMESTAMP=$(date +%Y%m%d_%H%M%S)

# Output remediation start information
echo "REMEDIATION_START"
echo "TIMESTAMP:$TIMESTAMP"
echo "PROFILE:$PROFILE"
echo "OS_VERSION:$OS_VERSION"
echo "CONTENT:$CONTENT"

FIXED=0
FAILED=0

# Process each rule
for RULE_SHORT in $RULE_ARGS; do
    # Add OpenSCAP rule prefix
    RULE_ID="xccdf_org.ssgproject.content_rule_${RULE_SHORT}"
    TEMP_DIR="/tmp/rem_${RULE_SHORT}_${TIMESTAMP}"
    mkdir -p "$TEMP_DIR"
    
    echo "RULE_START:$RULE_SHORT"
    
    # Attempt remediation (requires root for system changes)
    # Note: Some rules require system changes that may need reboot
    sudo oscap xccdf eval \
        --profile "$PROFILE" \
        --remediate \
        --rule "$RULE_ID" \
        --results "$TEMP_DIR/result.xml" \
        "$CONTENT" > "$TEMP_DIR/output.log" 2>&1 || true
    
    # Check if remediation succeeded
    if [ -f "$TEMP_DIR/result.xml" ] && grep -q '<result>pass</result>' "$TEMP_DIR/result.xml" 2>/dev/null; then
        echo "RULE_SUCCESS:$RULE_SHORT"
        FIXED=$((FIXED + 1))
    else
        # Verify the rule by running a check
        sudo oscap xccdf eval \
            --profile "$PROFILE" \
            --rule "$RULE_ID" \
            --results "$TEMP_DIR/verify.xml" \
            "$CONTENT" > /dev/null 2>&1 || true
        
        if [ -f "$TEMP_DIR/verify.xml" ] && grep -q '<result>pass</result>' "$TEMP_DIR/verify.xml" 2>/dev/null; then
            echo "RULE_SUCCESS:$RULE_SHORT"
            FIXED=$((FIXED + 1))
        else
            echo "RULE_FAILED:$RULE_SHORT"
            # Try to extract failure reason from output
            if [ -f "$TEMP_DIR/output.log" ]; then
                REASON=$(grep -i "error\|fail\|cannot" "$TEMP_DIR/output.log" | head -1 || echo "Unknown error")
                echo "RULE_FAIL_REASON:$REASON"
            fi
            FAILED=$((FAILED + 1))
        fi
    fi
    
    # Cleanup temporary files
    rm -rf "$TEMP_DIR"
    echo "RULE_END:$RULE_SHORT"
done

# Output summary
echo "REMEDIATION_COMPLETE"
echo "TOTAL_FIXED:$FIXED"
echo "TOTAL_FAILED:$FAILED"

# Exit with success if at least some rules were fixed
if [ "$FIXED" -gt 0 ]; then
    exit 0
else
    exit 1
fi

