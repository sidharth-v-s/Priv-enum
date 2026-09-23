#!/bin/bash

# Linux Privilege Escalation Enumeration Script
# Usage: ./enum.sh [-suid] [-suid-root] [-sudo] [-creds] [-ports] [-live-proc] [-groups] [-cron] [-cap] [-help]

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Performance and stability improvements
# set -eo pipefail  # REMOVED: Too risky for enumeration scripts where errors are expected
IFS=$'\n\t'       # Safer IFS

# Global configuration
readonly SCRIPT_VERSION="2.1"
readonly MAX_FIND_DEPTH=3  # Limit find depth for performance
readonly SCAN_TIMEOUT=60   # Timeout for long operations (seconds)
readonly CACHE_DIR="/tmp/enum_cache_$$"
readonly COMMON_PATHS=("/bin" "/sbin" "/usr/bin" "/usr/sbin" "/usr/local/bin" "/usr/local/sbin" "/opt" "/lib" "/lib64")

# Create cache directory
if ! mkdir -p "$CACHE_DIR"; then
    echo "[-] Critical Error: Could not create cache directory $CACHE_DIR" >&2
    exit 1
fi

# Cleanup function
cleanup() {
    # Kill any child processes in our process group
    pkill -P $$ 2>/dev/null || true
    rm -rf "$CACHE_DIR" 2>/dev/null || true
}
# Catch all terminate signals
trap cleanup EXIT INT TERM

# Output Helper Functions
print_info() { echo -e "${BLUE}[*] $1${NC}"; }
print_success() { echo -e "${GREEN}[+] $1${NC}"; }
print_warning() { echo -e "${YELLOW}[!] $1${NC}"; }
print_error() { echo -e "${RED}[-] $1${NC}" >&2; }
print_header() {
    echo -e "${BLUE}═══════════════════════════════════════════════════════════${NC}"
    echo -e "${GREEN}$1${NC}"
    echo -e "${BLUE}═══════════════════════════════════════════════════════════${NC}"
}

# Timeout function
run_with_timeout() {
    local timeout=$1
    shift
    local cmd="$*"
    
    if command -v timeout >/dev/null 2>&1; then
        timeout "$timeout" bash -c "$cmd" 2>/dev/null || return 1
    else
        # Fallback for systems without timeout command
        bash -c "$cmd" 2>/dev/null &
        local pid=$!
        local count=0
        while kill -0 "$pid" 2>/dev/null && [ $count -lt $timeout ]; do
            sleep 1
            count=$((count + 1))
        done
        if kill -0 "$pid" 2>/dev/null; then
            kill "$pid" 2>/dev/null || true
            return 1
        fi
        wait "$pid" 2>/dev/null || true
    fi
}

# Optimized find function
optimized_find() {
    local path=$1
    local criteria=$2
    local max_depth=${3:-$MAX_FIND_DEPTH}
    
    # Simple direct find is often more reliable than complex backgrounding logic for this use case
    # unless we are strictly searching root with timeouts.
    find "$path" $criteria -maxdepth "$max_depth" -not -path "/proc/*" -not -path "/sys/*" -not -path "/dev/*" 2>/dev/null
}

# Input validation function
validate_input() {
    local input=$1
    local pattern=$2
    
    if [[ ! "$input" =~ $pattern ]]; then
        return 1
    fi
    return 0
}

# Banner
banner() {
    echo -e "${BLUE}"
    echo "╔══════════════════════════════════════════════════════════╗"
    echo "║     Linux Privilege Escalation Enumeration Script      ║"
    echo "╚══════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

# Help function
show_help() {
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "If no options are provided, all enumeration modes will run."
    echo ""
    echo "Options:"
    echo "  -suid          Enumerate SUID binaries"
    echo "  -suid-root     Enumerate SUID binaries owned by root"
    echo "  -sudo          Enumerate sudo rules and allowed binaries"
    echo "  -creds         Enumerate users and passwords from files"
    echo "  -ports         Enumerate open ports and listening services"
    echo "  -live-proc     Monitor live processes in real-time (like pspy)"
    echo "  -groups        Enumerate group privileges for current user"
    echo "  -cron          Enumerate cron jobs and scheduled tasks"
    echo "  -cap           Enumerate Linux capabilities"
    echo "  --parallel     Run multiple enumeration modes in parallel (faster)"
    echo "  -help, -h      Show this help message"
    echo ""
    echo "Examples:"
    echo "  $0                          Run all enumeration modes"
    echo "  $0 --parallel               Run all modes in parallel (faster)"
    echo "  $0 -suid                    Run only SUID enumeration"
    echo "  $0 -suid-root               List only root-owned SUID binaries"
    echo "  $0 -sudo                    List sudo rules and allowed binaries"
    echo "  $0 -creds                   Search for credentials in files"
    echo "  $0 -ports                   List open ports and listening services"
    echo "  $0 -live-proc               Monitor processes in real-time (Ctrl+C to stop)"
    echo "  $0 -groups                  List group privileges for current user"
    echo "  $0 -cron                    List cron jobs and scheduled tasks"
    echo "  $0 -cap                     List binaries with Linux capabilities"
    echo "  $0 --parallel -suid -sudo   Run SUID and sudo enumeration in parallel"
    echo ""
    echo "Performance Features:"
    echo "  • Optimized filesystem scanning with depth limits"
    echo "  • Parallel execution support for faster results"
    echo "  • Timeout mechanisms to prevent hanging"
    echo "  • Caching system to avoid redundant scans"
    echo "  • Improved error handling and input validation"
}

# Common SUID binaries list (consolidated)
readonly VULNERABLE_SUID=(
    "/usr/bin/nmap" "/usr/bin/find" "/usr/bin/vim" "/usr/bin/vi" "/usr/bin/nano"
    "/usr/bin/cp" "/usr/bin/mv" "/usr/bin/cat" "/usr/bin/less" "/usr/bin/more"
    "/usr/bin/awk" "/usr/bin/man" "/usr/bin/head" "/usr/bin/tail" "/usr/bin/cut"
    "/usr/bin/strings" "/usr/bin/xxd" "/usr/bin/base64" "/usr/bin/python"
    "/usr/bin/python2" "/usr/bin/python3" "/usr/bin/perl" "/usr/bin/ruby"
    "/usr/bin/lua" "/usr/bin/node" "/usr/bin/php" "/usr/bin/tar" "/usr/bin/zip"
    "/usr/bin/unzip" "/usr/bin/gzip" "/usr/bin/gunzip" "/usr/bin/bzip2"
    "/usr/bin/bunzip2" "/usr/bin/xz" "/usr/bin/7z" "/usr/bin/rar" "/usr/bin/unrar"
    "/usr/bin/mount" "/usr/bin/umount" "/usr/bin/fusermount" "/usr/bin/chmod"
    "/usr/bin/chown" "/usr/bin/chgrp" "/usr/bin/at" "/usr/bin/atq" "/usr/bin/atrm"
    "/usr/bin/batch" "/usr/bin/crontab" "/usr/bin/newgrp" "/usr/bin/sudo"
    "/usr/bin/su" "/usr/bin/pkexec" "/usr/bin/passwd" "/usr/bin/chfn"
    "/usr/bin/chsh" "/usr/bin/gpasswd" "/usr/bin/newuidmap" "/usr/bin/newgidmap"
    "/usr/bin/wget" "/usr/bin/curl" "/usr/bin/aria2c" "/usr/bin/axel"
    "/usr/bin/nc" "/usr/bin/netcat" "/usr/bin/ncat" "/usr/bin/socat"
    "/usr/bin/openssl" "/usr/bin/expect" "/usr/bin/timeout" "/usr/bin/strace"
    "/usr/bin/ltrace" "/usr/bin/gdb" "/usr/bin/readelf" "/usr/bin/objdump"
    "/usr/bin/hexdump" "/usr/bin/od" "/usr/bin/bc" "/usr/bin/dc" "/usr/bin/jq"
    "/usr/bin/make" "/usr/bin/gcc" "/usr/bin/g++" "/usr/bin/clang"
    "/usr/bin/clang++" "/usr/bin/sudoedit" "/usr/bin/doas" "/usr/bin/ksu"
    "/usr/bin/dbus-send" "/usr/bin/polkit-agent-helper-1"
)

# Check if binary is in vulnerable list
is_vulnerable_suid() {
    local binary=$1
    for vuln_bin in "${VULNERABLE_SUID[@]}"; do
        if [[ "$binary" == "$vuln_bin" ]]; then
            return 0
        fi
    done
    return 1
}

# Get file metadata safely
get_file_metadata() {
    local file=$1
    local metadata
    
    if ! metadata=$(stat -c "%a %A %U %G" "$file" 2>/dev/null); then
        # print_error "Failed to stat $file"
        return 1
    fi
    
    echo "$metadata"
}

# Display SUID binary with proper formatting
display_suid_binary() {
    local suid_file=$1
    local filter_owner=${2:-""}
    
    if [[ -z "$suid_file" ]]; then
        return 1
    fi
    
    # Get file metadata
    local metadata
    if ! metadata=$(get_file_metadata "$suid_file"); then
        return 1
    fi
    
    read -r perms owner group <<< "$metadata"
    
    # Apply owner filter if specified
    if [[ -n "$filter_owner" && "$owner" != "$filter_owner" ]]; then
        return 0
    fi
    
    # Check vulnerability
    local is_vuln=false
    if is_vulnerable_suid "$suid_file"; then
        is_vuln=true
    fi
    
    # Display with appropriate formatting
    if [[ "$is_vuln" == true ]]; then
        echo -e "${RED}[!]${NC} ${YELLOW}$suid_file${NC}"
        echo -e "    Permissions: $perms"
        echo -e "    Owner: $owner | Group: $group"
        echo -e "    ${RED}[Potentially Vulnerable]${NC}"
    else
        echo -e "${GREEN}[+]${NC} $suid_file"
        echo -e "    Permissions: $perms"
        echo -e "    Owner: $owner | Group: $group"
    fi
    echo ""
}

# Common SUID enumeration function
enum_suid_common() {
    local title=$1
    local search_filter=$2
    local owner_filter=${3:-""}
    
    echo -e "${GREEN}[+] $title${NC}"
    echo ""
    echo -e "${YELLOW}[*] Searching for SUID binaries...${NC}"
    echo ""
    
    # Use optimized find with timeout
    local suid_files
    if ! suid_files=$(run_with_timeout "$SCAN_TIMEOUT" "optimized_find '/' '-type f $search_filter'"); then
        echo -e "${RED}[-] SUID search timed out or failed${NC}"
        return 1
    fi
    
    if [[ -z "$suid_files" ]]; then
        echo -e "${RED}[-] No SUID binaries found${NC}"
        return 0
    fi
    
    # Count and display results
    local count
    count=$(echo "$suid_files" | wc -l)
    echo -e "${GREEN}[+] Found $count SUID binary/binary(ies)${NC}"
    echo ""
    
    echo -e "${BLUE}═══════════════════════════════════════════════════════════${NC}"
    echo -e "${GREEN}$title:${NC}"
    echo -e "${BLUE}═══════════════════════════════════════════════════════════${NC}"
    echo ""
    
    # Process each SUID file
    while IFS= read -r suid_file; do
        display_suid_binary "$suid_file" "$owner_filter"
    done <<< "$suid_files"
    
    echo -e "${BLUE}═══════════════════════════════════════════════════════════${NC}"
    echo ""
    echo -e "${YELLOW}[*] Note: Some SUID binaries may be exploitable for privilege escalation${NC}"
    echo -e "${YELLOW}[*] Research each binary individually for known exploits${NC}"
    echo ""
}

# SUID Enumeration
enum_suid() {
    enum_suid_common "Enumerating SUID binaries" "-perm -4000"
}

# SUID Root Enumeration
enum_suid_root() {
    enum_suid_common "Enumerating SUID binaries owned by root" "-perm -4000 -user root" "root"
}



# Sudo Enumeration
enum_sudo() {
    echo -e "${GREEN}[+] Enumerating sudo rules...${NC}"
    echo ""
    
    # Check if sudo is installed
    if ! command -v sudo &> /dev/null; then
        echo -e "${RED}[-] sudo is not installed on this system${NC}"
        return
    fi
    
    echo -e "${YELLOW}[*] Checking sudo privileges...${NC}"
    echo ""
    
    # Try to run sudo -l (this may require password)
    # We'll try without password first, then show what we can get
    sudo_output=$(sudo -l 2>&1)
    sudo_exit_code=$?
    
    # Check if we got permission denied or need password
    if echo "$sudo_output" | grep -q "password is required"; then
        echo -e "${YELLOW}[!] Password required for sudo -l${NC}"
        echo -e "${YELLOW}[*] Attempting to read sudoers files directly...${NC}"
        echo ""
        
        # Try to read sudoers files
        sudoers_files=(
            "/etc/sudoers"
            "/etc/sudoers.d/*"
        )
        
        found_rules=false
        
        # Check main sudoers file
        if [ -r "/etc/sudoers" ]; then
            echo -e "${GREEN}[+] Found readable /etc/sudoers file${NC}"
            found_rules=true
        elif [ -f "/etc/sudoers" ]; then
            echo -e "${YELLOW}[*] /etc/sudoers exists but is not readable${NC}"
        fi
        
        # Check sudoers.d directory
        if [ -d "/etc/sudoers.d" ]; then
            readable_files=$(find /etc/sudoers.d -type f -readable 2>/dev/null)
            if [ -n "$readable_files" ]; then
                echo -e "${GREEN}[+] Found readable files in /etc/sudoers.d/${NC}"
                found_rules=true
            fi
        fi
        
        if [ "$found_rules" = false ]; then
            echo -e "${RED}[-] Cannot read sudoers files. Try running with sudo access.${NC}"
            echo -e "${YELLOW}[*] You can manually run: sudo -l${NC}"
            return
        fi
    elif [ $sudo_exit_code -eq 0 ]; then
        # Successfully got sudo -l output
        echo -e "${GREEN}[+] Successfully retrieved sudo rules${NC}"
        echo ""
    else
        # Check if user has no sudo access
        if echo "$sudo_output" | grep -qi "not allowed\|not permitted\|not in sudoers"; then
            echo -e "${RED}[-] Current user is not in sudoers file${NC}"
            echo -e "${YELLOW}[*] Checking if sudoers files are readable...${NC}"
            echo ""
        else
            echo -e "${YELLOW}[*] Attempting to read sudoers files directly...${NC}"
            echo ""
        fi
    fi
    
    echo -e "${BLUE}═══════════════════════════════════════════════════════════${NC}"
    echo -e "${GREEN}Sudo Rules:${NC}"
    echo -e "${BLUE}═══════════════════════════════════════════════════════════${NC}"
    echo ""
    
    # Parse sudo -l output if we got it
    if [ $sudo_exit_code -eq 0 ] && [ -n "$sudo_output" ]; then
        nopasswd_found=false
        commands_found=false
        
        while IFS= read -r line; do
            # Check for NOPASSWD entries
            if echo "$line" | grep -qi "NOPASSWD"; then
                nopasswd_found=true
                echo -e "${RED}[!]${NC} ${YELLOW}$line${NC}"
                echo -e "    ${RED}[NOPASSWD - No password required!]${NC}"
                echo ""
            # Check for specific commands
            elif echo "$line" | grep -qE "^[[:space:]]*\(|^[[:space:]]*[A-Za-z]"; then
                if echo "$line" | grep -qE "(ALL|/usr/bin|/bin|/sbin|/opt)"; then
                    commands_found=true
                    echo -e "${GREEN}[+]${NC} $line"
                    echo ""
                fi
            fi
        done <<< "$sudo_output"
        
        # Extract commands that can be run
        if [ "$commands_found" = true ] || [ "$nopasswd_found" = true ]; then
            echo -e "${BLUE}═══════════════════════════════════════════════════════════${NC}"
            echo ""
            echo -e "${GREEN}Extracted Commands:${NC}"
            echo ""
            
            # Extract binary paths from sudo output
            binaries=$(echo "$sudo_output" | grep -oE "(/usr/bin/[^,]*|/bin/[^,]*|/sbin/[^,]*|/opt/[^,]*|ALL)" | sort -u)
            
            if [ -n "$binaries" ]; then
                while IFS= read -r binary; do
                    if [ "$binary" = "ALL" ]; then
                        echo -e "${RED}[!]${NC} ${YELLOW}ALL commands${NC} ${RED}[Full sudo access!]${NC}"
                    elif [ -n "$binary" ]; then
                        # Check if it's NOPASSWD
                        if echo "$sudo_output" | grep -A 5 "$binary" | grep -qi "NOPASSWD"; then
                            echo -e "${RED}[!]${NC} ${YELLOW}$binary${NC} ${RED}[NOPASSWD]${NC}"
                        else
                            echo -e "${GREEN}[+]${NC} $binary"
                        fi
                    fi
                done <<< "$binaries"
            fi
        fi
    fi
    
    # Also try to read sudoers files directly
    echo ""
    echo -e "${BLUE}═══════════════════════════════════════════════════════════${NC}"
    echo -e "${GREEN}Sudoers File Contents:${NC}"
    echo -e "${BLUE}═══════════════════════════════════════════════════════════${NC}"
    echo ""
    
    # Read main sudoers file
    if [ -r "/etc/sudoers" ]; then
        echo -e "${GREEN}[+] /etc/sudoers:${NC}"
        echo ""
        # Filter out comments and empty lines, show relevant rules
        grep -v "^#" /etc/sudoers 2>/dev/null | grep -v "^$" | grep -E "(ALL|NOPASSWD|/usr/bin|/bin|/sbin)" | while IFS= read -r rule; do
            if echo "$rule" | grep -qi "NOPASSWD"; then
                echo -e "${RED}[!]${NC} ${YELLOW}$rule${NC}"
                echo -e "    ${RED}[NOPASSWD]${NC}"
            else
                echo -e "${GREEN}[+]${NC} $rule"
            fi
            echo ""
        done
    fi
    
    # Read sudoers.d files
    if [ -d "/etc/sudoers.d" ]; then
        for sudoers_file in /etc/sudoers.d/*; do
            if [ -r "$sudoers_file" ] && [ -f "$sudoers_file" ]; then
                echo -e "${GREEN}[+] $sudoers_file:${NC}"
                echo ""
                grep -v "^#" "$sudoers_file" 2>/dev/null | grep -v "^$" | grep -E "(ALL|NOPASSWD|/usr/bin|/bin|/sbin)" | while IFS= read -r rule; do
                    if echo "$rule" | grep -qi "NOPASSWD"; then
                        echo -e "${RED}[!]${NC} ${YELLOW}$rule${NC}"
                        echo -e "    ${RED}[NOPASSWD]${NC}"
                    else
                        echo -e "${GREEN}[+]${NC} $rule"
                    fi
                    echo ""
                done
            fi
        done
    fi
    
    echo -e "${BLUE}═══════════════════════════════════════════════════════════${NC}"
    echo ""
    echo -e "${YELLOW}[*] Note: NOPASSWD entries are particularly dangerous as they don't require a password${NC}"
    echo -e "${YELLOW}[*] Research each allowed binary for privilege escalation techniques${NC}"
    echo ""
}

# Improved credential patterns (more precise)
readonly CREDENTIAL_PATTERNS=(
    # Password patterns
    'password[[:space:]]*[=:][[:space:]]*["'\'']?([^"'\'']{4,})["'\'']?'
    'passwd[[:space:]]*[=:][[:space:]]*["'\'']?([^"'\'']{4,})["'\'']?'
    'pwd[[:space:]]*[=:][[:space:]]*["'\'']?([^"'\'']{4,})["'\'']?'
    'pass[[:space:]]*[=:][[:space:]]*["'\'']?([^"'\'']{4,})["'\'']?'
    
    # Database patterns
    'mysql.*password[[:space:]]*[=:][[:space:]]*["'\'']?([^"'\'']{4,})["'\'']?'
    'postgres.*password[[:space:]]*[=:][[:space:]]*["'\'']?([^"'\'']{4,})["'\'']?'
    'db_password[[:space:]]*[=:][[:space:]]*["'\'']?([^"'\'']{4,})["'\'']?'
    'database.*password[[:space:]]*[=:][[:space:]]*["'\'']?([^"'\'']{4,})["'\'']?'
    
    # API/Token patterns
    'api[_-]?key[[:space:]]*[=:][[:space:]]*["'\'']?([a-zA-Z0-9_-]{16,})["'\'']?'
    'apikey[[:space:]]*[=:][[:space:]]*["'\'']?([a-zA-Z0-9_-]{16,})["'\'']?'
    'secret[[:space:]]*[=:][[:space:]]*["'\'']?([a-zA-Z0-9_-]{8,})["'\'']?'
    'token[[:space:]]*[=:][[:space:]]*["'\'']?([a-zA-Z0-9._-]{16,})["'\'']?'
    'auth[[:space:]]*[=:][[:space:]]*["'\'']?([a-zA-Z0-9_-]{8,})["'\'']?'
    
    # Username patterns
    'username[[:space:]]*[=:][[:space:]]*["'\'']?([^"'\'']{2,})["'\'']?'
    'user[[:space:]]*[=:][[:space:]]*["'\'']?([^"'\'']{2,})["'\'']?'
    'login[[:space:]]*[=:][[:space:]]*["'\'']?([^"'\'']{2,})["'\'']?'
)

# Cache file search results
cache_search_results() {
    local search_key=$1
    local cache_file="$CACHE_DIR/${search_key}.cache"
    
    if [[ -f "$cache_file" ]]; then
        cat "$cache_file"
        return 0
    fi
    return 1
}

# Save search results to cache
save_to_cache() {
    local search_key=$1
    local data=$2
    local cache_file="$CACHE_DIR/${search_key}.cache"
    
    echo "$data" > "$cache_file"
}

# Search file for credentials with improved patterns
search_file_credentials() {
    local file=$1
    local results=""
    
    # Skip binary files
    if file "$file" 2>/dev/null | grep -qE "(binary|executable)"; then
        return 0
    fi
    
    # Search for each pattern
    for pattern in "${CREDENTIAL_PATTERNS[@]}"; do
        local matches
        if matches=$(grep -iE "$pattern" "$file" 2>/dev/null | head -5); then
            results+="$matches"$'\n'
        fi
    done
    
    echo "$results"
}

# Credentials Enumeration
enum_creds() {
    print_header "Enumerating credentials from files..."
    
    # Define search locations (optimized)
    local search_dirs=(
        "$HOME"
        "/var/log"
        "/var/www"
        "/opt"
        "/tmp"
    )
    # Add root if readable
    if [ -r "/root" ]; then
        search_dirs+=("/root")
    fi
    
    # Shell history files
    local history_files=(
        "$HOME/.bash_history"
        "$HOME/.zsh_history"
        "$HOME/.fish_history"
        "$HOME/.sh_history"
        "$HOME/.history"
        "/root/.bash_history"
        "/root/.zsh_history"
        "/root/.fish_history"
        "/root/.sh_history"
        "/root/.history"
    )
    
    local found_creds=false
    local total_findings=0
    
    print_info "Searching for credentials..."
    
    # 1. Search shell history files
    print_info "Checking Shell History Files..."
    
    for hist_file in "${history_files[@]}"; do
        if [[ -f "$hist_file" && -r "$hist_file" ]]; then
            # print_success "Found: $hist_file"
            
            # Use improved credential search
            local cred_results
            if cred_results=$(search_file_credentials "$hist_file"); then
                if [[ -n "$cred_results" ]]; then
                    found_creds=true
                    local count=$(echo "$cred_results" | wc -l)
                    total_findings=$((total_findings + count))
                    
                    print_warning "Found potential credentials in $hist_file:"
                    echo "$cred_results" | sed 's/^/    /'
                fi
            fi
        fi
    done
    
    echo ""
    print_info "Searching Text/Log/Config Files (max depth: $MAX_FIND_DEPTH)..."
    
    # 2. Optimized Main Search Loop
    # We build a massive find command to locate all interesting files in ONE pass
    for search_dir in "${search_dirs[@]}"; do
        if [ -d "$search_dir" ] && [ -r "$search_dir" ]; then
            # print_info "Scanning $search_dir..."
            
            # Find candidate files
            # -size -10M: skip huge files
            while IFS= read -r file; do
                # Check if it's a binary file (fast check)
                if [[ -f "$file" ]] && [[ ! -x "$file" ]]; then 
                     # Run grep for all patterns at once
                     # -H: print filename
                     # -I: skip binary files matching
                     # -n: line number
                     matches=$(grep -HInE "(password|passwd|pwd|username|user|login|mysql|postgres|api[_-]?key|secret|token|auth|credential)[[:space:]]*[=:]" "$file" 2>/dev/null | head -5)
                     
                     if [ -n "$matches" ]; then
                         found_creds=true
                         local count=$(echo "$matches" | wc -l)
                         total_findings=$((total_findings + count))
                         
                         print_success "Potential sensitive data in: $file"
                         # Colorize output
                         echo "$matches" | while IFS= read -r match; do
                            echo -e "    ${YELLOW}$match${NC}"
                         done
                         echo ""
                     fi
                fi
            done < <(optimized_find "$search_dir" "\( -name \"*.txt\" -o -name \"*.log\" -o -name \"*.conf\" -o -name \"*.config\" -o -name \"*.ini\" -o -name \"*.env\" -o -name \"*history*\" -o -name \"*passwd*\" -o -name \"*password*\" -o -name \"*credential*\" -o -name \"*secret*\" \)" "$MAX_FIND_DEPTH")
        fi
    done
    
    # 3. User Enumeration from /etc/passwd
    echo ""
    print_info "Enumerating Users from /etc/passwd..."
    
    if [ -r "/etc/passwd" ]; then
        # Show users with shells
        grep -E ":/bin/(bash|sh|zsh|fish|dash|ksh)" /etc/passwd 2>/dev/null | while IFS= read -r user_line; do
            username=$(echo "$user_line" | cut -d: -f1)
            uid=$(echo "$user_line" | cut -d: -f3)
            gid=$(echo "$user_line" | cut -d: -f4)
            home=$(echo "$user_line" | cut -d: -f6)
            shell=$(echo "$user_line" | cut -d: -f7)
            
            if [ "$uid" = "0" ]; then
                echo -e "    ${RED}[!]${NC} ${YELLOW}$username${NC} (UID: $uid, GID: $gid, Home: $home, Shell: $shell) ${RED}[ROOT]${NC}"
            else
                echo -e "    ${GREEN}[+]${NC} $username (UID: $uid, GID: $gid, Home: $home, Shell: $shell)"
            fi
        done
        echo ""
    fi
    
    # Summary
    echo ""
    print_header "Credential Enumeration Summary"
    if [ "$found_creds" = true ]; then
        print_success "Found $total_findings potential credential(s) or interesting finding(s)."
        print_warning "Review the findings above. Some may be false positives."
    else
        print_info "No obvious credentials found in accessible files."
    fi
    echo ""
}

# Ports Enumeration
enum_ports() {
    echo -e "${GREEN}[+] Enumerating open ports and listening services...${NC}"
    echo ""
    
    # Check which tools are available
    has_ss=false
    has_netstat=false
    has_lsof=false
    
    if command -v ss &> /dev/null; then
        has_ss=true
    fi
    
    if command -v netstat &> /dev/null; then
        has_netstat=true
    fi
    
    if command -v lsof &> /dev/null; then
        has_lsof=true
    fi
    
    if [ "$has_ss" = false ] && [ "$has_netstat" = false ]; then
        echo -e "${RED}[-] Neither 'ss' nor 'netstat' is available${NC}"
        echo -e "${YELLOW}[*] Install 'iproute2' (for ss) or 'net-tools' (for netstat)${NC}"
        return
    fi
    
    # Common port to service mapping
    declare -A port_services=(
        ["21"]="FTP"
        ["22"]="SSH"
        ["23"]="Telnet"
        ["25"]="SMTP"
        ["53"]="DNS"
        ["80"]="HTTP"
        ["88"]="Kerberos"
        ["110"]="POP3"
        ["111"]="RPC"
        ["135"]="MSRPC"
        ["139"]="NetBIOS"
        ["143"]="IMAP"
        ["443"]="HTTPS"
        ["445"]="SMB"
        ["993"]="IMAPS"
        ["995"]="POP3S"
        ["1433"]="MSSQL"
        ["1521"]="Oracle"
        ["3306"]="MySQL"
        ["3389"]="RDP"
        ["5432"]="PostgreSQL"
        ["5900"]="VNC"
        ["5985"]="WinRM"
        ["5986"]="WinRM-HTTPS"
        ["6379"]="Redis"
        ["8080"]="HTTP-Proxy"
        ["8443"]="HTTPS-Alt"
        ["27017"]="MongoDB"
    )
    
    echo -e "${YELLOW}[*] Gathering port information...${NC}"
    echo ""
    
    # Use ss if available (preferred), otherwise use netstat
    if [ "$has_ss" = true ]; then
        echo -e "${GREEN}[+] Using 'ss' command${NC}"
        port_info=$(ss -tulpn 2>/dev/null)
    elif [ "$has_netstat" = true ]; then
        echo -e "${GREEN}[+] Using 'netstat' command${NC}"
        port_info=$(netstat -tulpn 2>/dev/null)
    fi
    
    if [ -z "$port_info" ]; then
        echo -e "${RED}[-] Could not retrieve port information${NC}"
        echo -e "${YELLOW}[*] Try running with sudo/root privileges${NC}"
        return
    fi
    
    echo ""
    echo -e "${BLUE}═══════════════════════════════════════════════════════════${NC}"
    echo -e "${GREEN}Listening Ports:${NC}"
    echo -e "${BLUE}═══════════════════════════════════════════════════════════${NC}"
    echo ""
    
    # Parse and display port information
    listening_count=0
    
    # Process each line of port information
    while IFS= read -r line; do
        # Skip header lines
        if echo "$line" | grep -qE "(State|Proto|Recv-Q|Local|Foreign)"; then
            continue
        fi
        
        # Skip empty lines
        if [ -z "$line" ]; then
            continue
        fi
        
        listening_count=$((listening_count + 1))
        
        # Extract information based on tool used
        if [ "$has_ss" = true ]; then
            # Parse ss output: Netid State Recv-Q Send-Q Local Address:Port Peer Address:Port Process
            protocol=$(echo "$line" | awk '{print $1}')
            state=$(echo "$line" | awk '{print $2}')
            local_addr=$(echo "$line" | awk '{print $5}')
            process=$(echo "$line" | awk '{print $NF}')
            
            # Extract port from local address
            port=$(echo "$local_addr" | awk -F: '{print $NF}')
            address=$(echo "$local_addr" | awk -F: '{print $(NF-1)}')
        else
            # Parse netstat output: Proto Recv-Q Send-Q Local Address Foreign Address State PID/Program name
            protocol=$(echo "$line" | awk '{print $1}')
            local_addr=$(echo "$line" | awk '{print $4}')
            state=$(echo "$line" | awk '{print $6}')
            process=$(echo "$line" | awk '{for(i=7;i<=NF;i++) printf "%s ", $i; print ""}' | sed 's/ $//')
            
            # Extract port from local address
            port=$(echo "$local_addr" | awk -F: '{print $NF}')
            address=$(echo "$local_addr" | awk -F: '{print $(NF-1)}')
        fi
        
        # Clean up process info
        process=$(echo "$process" | sed 's/pid=//' | sed 's/,fd=.*//' | sed 's/users:((//' | sed 's/))//')
        
        # Get process name and PID if available
        pid=""
        pname=""
        
        if [ -n "$process" ]; then
            # Try to extract PID and process name
            if echo "$process" | grep -qE "^[0-9]+"; then
                pid=$(echo "$process" | grep -oE "^[0-9]+")
                pname=$(echo "$process" | sed "s/^$pid,//" | sed 's/.*"\(.*\)".*/\1/' | head -1)
            else
                pname=$(echo "$process" | sed 's/.*"\(.*\)".*/\1/' | head -1)
            fi
            
            # If we have PID, try to get more info
            if [ -n "$pid" ] && [ "$pid" != "0" ]; then
                if [ -r "/proc/$pid/cmdline" ]; then
                    cmdline=$(cat "/proc/$pid/cmdline" 2>/dev/null | tr '\0' ' ' | head -c 100)
                    if [ -n "$cmdline" ]; then
                        pname="$cmdline"
                    fi
                fi
                
                if [ -z "$pname" ] && [ -r "/proc/$pid/comm" ]; then
                    pname=$(cat "/proc/$pid/comm" 2>/dev/null)
                fi
            fi
        fi
        
        # Identify service if known
        service_name=""
        if [ -n "$port" ] && [ -n "${port_services[$port]}" ]; then
            service_name="${port_services[$port]}"
        fi
        
        # Determine if interesting (non-standard ports, root-owned, etc.)
        is_interesting=false
        if [ -n "$port" ] && [ "$port" -gt 1024 ]; then
            is_interesting=true
        fi
        
        if [ -n "$pid" ] && [ "$pid" != "0" ]; then
            if [ -r "/proc/$pid" ]; then
                proc_uid=$(stat -c "%u" "/proc/$pid" 2>/dev/null)
                if [ "$proc_uid" = "0" ]; then
                    is_interesting=true
                fi
            fi
        fi
        
        # Display port information
        if [ "$is_interesting" = true ] || [ -n "$service_name" ]; then
            echo -e "${GREEN}[+]${NC} ${YELLOW}Port: $port${NC} | Protocol: $protocol | Address: $address"
            if [ -n "$service_name" ]; then
                echo -e "    Service: ${BLUE}$service_name${NC}"
            fi
            if [ -n "$pid" ] && [ "$pid" != "0" ]; then
                echo -e "    PID: $pid"
            fi
            if [ -n "$pname" ]; then
                echo -e "    Process: ${YELLOW}$pname${NC}"
            fi
            if [ -n "$state" ] && [ "$state" != "LISTEN" ]; then
                echo -e "    State: $state"
            fi
            echo ""
        else
            echo -e "${GREEN}[+]${NC} Port: $port | Protocol: $protocol | Address: $address"
            if [ -n "$service_name" ]; then
                echo -e "    Service: $service_name"
            fi
            if [ -n "$pid" ] && [ "$pid" != "0" ]; then
                echo -e "    PID: $pid"
            fi
            if [ -n "$pname" ]; then
                echo -e "    Process: $pname"
            fi
            echo ""
        fi
        
    done <<< "$port_info"
    
    # Also try to get more detailed process information using lsof if available
    if [ "$has_lsof" = true ]; then
        echo -e "${BLUE}═══════════════════════════════════════════════════════════${NC}"
        echo -e "${GREEN}Detailed Process Information (lsof):${NC}"
        echo -e "${BLUE}═══════════════════════════════════════════════════════════${NC}"
        echo ""
        
        lsof_info=$(lsof -i -P -n 2>/dev/null | grep -i listen)
        
        if [ -n "$lsof_info" ]; then
            echo "$lsof_info" | while IFS= read -r lsof_line; do
                comm=$(echo "$lsof_line" | awk '{print $1}')
                pid=$(echo "$lsof_line" | awk '{print $2}')
                node=$(echo "$lsof_line" | awk '{print $8}')
                name=$(echo "$lsof_line" | awk '{print $9}')
                
                echo -e "${GREEN}[+]${NC} Process: ${YELLOW}$comm${NC} (PID: $pid)"
                echo -e "    Node: $node | Name: $name"
                echo ""
            done
        else
            echo -e "${YELLOW}[*] No additional information from lsof${NC}"
            echo ""
        fi
    fi
    
    # Summary
    echo -e "${BLUE}═══════════════════════════════════════════════════════════${NC}"
    echo ""
    echo -e "${GREEN}[+] Found $listening_count listening port(s)${NC}"
    echo -e "${YELLOW}[*] Review the ports above for potential services and vulnerabilities${NC}"
    echo -e "${YELLOW}[*] High-numbered ports (>1024) may be custom services${NC}"
    echo -e "${YELLOW}[*] Root-owned processes on listening ports are particularly interesting${NC}"
    echo ""
}

# Live Process Monitoring (pspy-like)
enum_live_proc() {
    echo -e "${GREEN}[+] Starting live process monitoring (pspy-like)...${NC}"
    echo -e "${YELLOW}[*] Press Ctrl+C to stop${NC}"
    echo ""
    
    # Check if /proc is accessible
    if [ ! -d "/proc" ] || [ ! -r "/proc" ]; then
        echo -e "${RED}[-] Cannot access /proc directory${NC}"
        return
    fi
    
    # Check for inotifywait (preferred method)
    has_inotify=false
    if command -v inotifywait &> /dev/null; then
        has_inotify=true
        echo -e "${GREEN}[+] Using inotifywait for efficient monitoring${NC}"
    else
        echo -e "${YELLOW}[*] inotifywait not available, using polling method${NC}"
        echo -e "${YELLOW}[*] Install 'inotify-tools' for better performance${NC}"
    fi
    
    echo ""
    echo -e "${BLUE}═══════════════════════════════════════════════════════════${NC}"
    echo -e "${GREEN}Live Process Events:${NC}"
    echo -e "${BLUE}═══════════════════════════════════════════════════════════${NC}"
    echo ""
    
    # Track seen processes to avoid duplicates
    declare -A seen_pids
    
    # Function to get process info
    get_process_info() {
        local pid=$1
        local proc_dir="/proc/$pid"
        
        # Skip if we've already seen this process
        if [ -n "${seen_pids[$pid]}" ]; then
            return
        fi
        
        # Check if process still exists
        if [ ! -d "$proc_dir" ]; then
            return
        fi
        
        # Mark as seen
        seen_pids[$pid]=1
        
        # Get process information
        local ppid=""
        local cmdline=""
        local comm=""
        local uid=""
        local user=""
        local exe=""
        local cwd=""
        local env_info=""
        
        # Get PPID
        if [ -r "$proc_dir/status" ]; then
            ppid=$(grep "^PPid:" "$proc_dir/status" 2>/dev/null | awk '{print $2}')
        fi
        
        # Get command line
        if [ -r "$proc_dir/cmdline" ]; then
            cmdline=$(cat "$proc_dir/cmdline" 2>/dev/null | tr '\0' ' ' | sed 's/ $//')
        fi
        
        # Get comm (process name)
        if [ -r "$proc_dir/comm" ]; then
            comm=$(cat "$proc_dir/comm" 2>/dev/null | tr -d '\n')
        fi
        
        # Get UID
        if [ -r "$proc_dir/status" ]; then
            uid=$(grep "^Uid:" "$proc_dir/status" 2>/dev/null | awk '{print $2}')
        fi
        
        # Get username from UID
        if [ -n "$uid" ]; then
            user=$(getent passwd "$uid" 2>/dev/null | cut -d: -f1)
            if [ -z "$user" ]; then
                user="UID:$uid"
            fi
        fi
        
        # Get executable path
        if [ -r "$proc_dir/exe" ]; then
            exe=$(readlink "$proc_dir/exe" 2>/dev/null)
        fi
        
        # Get current working directory
        if [ -r "$proc_dir/cwd" ]; then
            cwd=$(readlink "$proc_dir/cwd" 2>/dev/null)
        fi
        
        # Get environment variables (limited)
        if [ -r "$proc_dir/environ" ]; then
            env_info=$(cat "$proc_dir/environ" 2>/dev/null | tr '\0' '\n' | grep -E "(PATH|HOME|USER|PWD)" | head -3 | tr '\n' ' ')
        fi
        
        # Determine if interesting (root-owned, etc.)
        local is_interesting=false
        if [ "$uid" = "0" ]; then
            is_interesting=true
        fi
        
        # Get timestamp
        local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
        
        # Display process information
        if [ "$is_interesting" = true ]; then
            echo -e "${RED}[!]${NC} ${YELLOW}[$timestamp]${NC} ${GREEN}NEW PROCESS${NC}"
            echo -e "    ${RED}PID: $pid${NC} | PPID: $ppid | ${RED}User: $user (ROOT)${NC}"
        else
            echo -e "${GREEN}[+]${NC} ${YELLOW}[$timestamp]${NC} ${GREEN}NEW PROCESS${NC}"
            echo -e "    PID: $pid | PPID: $ppid | User: $user"
        fi
        
        if [ -n "$comm" ]; then
            echo -e "    Command: ${YELLOW}$comm${NC}"
        fi
        
        if [ -n "$cmdline" ] && [ "$cmdline" != "$comm" ]; then
            # Truncate long command lines
            if [ ${#cmdline} -gt 150 ]; then
                cmdline="${cmdline:0:150}..."
            fi
            echo -e "    Cmdline: ${BLUE}$cmdline${NC}"
        fi
        
        if [ -n "$exe" ]; then
            echo -e "    Executable: $exe"
        fi
        
        if [ -n "$cwd" ]; then
            echo -e "    CWD: $cwd"
        fi
        
        if [ -n "$env_info" ]; then
            echo -e "    Env: $env_info"
        fi
        
        echo ""
    }
    
    # Function to scan existing processes
    scan_existing_processes() {
        local current_pids=$(ls -1 /proc 2>/dev/null | grep -E '^[0-9]+$')
        for pid in $current_pids; do
            if [ -z "${seen_pids[$pid]}" ]; then
                get_process_info "$pid"
            fi
        done
    }
    
    # Initial scan of existing processes
    echo -e "${YELLOW}[*] Scanning existing processes...${NC}"
    scan_existing_processes
    echo -e "${GREEN}[+] Now monitoring for new processes...${NC}"
    echo ""
    
    # Set up signal handler for clean exit
    trap 'echo ""; echo -e "${YELLOW}[*] Monitoring stopped${NC}"; exit 0' INT TERM
    
    if [ "$has_inotify" = true ]; then
        # Use inotifywait to monitor /proc for new directories (new processes)
        inotifywait -m -q -e create --format '%w%f' /proc 2>/dev/null | while read -r event_path; do
            # Extract PID from path
            pid=$(basename "$event_path")
            
            # Check if it's a numeric PID
            if [[ "$pid" =~ ^[0-9]+$ ]]; then
                # Small delay to let process initialize
                sleep 0.1
                get_process_info "$pid"
            fi
        done
    else
        # Polling method: periodically check for new processes
        local last_scan_pids=""
        
        while true; do
            local current_pids=$(ls -1 /proc 2>/dev/null | grep -E '^[0-9]+$' | sort -n)
            
            # Find new PIDs
            if [ -n "$last_scan_pids" ]; then
                for pid in $current_pids; do
                    if ! echo "$last_scan_pids" | grep -q "^$pid$"; then
                        # New process found
                        sleep 0.1  # Small delay
                        get_process_info "$pid"
                    fi
                done
            fi
            
            last_scan_pids="$current_pids"
            sleep 0.5  # Poll every 500ms
        done
    fi
}

# Groups Enumeration
enum_groups() {
    echo -e "${GREEN}[+] Enumerating group privileges for current user...${NC}"
    echo ""
    
    # Get current user
    current_user=$(whoami)
    current_uid=$(id -u)
    
    echo -e "${YELLOW}[*] Current user: ${GREEN}$current_user${NC} (UID: $current_uid)"
    echo ""
    
    # Get all groups for current user
    groups_list=$(groups)
    group_ids=$(id -G)
    
    echo -e "${BLUE}═══════════════════════════════════════════════════════════${NC}"
    echo -e "${GREEN}Group Memberships:${NC}"
    echo -e "${BLUE}═══════════════════════════════════════════════════════════${NC}"
    echo ""
    
    # List of potentially interesting/privileged groups
    # Note: This array is for reference, actual checking is done via case statement
    privileged_groups=(
        "root"
        "sudo"
        "admin"
        "wheel"
        "docker"
        "lxd"
        "kvm"
        "libvirt"
        "audio"
        "video"
        "disk"
        "dialout"
        "cdrom"
        "floppy"
        "tape"
        "adm"
        "systemd-journal"
        "systemd-network"
        "systemd-resolve"
        "systemd-timesync"
        "input"
        "render"
        "lp"
        "mail"
        "news"
        "uucp"
        "man"
        "proxy"
        "www-data"
        "backup"
        "list"
        "irc"
        "gnats"
        "nobody"
        "nogroup"
        "users"
        "netdev"
        "plugdev"
        "staff"
        "games"
    )
    
    # Parse groups
    group_count=0
    interesting_groups=0
    
    for group in $groups_list; do
        group_count=$((group_count + 1))
        
        # Get GID for this group
        gid=$(getent group "$group" 2>/dev/null | cut -d: -f3)
        
        # Get group members
        members=$(getent group "$group" 2>/dev/null | cut -d: -f4)
        
        # Check if it's a privileged/interesting group
        is_privileged=false
        privilege_info=""
        
        case "$group" in
            root|sudo|admin|wheel)
                is_privileged=true
                privilege_info="${RED}[PRIVILEGED - May have sudo/admin access]${NC}"
                interesting_groups=$((interesting_groups + 1))
                ;;
            docker)
                is_privileged=true
                privilege_info="${RED}[PRIVILEGED - Docker group can lead to root]${NC}"
                interesting_groups=$((interesting_groups + 1))
                ;;
            lxd)
                is_privileged=true
                privilege_info="${RED}[PRIVILEGED - LXD group can lead to root]${NC}"
                interesting_groups=$((interesting_groups + 1))
                ;;
            kvm|libvirt)
                is_privileged=true
                privilege_info="${YELLOW}[INTERESTING - Virtualization access]${NC}"
                interesting_groups=$((interesting_groups + 1))
                ;;
            disk|audio|video|dialout|cdrom|floppy|tape)
                is_privileged=true
                privilege_info="${YELLOW}[INTERESTING - Hardware access]${NC}"
                interesting_groups=$((interesting_groups + 1))
                ;;
            adm|systemd-*)
                is_privileged=true
                privilege_info="${YELLOW}[INTERESTING - System administration]${NC}"
                interesting_groups=$((interesting_groups + 1))
                ;;
        esac
        
        # Display group information
        if [ "$is_privileged" = true ]; then
            echo -e "${RED}[!]${NC} ${YELLOW}Group: $group${NC} (GID: $gid)"
        else
            echo -e "${GREEN}[+]${NC} Group: $group (GID: $gid)"
        fi
        
        if [ -n "$members" ]; then
            echo -e "    Members: $members"
        fi
        
        if [ -n "$privilege_info" ]; then
            echo -e "    $privilege_info"
        fi
        
        # Check for group-writable files/directories
        if [ "$group" != "root" ] && [ -n "$gid" ]; then
            # Check for group-writable sensitive directories
            group_writable_dirs=$(find / -type d -group "$group" -perm -g=w 2>/dev/null | head -5)
            if [ -n "$group_writable_dirs" ]; then
                echo -e "    ${YELLOW}[*] Group-writable directories found:${NC}"
                echo "$group_writable_dirs" | while IFS= read -r dir; do
                    echo -e "        ${GREEN}[+]${NC} $dir"
                done
            fi
        fi
        
        echo ""
    done
    
    # Check for SGID binaries owned by user's groups
    echo -e "${BLUE}═══════════════════════════════════════════════════════════${NC}"
    echo -e "${GREEN}SGID Binaries Owned by User's Groups:${NC}"
    echo -e "${BLUE}═══════════════════════════════════════════════════════════${NC}"
    echo ""
    
    sgid_found=false
    for group in $groups_list; do
        gid=$(getent group "$group" 2>/dev/null | cut -d: -f3)
        if [ -n "$gid" ]; then
            sgid_files=$(find / -type f -perm -2000 -group "$group" 2>/dev/null | head -10)
            if [ -n "$sgid_files" ]; then
                sgid_found=true
                echo -e "${GREEN}[+] SGID binaries owned by group '$group':${NC}"
                echo "$sgid_files" | while IFS= read -r sgid_file; do
                    perms=$(stat -c "%a %A" "$sgid_file" 2>/dev/null | awk '{print $2}')
                    owner=$(stat -c "%U" "$sgid_file" 2>/dev/null)
                    echo -e "    ${YELLOW}$sgid_file${NC}"
                    echo -e "        Permissions: $perms | Owner: $owner"
                done
                echo ""
            fi
        fi
    done
    
    if [ "$sgid_found" = false ]; then
        echo -e "${YELLOW}[*] No SGID binaries found owned by user's groups${NC}"
        echo ""
    fi
    
    # Check primary group
    primary_gid=$(id -g)
    primary_group=$(id -gn)
    
    echo -e "${BLUE}═══════════════════════════════════════════════════════════${NC}"
    echo -e "${GREEN}Primary Group Information:${NC}"
    echo -e "${BLUE}═══════════════════════════════════════════════════════════${NC}"
    echo ""
    echo -e "${GREEN}[+]${NC} Primary Group: ${YELLOW}$primary_group${NC} (GID: $primary_gid)"
    echo ""
    
    # Check for files owned by primary group
    primary_group_files=$(find "$HOME" -type f -group "$primary_group" 2>/dev/null | wc -l)
    if [ "$primary_group_files" -gt 0 ]; then
        echo -e "${YELLOW}[*] Found $primary_group_files file(s) in $HOME owned by primary group${NC}"
    fi
    echo ""
    
    # Summary
    echo -e "${BLUE}═══════════════════════════════════════════════════════════${NC}"
    echo ""
    echo -e "${GREEN}[+] User '$current_user' is a member of $group_count group(s)${NC}"
    if [ "$interesting_groups" -gt 0 ]; then
        echo -e "${RED}[!] Found $interesting_groups potentially privileged/interesting group(s)${NC}"
        echo -e "${YELLOW}[*] Review the groups above for privilege escalation opportunities${NC}"
    fi
    echo -e "${YELLOW}[*] Groups like 'docker', 'lxd', 'sudo' can lead to privilege escalation${NC}"
    echo ""
}

# Cron Enumeration
enum_cron() {
    echo -e "${GREEN}[+] Enumerating cron jobs and scheduled tasks...${NC}"
    echo ""
    
    found_crons=false
    cron_count=0
    writable_crons=0
    
    # Check current user's crontab
    echo -e "${BLUE}═══════════════════════════════════════════════════════════${NC}"
    echo -e "${GREEN}User Crontabs:${NC}"
    echo -e "${BLUE}═══════════════════════════════════════════════════════════${NC}"
    echo ""
    
    current_user=$(whoami)
    
    # Try to list user crontabs
    if command -v crontab &> /dev/null; then
        # Current user's crontab
        user_crontab=$(crontab -l 2>/dev/null)
        if [ -n "$user_crontab" ]; then
            found_crons=true
            cron_count=$((cron_count + 1))
            echo -e "${GREEN}[+] Current user ($current_user) crontab:${NC}"
            echo "$user_crontab" | grep -v "^#" | grep -v "^$" | while IFS= read -r line; do
                if [ -n "$line" ]; then
                    echo -e "    ${YELLOW}$line${NC}"
                fi
            done
            echo ""
        else
            echo -e "${YELLOW}[*] No crontab found for current user${NC}"
            echo ""
        fi
        
        # Try to list other users' crontabs (if we have access)
        for user_home in /home/* /root; do
            if [ -d "$user_home" ]; then
                username=$(basename "$user_home")
                if [ "$username" != "$current_user" ]; then
                    user_crontab=$(crontab -u "$username" -l 2>/dev/null)
                    if [ -n "$user_crontab" ]; then
                        found_crons=true
                        cron_count=$((cron_count + 1))
                        echo -e "${GREEN}[+] User '$username' crontab:${NC}"
                        echo "$user_crontab" | grep -v "^#" | grep -v "^$" | while IFS= read -r line; do
                            if [ -n "$line" ]; then
                                echo -e "    ${YELLOW}$line${NC}"
                            fi
                        done
                        echo ""
                    fi
                fi
            fi
        done
    else
        echo -e "${YELLOW}[*] crontab command not available${NC}"
        echo ""
    fi
    
    # Check system-wide crontab
    echo -e "${BLUE}═══════════════════════════════════════════════════════════${NC}"
    echo -e "${GREEN}System-wide Crontab:${NC}"
    echo -e "${BLUE}═══════════════════════════════════════════════════════════${NC}"
    echo ""
    
    if [ -r "/etc/crontab" ]; then
        found_crons=true
        cron_count=$((cron_count + 1))
        echo -e "${GREEN}[+] /etc/crontab (readable):${NC}"
        echo ""
        
        # Check if writable
        if [ -w "/etc/crontab" ]; then
            writable_crons=$((writable_crons + 1))
            echo -e "${RED}[!]${NC} ${RED}/etc/crontab is WRITABLE!${NC}"
            echo ""
        fi
        
        # Parse and display cron jobs
        grep -v "^#" /etc/crontab 2>/dev/null | grep -v "^$" | while IFS= read -r line; do
            if [ -n "$line" ]; then
                # Extract schedule and command
                schedule=$(echo "$line" | awk '{print $1, $2, $3, $4, $5}')
                user=$(echo "$line" | awk '{print $6}')
                command=$(echo "$line" | awk '{for(i=7;i<=NF;i++) printf "%s ", $i; print ""}' | sed 's/ $//')
                
                if [ "$user" = "root" ]; then
                    echo -e "    ${RED}[!]${NC} ${YELLOW}Schedule: $schedule${NC} | ${RED}User: $user${NC}"
                else
                    echo -e "    ${GREEN}[+]${NC} Schedule: $schedule | User: $user"
                fi
                echo -e "        Command: ${BLUE}$command${NC}"
                echo ""
            fi
        done
    else
        echo -e "${YELLOW}[*] /etc/crontab not readable${NC}"
        echo ""
    fi
    
    # Check /etc/cron.d/ directory
    echo -e "${BLUE}═══════════════════════════════════════════════════════════${NC}"
    echo -e "${GREEN}/etc/cron.d/ Directory:${NC}"
    echo -e "${BLUE}═══════════════════════════════════════════════════════════${NC}"
    echo ""
    
    if [ -d "/etc/cron.d" ]; then
        if [ -r "/etc/cron.d" ]; then
            for cron_file in /etc/cron.d/*; do
                if [ -f "$cron_file" ] && [ -r "$cron_file" ]; then
                    found_crons=true
                    cron_count=$((cron_count + 1))
                    
                    filename=$(basename "$cron_file")
                    echo -e "${GREEN}[+] File: $filename${NC}"
                    
                    # Check if writable
                    if [ -w "$cron_file" ]; then
                        writable_crons=$((writable_crons + 1))
                        echo -e "    ${RED}[!]${NC} ${RED}File is WRITABLE!${NC}"
                    fi
                    
                    # Parse and display cron jobs
                    grep -v "^#" "$cron_file" 2>/dev/null | grep -v "^$" | while IFS= read -r line; do
                        if [ -n "$line" ]; then
                            schedule=$(echo "$line" | awk '{print $1, $2, $3, $4, $5}')
                            user=$(echo "$line" | awk '{print $6}')
                            command=$(echo "$line" | awk '{for(i=7;i<=NF;i++) printf "%s ", $i; print ""}' | sed 's/ $//')
                            
                            if [ "$user" = "root" ]; then
                                echo -e "    ${RED}[!]${NC} ${YELLOW}Schedule: $schedule${NC} | ${RED}User: $user${NC}"
                            else
                                echo -e "    ${GREEN}[+]${NC} Schedule: $schedule | User: $user"
                            fi
                            echo -e "        Command: ${BLUE}$command${NC}"
                        fi
                    done
                    echo ""
                fi
            done
        else
            echo -e "${YELLOW}[*] /etc/cron.d/ not readable${NC}"
            echo ""
        fi
    fi
    
    # Check periodic cron directories
    cron_dirs=(
        "/etc/cron.hourly"
        "/etc/cron.daily"
        "/etc/cron.weekly"
        "/etc/cron.monthly"
    )
    
    echo -e "${BLUE}═══════════════════════════════════════════════════════════${NC}"
    echo -e "${GREEN}Periodic Cron Directories:${NC}"
    echo -e "${BLUE}═══════════════════════════════════════════════════════════${NC}"
    echo ""
    
    for cron_dir in "${cron_dirs[@]}"; do
        if [ -d "$cron_dir" ] && [ -r "$cron_dir" ]; then
            period=$(basename "$cron_dir" | sed 's/cron\.//')
            echo -e "${GREEN}[+] $cron_dir ($period):${NC}"
            
            # List files in directory
            files_found=false
            for cron_script in "$cron_dir"/*; do
                if [ -f "$cron_script" ] && [ -r "$cron_script" ]; then
                    files_found=true
                    found_crons=true
                    cron_count=$((cron_count + 1))
                    
                    script_name=$(basename "$cron_script")
                    echo -e "    ${GREEN}[+]${NC} Script: ${YELLOW}$script_name${NC}"
                    
                    # Check if writable
                    if [ -w "$cron_script" ]; then
                        writable_crons=$((writable_crons + 1))
                        echo -e "        ${RED}[!]${NC} ${RED}Script is WRITABLE!${NC}"
                    fi
                    
                    # Get file owner
                    owner=$(stat -c "%U" "$cron_script" 2>/dev/null)
                    perms=$(stat -c "%a %A" "$cron_script" 2>/dev/null | awk '{print $2}')
                    
                    if [ "$owner" = "root" ]; then
                        echo -e "        ${RED}[!]${NC} Owner: ${RED}$owner${NC} | Permissions: $perms"
                    else
                        echo -e "        Owner: $owner | Permissions: $perms"
                    fi
                    
                    # Show first few lines of script
                    head -3 "$cron_script" 2>/dev/null | while IFS= read -r line; do
                        if [ -n "$line" ]; then
                            echo -e "        ${BLUE}$line${NC}"
                        fi
                    done
                    echo ""
                fi
            done
            
            if [ "$files_found" = false ]; then
                echo -e "    ${YELLOW}[*] No scripts found${NC}"
                echo ""
            fi
        fi
    done
    
    # Check for writable cron directories
    echo -e "${BLUE}═══════════════════════════════════════════════════════════${NC}"
    echo -e "${GREEN}Writable Cron Directories/Files:${NC}"
    echo -e "${BLUE}═══════════════════════════════════════════════════════════${NC}"
    echo ""
    
    writable_found=false
    
    # Check if we can write to cron directories
    for cron_dir in "/etc/cron.d" "/etc/cron.hourly" "/etc/cron.daily" "/etc/cron.weekly" "/etc/cron.monthly"; do
        if [ -d "$cron_dir" ] && [ -w "$cron_dir" ]; then
            writable_found=true
            echo -e "${RED}[!]${NC} ${RED}$cron_dir is WRITABLE!${NC}"
            echo -e "    ${RED}[CRITICAL] You can create cron jobs here for privilege escalation!${NC}"
            echo ""
        fi
    done
    
    # Check for writable files in cron directories
    for cron_dir in "/etc/cron.d" "/etc/cron.hourly" "/etc/cron.daily" "/etc/cron.weekly" "/etc/cron.monthly"; do
        if [ -d "$cron_dir" ] && [ -r "$cron_dir" ]; then
            writable_files=$(find "$cron_dir" -type f -writable 2>/dev/null)
            if [ -n "$writable_files" ]; then
                writable_found=true
                echo "$writable_files" | while IFS= read -r file; do
                    echo -e "${RED}[!]${NC} ${RED}$file is WRITABLE!${NC}"
                    echo -e "    ${RED}[CRITICAL] You can modify this cron job!${NC}"
                    echo ""
                done
            fi
        fi
    done
    
    if [ "$writable_found" = false ]; then
        echo -e "${YELLOW}[*] No writable cron directories or files found${NC}"
        echo ""
    fi
    
    # Summary
    echo -e "${BLUE}═══════════════════════════════════════════════════════════${NC}"
    echo ""
    if [ "$found_crons" = true ]; then
        echo -e "${GREEN}[+] Found $cron_count cron job(s) or script(s)${NC}"
        if [ "$writable_crons" -gt 0 ]; then
            echo -e "${RED}[!]${NC} ${RED}Found $writable_crons writable cron file(s)!${NC}"
            echo -e "${RED}[!]${NC} ${RED}Writable cron files can be exploited for privilege escalation!${NC}"
        fi
        echo -e "${YELLOW}[*] Review cron jobs for commands running as root or other privileged users${NC}"
        echo -e "${YELLOW}[*] Check if any cron scripts are writable or in writable directories${NC}"
    else
        echo -e "${YELLOW}[*] No readable cron jobs found${NC}"
        echo -e "${YELLOW}[*] Try running with higher privileges to see more${NC}"
    fi
    echo ""
}

# Capabilities Enumeration
enum_cap() {
    echo -e "${GREEN}[+] Enumerating Linux capabilities...${NC}"
    echo ""
    
    # Check if getcap is available
    if ! command -v getcap &> /dev/null; then
        echo -e "${YELLOW}[*] getcap command not available${NC}"
        echo -e "${YELLOW}[*] Install 'libcap-ng-utils' or 'libcap2-bin' package${NC}"
        echo -e "${YELLOW}[*] Attempting alternative methods...${NC}"
        echo ""
    fi
    
    # Dangerous capabilities that can lead to privilege escalation
    declare -A dangerous_caps=(
        ["CAP_DAC_OVERRIDE"]="Bypass file read, write, and execute permission checks"
        ["CAP_DAC_READ_SEARCH"]="Bypass file read permission checks and directory read and execute permission checks"
        ["CAP_SYS_ADMIN"]="Perform a range of system administration operations"
        ["CAP_SYS_MODULE"]="Load and unload kernel modules"
        ["CAP_SYS_RAWIO"]="Perform I/O port operations"
        ["CAP_SYS_PTRACE"]="Trace arbitrary processes"
        ["CAP_SYS_TIME"]="Modify system clock"
        ["CAP_FOWNER"]="Bypass permission checks on operations that normally require the file system UID of the process to match the UID of the file"
        ["CAP_SETUID"]="Make arbitrary manipulations of process UIDs"
        ["CAP_SETGID"]="Make arbitrary manipulations of process GIDs"
        ["CAP_SETFCAP"]="Set file capabilities"
        ["CAP_SYS_CHROOT"]="Use chroot()"
        ["CAP_KILL"]="Bypass permission checks for sending signals"
        ["CAP_NET_BIND_SERVICE"]="Bind a socket to Internet domain privileged ports"
        ["CAP_NET_RAW"]="Use RAW and PACKET sockets"
        ["CAP_IPC_LOCK"]="Lock memory"
        ["CAP_IPC_OWNER"]="Bypass permission checks for operations on System V IPC objects"
        ["CAP_SYS_BOOT"]="Use reboot() and kexec_load()"
        ["CAP_SYS_NICE"]="Raise process nice value and set real-time scheduling policies"
        ["CAP_SYS_RESOURCE"]="Override resource limits"
    )
    
    # Check current process capabilities
    echo -e "${BLUE}═══════════════════════════════════════════════════════════${NC}"
    echo -e "${GREEN}Current Process Capabilities:${NC}"
    echo -e "${BLUE}═══════════════════════════════════════════════════════════${NC}"
    echo ""
    
    current_pid=$$
    
    # Check /proc/self/status for capabilities
    if [ -r "/proc/self/status" ]; then
        cap_inherit=$(grep "^CapInh:" /proc/self/status 2>/dev/null | awk '{print $2}')
        cap_permitted=$(grep "^CapPrm:" /proc/self/status 2>/dev/null | awk '{print $2}')
        cap_effective=$(grep "^CapEff:" /proc/self/status 2>/dev/null | awk '{print $2}')
        cap_bounding=$(grep "^CapBnd:" /proc/self/status 2>/dev/null | awk '{print $2}')
        cap_ambient=$(grep "^CapAmb:" /proc/self/status 2>/dev/null | awk '{print $2}')
        
        if [ -n "$cap_effective" ]; then
            echo -e "${GREEN}[+] Process capabilities (PID: $current_pid):${NC}"
            echo -e "    Effective: $cap_effective"
            echo -e "    Permitted: $cap_permitted"
            echo -e "    Inheritable: $cap_inherit"
            echo -e "    Bounding: $cap_bounding"
            if [ -n "$cap_ambient" ]; then
                echo -e "    Ambient: $cap_ambient"
            fi
            echo ""
            
            # Decode capabilities if capsh is available
            if command -v capsh &> /dev/null; then
                effective_decoded=$(capsh --decode="$cap_effective" 2>/dev/null | sed 's/Current: = //')
                if [ -n "$effective_decoded" ] && [ "$effective_decoded" != "=" ]; then
                    echo -e "${YELLOW}[*] Decoded effective capabilities:${NC}"
                    echo -e "    $effective_decoded"
                    echo ""
                fi
            fi
        else
            echo -e "${YELLOW}[*] No capabilities found for current process${NC}"
            echo ""
        fi
    fi
    
    # Find binaries with capabilities
    echo -e "${BLUE}═══════════════════════════════════════════════════════════${NC}"
    echo -e "${GREEN}Binaries with Capabilities:${NC}"
    echo -e "${BLUE}═══════════════════════════════════════════════════════════${NC}"
    echo ""
    
    if command -v getcap &> /dev/null; then
        echo -e "${YELLOW}[*] Searching for binaries with capabilities...${NC}"
        echo ""
        
        # Use getcap to find all files with capabilities
        cap_files=$(getcap -r / 2>/dev/null)
        
        if [ -z "$cap_files" ]; then
            echo -e "${YELLOW}[*] No binaries with capabilities found${NC}"
            echo ""
        else
            cap_count=0
            dangerous_count=0
            
            while IFS= read -r cap_line; do
                if [ -n "$cap_line" ]; then
                    cap_count=$((cap_count + 1))
                    
                    # Parse getcap output: /path/to/file = cap1,cap2,cap3+ep
                    file_path=$(echo "$cap_line" | awk -F' = ' '{print $1}')
                    caps=$(echo "$cap_line" | awk -F' = ' '{print $2}')
                    
                    # Check if any dangerous capabilities are present
                    is_dangerous=false
                    dangerous_caps_found=""
                    
                    for cap_name in "${!dangerous_caps[@]}"; do
                        if echo "$caps" | grep -q "$cap_name"; then
                            is_dangerous=true
                            if [ -z "$dangerous_caps_found" ]; then
                                dangerous_caps_found="$cap_name"
                            else
                                dangerous_caps_found="$dangerous_caps_found, $cap_name"
                            fi
                        fi
                    done
                    
                    # Increment dangerous count only once per binary if it has dangerous caps
                    if [ "$is_dangerous" = true ]; then
                        dangerous_count=$((dangerous_count + 1))
                    fi
                    
                    # Get file info
                    if [ -f "$file_path" ]; then
                        owner=$(stat -c "%U" "$file_path" 2>/dev/null)
                        perms=$(stat -c "%a %A" "$file_path" 2>/dev/null | awk '{print $2}')
                        
                        # Display with color coding
                        if [ "$is_dangerous" = true ]; then
                            echo -e "${RED}[!]${NC} ${YELLOW}$file_path${NC}"
                            echo -e "    Capabilities: ${RED}$caps${NC}"
                            echo -e "    ${RED}[DANGEROUS]${NC} Found: $dangerous_caps_found"
                            echo -e "    Owner: $owner | Permissions: $perms"
                            
                            # Show what dangerous capabilities allow
                            for cap_name in $(echo "$dangerous_caps_found" | tr ',' ' '); do
                                cap_name=$(echo "$cap_name" | xargs)
                                if [ -n "${dangerous_caps[$cap_name]}" ]; then
                                    echo -e "        ${YELLOW}→${NC} $cap_name: ${dangerous_caps[$cap_name]}"
                                fi
                            done
                        else
                            echo -e "${GREEN}[+]${NC} $file_path"
                            echo -e "    Capabilities: $caps"
                            echo -e "    Owner: $owner | Permissions: $perms"
                        fi
                        echo ""
                    fi
                fi
            done <<< "$cap_files"
            
            echo -e "${BLUE}═══════════════════════════════════════════════════════════${NC}"
            echo ""
            echo -e "${GREEN}[+] Found $cap_count binary/binary(ies) with capabilities${NC}"
            if [ "$dangerous_count" -gt 0 ]; then
                echo -e "${RED}[!]${NC} ${RED}Found $dangerous_count binary/binary(ies) with dangerous capabilities!${NC}"
                echo -e "${YELLOW}[*] These capabilities can potentially be exploited for privilege escalation${NC}"
            fi
        fi
    else
        # Alternative: search for extended attributes
        echo -e "${YELLOW}[*] getcap not available, searching for extended attributes...${NC}"
        echo ""
        
        # Search common locations for files with capabilities
        search_dirs=(
            "/usr/bin"
            "/usr/sbin"
            "/bin"
            "/sbin"
            "/opt"
        )
        
        found_caps=false
        for search_dir in "${search_dirs[@]}"; do
            if [ -d "$search_dir" ] && [ -r "$search_dir" ]; then
                # Look for files with security.capability extended attribute
                dir_has_caps=false
                while IFS= read -r file; do
                    if [ -f "$file" ] && getfattr -h -m security.capability "$file" &>/dev/null; then
                        if [ "$dir_has_caps" = false ]; then
                            dir_has_caps=true
                            found_caps=true
                            echo -e "${GREEN}[+] Found files with capabilities in: $search_dir${NC}"
                        fi
                        owner=$(stat -c "%U" "$file" 2>/dev/null)
                        echo -e "    ${YELLOW}$file${NC} (Owner: $owner)"
                    fi
                done < <(find "$search_dir" -type f 2>/dev/null | head -50)
                
                if [ "$dir_has_caps" = true ]; then
                    echo ""
                fi
            fi
        done
        
        if [ "$found_caps" = false ]; then
            echo -e "${YELLOW}[*] No files with capabilities found (or unable to check)${NC}"
            echo ""
        fi
    fi
    
    # Check for capability-related vulnerabilities
    echo -e "${BLUE}═══════════════════════════════════════════════════════════${NC}"
    echo -e "${GREEN}Capability Exploitation Notes:${NC}"
    echo -e "${BLUE}═══════════════════════════════════════════════════════════${NC}"
    echo ""
    echo -e "${YELLOW}[*] Dangerous capabilities to look for:${NC}"
    echo -e "    ${RED}CAP_DAC_OVERRIDE${NC} - Can read/write any file"
    echo -e "    ${RED}CAP_DAC_READ_SEARCH${NC} - Can read any file"
    echo -e "    ${RED}CAP_SYS_ADMIN${NC} - System administration operations"
    echo -e "    ${RED}CAP_SYS_MODULE${NC} - Can load kernel modules"
    echo -e "    ${RED}CAP_SYS_PTRACE${NC} - Can trace processes"
    echo -e "    ${RED}CAP_SETUID/CAP_SETGID${NC} - Can change UID/GID"
    echo ""
    echo -e "${YELLOW}[*] Research each binary with capabilities for known exploits${NC}"
    echo -e "${YELLOW}[*] Some capabilities can be combined for privilege escalation${NC}"
    echo ""
}

# Parallel execution support
run_parallel() {
    local -a funcs=("$@")
    local -a pids=()
    local -a temp_files=()
    
    print_info "Starting parallel execution of ${#funcs[@]} modules..."
    
    # Start each function in background, redirecting output to a specific temp file
    for i in "${!funcs[@]}"; do
        local func="${funcs[$i]}"
        local temp_file="$CACHE_DIR/${func}_output.tmp"
        temp_files+=("$temp_file")
        
        # We wrap the function call to redirect stdout/stderr to the temp file
        {
            $func
        } > "$temp_file" 2>&1 &
        
        pids+=($!)
        print_info "Started $func (PID: $!)"
    done
    
    # Wait for all background jobs
    for pid in "${pids[@]}"; do
        wait "$pid" 2>/dev/null || true
    done
    
    print_success "All modules completed. Aggregating results..."
    echo ""
    
    # Display results sequentially
    for i in "${!funcs[@]}"; do
        local func="${funcs[$i]}"
        local temp_file="${temp_files[$i]}"
        
        if [[ -f "$temp_file" ]]; then
            cat "$temp_file"
            # Optional: Add separator if needed, but functions usually handle their own headers
            # rm "$temp_file" # Cleanup happens at exit, or we can do it here
        else
            print_error "Output file for $func was lost or not created."
        fi
    done
}

# Main function
main() {
    local -a functions_to_run=()
    local parallel_mode=false
    
    # Check for parallel mode flag
    if [[ $# -gt 0 && "$1" == "--parallel" ]]; then
        parallel_mode=true
        shift
    fi
    
    # Only show banner if we have functions to run
    if [[ $# -eq 0 || $# -gt 0 ]]; then
        banner
    fi
    
    # Check if no arguments provided - run all enumerations
    if [ $# -eq 0 ]; then
        print_success "No options specified, running all enumeration modes..."
        echo ""
        
        functions_to_run=(
            "enum_suid"
            "enum_sudo" 
            "enum_creds"
            "enum_ports"
            "enum_groups"
            "enum_cron"
            "enum_cap"
        )
    else
        # Parse arguments - run only specified mode(s)
        while [[ $# -gt 0 ]]; do
            case $1 in
                -suid) functions_to_run+=("enum_suid"); shift ;;
                -suid-root) functions_to_run+=("enum_suid_root"); shift ;;
                -sudo) functions_to_run+=("enum_sudo"); shift ;;
                -creds) functions_to_run+=("enum_creds"); shift ;;
                -ports) functions_to_run+=("enum_ports"); shift ;;
                -live-proc)
                    if [ "$parallel_mode" = true ]; then
                         print_warning "Skipping -live-proc in parallel mode (interactive only)"
                    else
                         functions_to_run+=("enum_live_proc")
                    fi
                    shift 
                    ;;
                -groups) functions_to_run+=("enum_groups"); shift ;;
                -cron) functions_to_run+=("enum_cron"); shift ;;
                -cap) functions_to_run+=("enum_cap"); shift ;;
                -help|-h) show_help; exit 0 ;;
                --parallel) parallel_mode=true; shift ;;
                *)
                    print_error "Unknown option: $1"
                    show_help
                    exit 1
                    ;;
            esac
        done
    fi
    
    # Execute functions
    if [[ ${#functions_to_run[@]} -eq 0 ]]; then
        print_error "No functions to run"
        exit 1
    fi
    
    # Check if we should run in parallel
    if [[ "$parallel_mode" == true && ${#functions_to_run[@]} -gt 1 ]]; then
        # Filter out interactive functions just in case
        local -a safe_funcs=()
        for func in "${functions_to_run[@]}"; do
            if [[ "$func" != "enum_live_proc" ]]; then
                safe_funcs+=("$func")
            fi
        done
        run_parallel "${safe_funcs[@]}"
    else
        # Run sequentially
        for func in "${functions_to_run[@]}"; do
            $func
        done
    fi
    
    # Show completion message
    echo ""
    print_success "Enumeration completed"
    # echo -e "${YELLOW}[*] Results cached in: $CACHE_DIR${NC}"
}

# Run main function
main "$@"
