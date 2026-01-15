# Priv-enum 🔍

A comprehensive Linux privilege escalation enumeration script that automates the discovery of potential security misconfigurations and vulnerabilities.

## Features

- **SUID Enumeration**: Find and analyze SUID binaries, with special focus on root-owned binaries
- **Sudo Rules**: Enumerate sudo permissions and identify binaries that can be run with sudo
- **Credentials Search**: Search for passwords, usernames, and API keys in files and shell history
- **Port Enumeration**: List all open ports and identify listening services
- **Live Process Monitoring**: Real-time process monitoring similar to pspy
- **Group Privileges**: Analyze group memberships and identify privileged groups
- **Cron Jobs**: Enumerate scheduled tasks and identify writable cron files
- **Linux Capabilities**: Find binaries with dangerous capabilities set

## Installation

```bash
git clone https://github.com/yourusername/Priv-enum.git
cd Priv-enum
chmod +x enum.sh
```

## Usage

### Run All Enumeration Modes

```bash
./enum.sh
```

This will run all enumeration modes automatically (except `-live-proc` which requires interactive mode).

### Run Specific Enumeration Mode

```bash
./enum.sh [OPTION]
```

### Available Options

| Flag | Description |
|------|-------------|
| `-suid` | Enumerate SUID binaries |
| `-suid-root` | Enumerate SUID binaries owned by root |
| `-sudo` | Enumerate sudo rules and allowed binaries |
| `-creds` | Search for credentials in files |
| `-ports` | List open ports and listening services |
| `-live-proc` | Monitor processes in real-time (like pspy) |
| `-groups` | List group privileges for current user |
| `-cron` | List cron jobs and scheduled tasks |
| `-cap` | List binaries with Linux capabilities |
| `-help`, `-h` | Show help message |

## Examples

```bash
# Run all enumeration modes
./enum.sh

# Enumerate only SUID binaries
./enum.sh -suid

# Check sudo permissions
./enum.sh -sudo

# Search for credentials
./enum.sh -creds

# Monitor live processes (Ctrl+C to stop)
./enum.sh -live-proc

# Combine multiple flags
./enum.sh -suid -sudo -groups
```

## Detailed Feature Descriptions

### SUID Enumeration (`-suid`)

Finds all SUID binaries on the system and highlights potentially vulnerable ones. Shows:
- File path
- Permissions
- Owner and group
- Vulnerability status

### Root-Owned SUID (`-suid-root`)

Filters SUID binaries to show only those owned by root, which are particularly interesting for privilege escalation.

### Sudo Rules (`-sudo`)

Enumerates sudo permissions by:
- Running `sudo -l` if possible
- Reading `/etc/sudoers` and `/etc/sudoers.d/*` files
- Highlighting NOPASSWD entries (no password required)
- Extracting allowed binaries and commands

### Credentials Search (`-creds`)

Searches for credentials in:
- Shell history files (`.bash_history`, `.zsh_history`, etc.)
- Text and log files
- Configuration files
- Common directories (`/home`, `/var/log`, `/tmp`, etc.)

Looks for:
- Passwords (`password=`, `passwd=`, `pwd=`)
- Usernames (`username=`, `user=`, `login=`)
- Database credentials (MySQL, PostgreSQL)
- API keys and tokens
- System users from `/etc/passwd`

### Port Enumeration (`-ports`)

Lists all listening ports and shows:
- Port number and protocol
- Listening address
- Process ID (PID)
- Process name and command
- Service identification for common ports

### Live Process Monitoring (`-live-proc`)

Monitors processes in real-time, similar to `pspy`:
- Uses `inotifywait` for efficient monitoring (if available)
- Falls back to polling method
- Shows new processes as they spawn
- Displays PID, PPID, user, command, executable path, and CWD
- Highlights root-owned processes

### Group Privileges (`-groups`)

Analyzes group memberships and identifies:
- All groups the current user belongs to
- Privileged groups (sudo, docker, lxd, etc.)
- SGID binaries owned by user's groups
- Primary group information
- Group-writable directories

### Cron Jobs (`-cron`)

Enumerates scheduled tasks from:
- User crontabs
- `/etc/crontab`
- `/etc/cron.d/`
- Periodic directories (`/etc/cron.hourly`, `/etc/cron.daily`, etc.)

Highlights:
- Writable cron files (critical for privilege escalation)
- Root-owned cron jobs
- File permissions and ownership

### Linux Capabilities (`-cap`)

Finds binaries with capabilities set and identifies dangerous capabilities:
- **CAP_DAC_OVERRIDE**: Bypass file permission checks
- **CAP_DAC_READ_SEARCH**: Bypass file read permission checks
- **CAP_SYS_ADMIN**: System administration operations
- **CAP_SYS_MODULE**: Load kernel modules
- **CAP_SYS_PTRACE**: Trace processes
- **CAP_SETUID/CAP_SETGID**: Change UID/GID
- And more...

## Requirements

The script works on most Linux systems. Some features may require additional tools:

- `ss` or `netstat` (for port enumeration)
- `lsof` (optional, for detailed port information)
- `getcap` (for capabilities enumeration, from `libcap2-bin` or `libcap-ng-utils`)
- `inotifywait` (optional, for efficient process monitoring, from `inotify-tools`)
- `crontab` (for cron enumeration)

The script will gracefully handle missing tools and provide fallback methods where possible.

## Output

The script uses color-coded output for easy identification:
- 🟢 **Green**: Normal findings
- 🟡 **Yellow**: Interesting findings
- 🔴 **Red**: Critical/dangerous findings

## Security Note

This tool is designed for:
- Security researchers
- Penetration testers
- System administrators auditing their systems
- CTF participants

**Only use this tool on systems you own or have explicit permission to test.**

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is open source and available under the MIT License.

## Disclaimer

This tool is for educational and authorized security testing purposes only. The authors are not responsible for any misuse or damage caused by this program.

## Acknowledgments

Inspired by tools like:
- LinPEAS
- LinEnum
- pspy
- And other privilege escalation enumeration tools

---

**Happy Hacking! 🚀**
