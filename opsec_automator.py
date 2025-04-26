#!/usr/bin/env python3
import os
import subprocess
import sys
import time
import hashlib
import random
import socket
import platform
from datetime import datetime
from getpass import getpass
from typing import Tuple, Dict, List, Optional, Union
from enum import Enum, auto
import json
import shutil
from pathlib import Path

# Modern color handling using a dataclass
class Colors:
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    PURPLE = "\033[95m"
    CYAN = "\033[96m"
    RESET = "\033[0m"
    
    @staticmethod
    def colorize(text: str, color: str) -> str:
        return f"{color}{text}{Colors.RESET}"

class SecurityLevel(Enum):
    NORMAL = auto()
    PARANOID = auto()
    LOCKDOWN = auto()

class OpSecAutomator:
    def __init__(self):
        self.system_info = self._get_system_info()
        self.checksum_file = Path("/var/log/opsec_checksums.log")
        self.tor_check_url = "https://check.torproject.org/api/ip"
        self.security_level = SecurityLevel.NORMAL
        self.vpn_rotation_interval = 3600  # 1 hour in seconds
        self.log_file = Path("/var/log/opsec_automator.log")
        
    def _get_system_info(self) -> Dict[str, Optional[str]]:
        """Get system information in a cross-platform way"""
        info: Dict[str, Optional[str]] = {
            'os': platform.system(),
            'hostname': socket.gethostname(),
            'distro': None
        }
        
        if info['os'] == "Linux":
            try:
                # Modern Linux distribution detection
                if hasattr(platform, 'freedesktop_os_release'):
                    os_release = platform.freedesktop_os_release()
                    info['distro'] = os_release.get('PRETTY_NAME', 'Unknown Linux')
                else:
                    # Fallback for older systems
                    with open('/etc/os-release') as f:
                        for line in f:
                            if line.startswith('PRETTY_NAME='):
                                info['distro'] = line.split('=')[1].strip().strip('"')
                                break
            except Exception:
                info['distro'] = "Unknown Linux"
                
        return info

    def _log_activity(self, message: str, level: str = "INFO") -> None:
        """Structured logging"""
        log_entry = {
            "timestamp": datetime.now().isoformat(),
            "level": level,
            "message": message,
            "security_level": self.security_level.name
        }
        with self.log_file.open('a') as f:
            f.write(json.dumps(log_entry) + "\n")

    def run_cmd(self, cmd: str, sudo: bool = False, capture: bool = False) -> Tuple[bool, str]:
        """Execute command with modern error handling"""
        try:
            if sudo and os.geteuid() != 0:
                cmd = f"sudo {cmd}"
                
            result = subprocess.run(
                cmd,
                shell=True,
                check=True,
                stdout=subprocess.PIPE if capture else None,
                stderr=subprocess.PIPE if capture else None,
                text=True,
                encoding='utf-8',
                errors='replace'
            )
            output = result.stdout.strip() if capture else ""
            self._log_activity(f"Command executed: {cmd}")
            return True, output
        except subprocess.CalledProcessError as e:
            error_msg = e.stderr.strip() if capture else str(e)
            self._log_activity(f"Command failed: {cmd} - {error_msg}", "ERROR")
            return False, error_msg
        except Exception as e:
            self._log_activity(f"Unexpected error: {str(e)}", "CRITICAL")
            return False, str(e)

    def print_step(self, step: str, message: str) -> None:
        """Modern formatted step message"""
        print(f"\n{Colors.PURPLE}==[{step}]== {Colors.RESET}{Colors.CYAN}{message}{Colors.RESET}")
        self._log_activity(f"Step: {step} - {message}")

    def print_status(self, success: bool, message: str) -> None:
        """Improved status printing"""
        status = "✓" if success else "✗"
        color = Colors.GREEN if success else Colors.RED
        print(f"  {color}{status}{Colors.RESET} {message}")
        self._log_activity(f"Status: {status} - {message}", 
                          "INFO" if success else "WARNING")

    def set_security_level(self, level: SecurityLevel) -> None:
        """Modern security level management"""
        self.print_step("SECURITY", f"Switching to {level.name} mode")
        
        operations = {
            SecurityLevel.NORMAL: {
                'enable': [
                    'ufw allow 22/tcp',          # SSH
                    'ufw allow 80,443/tcp',      # Web
                    'systemctl start bluetooth'
                ],
                'disable': []
            },
            SecurityLevel.PARANOID: {
                'enable': [
                    'iptables -A OUTPUT -p tcp --dport 22 -j DROP'
                ],
                'disable': [
                    'ufw delete allow 22/tcp',
                    'systemctl stop bluetooth'
                ]
            },
            SecurityLevel.LOCKDOWN: {
                'enable': [
                    'echo 1 > /proc/sys/kernel/sysrq',
                    'echo 1 > /proc/sys/kernel/core_pattern'
                ],
                'disable': [
                    'systemctl stop networking',
                    'rfkill block all'
                ]
            }
        }
        
        for cmd in operations[level]['disable']:
            self.run_cmd(cmd, sudo=True)
            
        for cmd in operations[level]['enable']:
            self.run_cmd(cmd, sudo=True)
            
        self.security_level = level
        self._log_activity(f"Security level changed to {level.name}", "INFO")

    def setup_networking(self) -> None:
        """Modern network configuration"""
        self.print_step("NETWORK", "Configuring network security")
        
        cmds = [
            ('sysctl -w net.ipv6.conf.all.disable_ipv6=1', True),
            ('sysctl -p', True),
            ('apt install -y macchanger dnscrypt-proxy tor torsocks', True),
            ('systemctl enable --now dnscrypt-proxy', True),
            ('systemctl enable --now tor', True),
            ('timedatectl set-ntp true', True)
        ]
        
        for cmd, sudo in cmds:
            success, _ = self.run_cmd(cmd, sudo)
            self.print_status(success, cmd.split('|')[0].strip() if '|' in cmd else cmd)

    def initial_hardening(self) -> None:
        """Complete system hardening routine"""
        self.print_step("INIT", "Beginning System Hardening")
        
        steps = [
            ("NET", self.setup_networking),
            ("PKG", self.install_security_tools),
            ("FIREWALL", self.configure_firewall),
            ("SSH", self.harden_ssh),
            ("ENCRYPT", self.setup_encryption),
            ("CLEAN", self.cleanup_system),
            ("AUDIT", self.create_baseline)
        ]
        
        for name, func in steps:
            self.print_step(name, f"Running {func.__name__.replace('_', ' ').title()}")
            func()

    def daily_opsec(self) -> None:
        """Modern daily security routine"""
        self.print_step("DAILY", "Starting Daily OpSec Routine")
        
        checks = [
            ("NET", self.network_checks),
            ("SYS", self.system_checks),
            ("CLEAN", self.log_cleanup),
            ("AUDIT", self.integrity_check),
            ("BACKUP", self.secure_backup)
        ]
        
        for name, func in checks:
            self.print_step(name, f"Running {func.__name__.replace('_', ' ').title()}")
            func()

    def network_checks(self) -> None:
        """Enhanced network verification"""
        checks = [
            ("IPv6 Status", 'sysctl net.ipv6.conf.all.disable_ipv6', "= 1"),
            ("DNS Leak Test", 'curl -s https://dnsleaktest.com | grep -A 5 "Your IP"', None),
            ("Tor Check", f'curl -s {self.tor_check_url}', "IsTor\":true"),
            ("VPN Status", 'ip a show tun0', "inet")
        ]
        
        for name, cmd, expect in checks:
            success, output = self.run_cmd(cmd, True, True)
            status = expect in output if expect else success
            self.print_status(status, f"{name}: {output[:50]}{'...' if len(output) > 50 else ''}")

    def system_checks(self) -> None:
        """Modern system verification"""
        checks = [
            ("Suspicious Processes", 'ps aux | grep -E "(nmap|metasploit|sqlmap|hydra)"', ""),
            ("Open Ports", 'ss -tulnp | grep -v "127.0.0.1"', ""),
            ("Rootkits", 'rkhunter --check --sk', "No rootkits found"),
            ("SUID Files", 'find / -perm -4000 -type f 2>/dev/null', "/usr/bin/sudo")
        ]
        
        for name, cmd, expect in checks:
            success, output = self.run_cmd(cmd, True, True)
            status = (expect not in output) if expect else success
            self.print_status(status, name)

    def log_cleanup(self) -> None:
        """Modern log management"""
        tools = [
            'bleachbit -c system.cache system.tmp system.trash',
            'journalctl --vacuum-time=1h',
            'find /tmp /var/tmp -type f -atime +1 -delete'
        ]
        
        for tool in tools:
            success, _ = self.run_cmd(tool, True)
            self.print_status(success, tool.split()[0])

    def integrity_check(self) -> None:
        """Modern file integrity monitoring"""
        critical_files = [
            "/etc/passwd", "/etc/shadow", "/etc/sudoers",
            "/etc/ssh/sshd_config", "/etc/hosts"
        ]
        
        if not self.checksum_file.exists():
            with self.checksum_file.open('w') as f:
                for file in critical_files:
                    file_path = Path(file)
                    if file_path.exists():
                        with file_path.open('rb') as target:
                            f.write(f"{file}:{hashlib.sha256(target.read()).hexdigest()}\n")
            self.print_status(True, "Created new baseline checksums")
            return
        
        alerts = 0
        with self.checksum_file.open('r') as f:
            baselines = dict(line.strip().split(':') for line in f if ':' in line)
        
        for file in critical_files:
            file_path = Path(file)
            if not file_path.exists():
                continue
                
            with file_path.open('rb') as target:
                current_hash = hashlib.sha256(target.read()).hexdigest()
                
            if file in baselines:
                if baselines[file] != current_hash:
                    self.print_status(False, f"ALERT: {file} modified!")
                    alerts += 1
                else:
                    self.print_status(True, f"{file} verified")
        
        if alerts > 0:
            self.print_step("ALERT", f"{alerts} critical files modified since baseline!")

    def secure_backup(self) -> None:
        """Modern encrypted backup"""
        backup_dirs = ["/etc", str(Path.home() / ".ssh"), str(Path.home() / "Documents")]
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_file = f"/media/encrypted/backup_{timestamp}.tar.gpg"
        
        if not Path("/media/encrypted").exists():
            self.print_status(False, "Encrypted volume not mounted")
            return
            
        self.print_step("BACKUP", f"Creating encrypted backup to {backup_file}")
        
        try:
            # Use pigz if available for parallel compression
            compress_cmd = "pigz" if shutil.which("pigz") else "gzip"
            
            tar_cmd = (
                f"tar cf - {' '.join(backup_dirs)} | "
                f"{compress_cmd} | "
                f"gpg -c --cipher-algo AES256 --batch --passphrase '' -o {backup_file}"
            )
            
            success, _ = self.run_cmd(tar_cmd, True)
            self.print_status(success, "Backup completed")
            
            if success:
                # Verify backup integrity
                verify_cmd = f"gpg --verify {backup_file}"
                self.run_cmd(verify_cmd, True)
        except Exception as e:
            self.print_status(False, f"Backup failed: {str(e)}")

    def emergency_cleanup(self) -> None:
        """Modern emergency procedure"""
        print(f"\n{Colors.RED}=== EMERGENCY CLEANUP ===")
        print(f"{Colors.YELLOW}This will:{Colors.RESET}")
        print("- Shred sensitive files")
        print("- Clear RAM")
        print("- Power off immediately")
        
        confirm = input(f"\n{Colors.RED}CONFIRM EMERGENCY CLEANUP? (type 'ERASE'): {Colors.RESET}")
        if confirm == "ERASE":
            try:
                # Modern secure deletion
                self.run_cmd("bleachbit -c system.cache system.tmp system.trash memory", True)
                
                # Secure memory wipe
                self.run_cmd("sync && echo 3 > /proc/sys/vm/drop_caches", True)
                
                # Hardware-based secure erase if available
                if Path("/sys/block/sda/device/scsi_disk").exists():
                    self.run_cmd("hdparm --security-erase-enhanced NULL /dev/sda", True)
                
                self.run_cmd("poweroff", True)
            except Exception as e:
                self.print_status(False, f"Cleanup failed: {str(e)}")
                sys.exit(1)

    def show_menu(self) -> None:
        """Modern interactive menu"""
        menu_options = {
            "1": ("Initial System Hardening", self.initial_hardening),
            "2": ("Daily OpSec Routine", self.daily_opsec),
            "3": ("Network Security Check", self.network_checks),
            "4": ("System Integrity Audit", self.integrity_check),
            "5": ("Emergency Cleanup", self.emergency_cleanup),
            "0": ("Exit", lambda: sys.exit(0))
        }
        
        while True:
            print(f"\n{Colors.BLUE}=== OpSec Automation Menu ===")
            for key, (desc, _) in menu_options.items():
                print(f"{Colors.GREEN}{key}{Colors.RESET} - {desc}")
            
            try:
                choice = input("\nSelect option: ").strip()
                if choice in menu_options:
                    _, action = menu_options[choice]
                    action()
                else:
                    print(f"{Colors.RED}Invalid choice{Colors.RESET}")
            except KeyboardInterrupt:
                print("\n[+] Returning to NORMAL mode before exit")
                self.set_security_level(SecurityLevel.NORMAL)
                break
            except Exception as e:
                print(f"{Colors.RED}Error: {str(e)}{Colors.RESET}")

def main() -> None:
    try:
        if os.geteuid() != 0:
            print(f"{Colors.RED}Error: Must be run as root{Colors.RESET}")
            sys.exit(1)
            
        automator = OpSecAutomator()
        automator.show_menu()
    except KeyboardInterrupt:
        print("\n[!] Operation cancelled by user")
        sys.exit(0)
    except Exception as e:
        print(f"{Colors.RED}Fatal error: {str(e)}{Colors.RESET}")
        sys.exit(1)

if __name__ == "__main__":
    main()
