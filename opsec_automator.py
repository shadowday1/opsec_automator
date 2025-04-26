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

# Color codes
RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
BLUE = "\033[94m"
PURPLE = "\033[95m"
CYAN = "\033[96m"
RESET = "\033[0m"

class OpSecAutomator:
    def __init__(self):
        self.system_info = {
            'os': platform.system(),
            'distro': platform.linux_distribution()[0] if platform.system() == 'Linux' else None,
            'hostname': socket.gethostname()
        }
        self.checksum_file = "/var/log/opsec_checksums.log"
        self.tor_check_url = "https://check.torproject.org/api/ip"
        
    def run_cmd(self, cmd, sudo=False, capture=False):
        """Execute command with error handling"""
        try:
            if sudo:
                cmd = f"sudo {cmd}"
            result = subprocess.run(
                cmd, shell=True, check=True,
                stdout=subprocess.PIPE if capture else None,
                stderr=subprocess.PIPE if capture else None
            )
            return True, result.stdout.decode().strip() if capture else ""
        except subprocess.CalledProcessError as e:
            return False, e.stderr.decode().strip() if capture else ""

    def print_step(self, step, message):
        """Print formatted step message"""
        print(f"\n{PURPLE}==[{step}]== {RESET}{CYAN}{message}{RESET}")

    def print_status(self, success, message):
        """Print status with colors"""
        status = "✓" if success else "✗"
        color = GREEN if success else RED
        print(f"  {color}{status}{RESET} {message}")

    # --- Initial Setup Functions ---
    def initial_hardening(self):
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
    
    def setup_networking(self):
        """Network security configuration"""
        cmds = [
            ('echo "net.ipv6.conf.all.disable_ipv6=1" | sudo tee -a /etc/sysctl.conf', True),
            ('sysctl -p', True),
            ('apt install -y macchanger dnscrypt-proxy tor torsocks', True),
            ('systemctl enable --now dnscrypt-proxy', True),
            ('systemctl enable --now tor', True)
        ]
        
        for cmd, sudo in cmds:
            success, _ = self.run_cmd(cmd, sudo)
            self.print_status(success, cmd.split('|')[0].strip() if '|' in cmd else cmd)
    
    # ... (other initial setup functions from previous script)

    # --- Daily OpSec Functions ---
    def daily_opsec(self):
        """Routine daily security checks"""
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
    
    def network_checks(self):
        """Verify network security"""
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

    def system_checks(self):
        """System security verification"""
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

    def log_cleanup(self):
        """Secure log cleaning"""
        tools = [
            'bleachbit -c system.cache system.tmp system.trash',
            'journalctl --vacuum-time=1h',
            'find /tmp /var/tmp -type f -atime +1 -delete'
        ]
        
        for tool in tools:
            success, _ = self.run_cmd(tool, True)
            self.print_status(success, tool.split()[0])
    
    def integrity_check(self):
        """File integrity monitoring"""
        critical_files = [
            "/etc/passwd", "/etc/shadow", "/etc/sudoers",
            "/etc/ssh/sshd_config", "/etc/hosts"
        ]
        
        if not os.path.exists(self.checksum_file):
            with open(self.checksum_file, 'w') as f:
                for file in critical_files:
                    if os.path.exists(file):
                        with open(file, 'rb') as target:
                            f.write(f"{file}:{hashlib.sha256(target.read()).hexdigest()}\n")
            self.print_status(True, "Created new baseline checksums")
            return
        
        alerts = 0
        with open(self.checksum_file, 'r') as f:
            baselines = dict(line.strip().split(':') for line in f if ':' in line)
        
        for file in critical_files:
            if not os.path.exists(file):
                continue
                
            with open(file, 'rb') as target:
                current_hash = hashlib.sha256(target.read()).hexdigest()
                
            if file in baselines:
                if baselines[file] != current_hash:
                    self.print_status(False, f"ALERT: {file} modified!")
                    alerts += 1
                else:
                    self.print_status(True, f"{file} verified")
        
        if alerts > 0:
            self.print_step("ALERT", f"{alerts} critical files modified since baseline!")

    def secure_backup(self):
        """Encrypted backup routine"""
        backup_dirs = ["/etc", "~/.ssh", "~/Documents"]
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_file = f"/media/encrypted/backup_{timestamp}.tar.gpg"
        
        if not os.path.exists("/media/encrypted"):
            self.print_status(False, "Encrypted volume not mounted")
            return
            
        self.print_step("BACKUP", f"Creating encrypted backup to {backup_file}")
        
        # Create encrypted backup
        tar_cmd = f"tar czpf - {' '.join(backup_dirs)} | gpg -c --cipher-algo AES256 -o {backup_file}"
        success, _ = self.run_cmd(tar_cmd, True)
        self.print_status(success, "Backup completed")

    # --- Menu System ---
    def show_menu(self):
        """Interactive menu system"""
        while True:
            print(f"\n{BLUE}=== OpSec Automation Menu ===")
            print(f"{GREEN}1{RESET} - Initial System Hardening")
            print(f"{GREEN}2{RESET} - Daily OpSec Routine")
            print(f"{GREEN}3{RESET} - Network Security Check")
            print(f"{GREEN}4{RESET} - System Integrity Audit")
            print(f"{GREEN}5{RESET} - Emergency Cleanup")
            print(f"{RED}0{RESET} - Exit")
            
            choice = input("\nSelect option: ")
            
            if choice == "1":
                self.initial_hardening()
            elif choice == "2":
                self.daily_opsec()
            elif choice == "3":
                self.network_checks()
            elif choice == "4":
                self.integrity_check()
            elif choice == "5":
                self.emergency_cleanup()
            elif choice == "0":
                break
            else:
                print(f"{RED}Invalid choice{RESET}")

    def emergency_cleanup(self):
        """Nuclear option for sensitive situations"""
        print(f"\n{RED}=== EMERGENCY CLEANUP ===")
        print(f"{YELLOW}This will:{RESET}")
        print("- Shred sensitive files")
        print("- Clear RAM")
        print("- Power off immediately")
        
        confirm = input(f"\n{RED}CONFIRM EMERGENCY CLEANUP? (type 'ERASE'): {RESET}")
        if confirm == "ERASE":
            self.run_cmd("bleachbit -c system.cache system.tmp system.trash memory", True)
            self.run_cmd("sync && echo 3 > /proc/sys/vm/drop_caches", True)
            self.run_cmd("poweroff", True)

if __name__ == "__main__":
    if os.geteuid() != 0:
        print(f"{RED}Error: Must be run as root{RESET}")
        sys.exit(1)
        
    automator = OpSecAutomator()
    automator.show_menu()