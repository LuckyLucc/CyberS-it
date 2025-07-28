#!/usr/bin/env python3
"""
Ethical Pentesting Toolkit - Simple & User Friendly
Author: [Your Name]
Date: [Current Date]
License: For educational and authorized testing only
"""

import os
import sys
import socket
import platform
import subprocess
import time
import hashlib
import threading
from datetime import datetime

# ================= CONFIGURATION =================
DEFAULT_SCAN_PORTS = "21,22,80,443,3389"  # Common ports to scan
MAX_THREADS = 50  # For port scanning
# ================================================

def clear_screen():
    """Clear the terminal screen"""
    os.system('cls' if platform.system() == 'Windows' else 'clear')

def print_banner():
    """Display the tool banner"""
    clear_screen()
    print("""
    \033[94m╔════════════════════════════════════════════╗
    ║                                            ║
    ║         ETHICAL PENTESTING TOOLKIT         ║
    ║         Simple & User Friendly Edition     ║
    ║                                            ║
    ╚════════════════════════════════════════════╝
    \033[0m""")

def get_user_choice():
    """Display menu and get user choice"""
    print("\n\033[93mMain Menu:\033[0m")
    print("1. Network Scanner")
    print("2. Port Scanner")
    print("3. System Information")
    print("4. Password Hash Generator")
    print("5. Basic Vulnerability Check")
    print("6. Exit")
    
    while True:
        try:
            choice = int(input("\n\033[92mSelect an option (1-6): \033[0m"))
            if 1 <= choice <= 6:
                return choice
            print("Please enter a number between 1 and 6")
        except ValueError:
            print("Invalid input. Please enter a number.")

def network_scanner():
    """Simple network scanner using ping - Windows/Linux compatible"""
    print("\n\033[93mNetwork Scanner\033[0m")
    network = input("Enter network to scan (e.g., 192.168.1.0/24 or 192.168.1.1-100): ")
    
    try:
        if '/' in network:
            # CIDR notation (Linux style)
            base_ip = network.split('/')[0]
            print(f"\nScanning network {network}...")
            base_parts = base_ip.split('.')[:3]
            base_ip = '.'.join(base_parts)
            
            for i in range(1, 255):
                ip = f"{base_ip}.{i}"
                if platform.system() == 'Windows':
                    response = os.system(f"ping -n 1 -w 100 {ip} > nul")
                else:
                    response = os.system(f"ping -c 1 -w 1 {ip} > /dev/null 2>&1")
                if response == 0:
                    print(f"\033[92m[+] {ip} is up\033[0m")
                    
        elif '-' in network:
            # IP range
            base_ip = network.split('-')[0]
            end = int(network.split('-')[1])
            base_parts = base_ip.split('.')[:3]
            base_ip = '.'.join(base_parts)
            start = int(base_ip.split('.')[-1])
            
            print(f"\nScanning IPs {base_ip}.{start} to {base_ip}.{end}...")
            for i in range(start, end + 1):
                ip = f"{base_ip}.{i}"
                if platform.system() == 'Windows':
                    response = os.system(f"ping -n 1 -w 100 {ip} > nul")
                else:
                    response = os.system(f"ping -c 1 -w 1 {ip} > /dev/null 2>&1")
                if response == 0:
                    print(f"\033[92m[+] {ip} is up\033[0m")
        else:
            print("\nPlease use either CIDR notation (e.g., 192.168.1.0/24) or IP range (e.g., 192.168.1.1-100)")
    
    except Exception as e:
        print(f"\033[91mError during scanning: {e}\033[0m")
def port_scanner():
    """Multi-threaded port scanner"""
    print("\n\033[93mPort Scanner\033[0m")
    target = input("Enter target IP or hostname: ")
    ports_input = input(f"Enter ports to scan (comma separated, default: {DEFAULT_SCAN_PORTS}): ")
    
    ports = ports_input if ports_input else DEFAULT_SCAN_PORTS
    ports = [int(p.strip()) for p in ports.split(',')]
    
    print(f"\nScanning {target} on ports: {', '.join(map(str, ports))}")
    print("This may take a moment...\n")
    
    open_ports = []
    lock = threading.Lock()
    
    def scan_port(port):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(1)
                result = s.connect_ex((target, port))
                if result == 0:
                    with lock:
                        open_ports.append(port)
                        print(f"\033[92m[+] Port {port} is open\033[0m")
        except:
            pass
    
    threads = []
    for port in ports:
        thread = threading.Thread(target=scan_port, args=(port,))
        threads.append(thread)
        thread.start()
        
        # Limit number of concurrent threads
        while threading.active_count() > MAX_THREADS:
            time.sleep(0.1)
    
    for thread in threads:
        thread.join()
    
    if not open_ports:
        print("\033[91m[-] No open ports found\033[0m")
    else:
        print(f"\n\033[92mOpen ports on {target}: {', '.join(map(str, sorted(open_ports)))}\033[0m")

def system_info():
    """Display system information"""
    print("\n\033[93mSystem Information\033[0m")
    
    try:
        # Basic system info
        print("\n\033[96mBasic Information:\033[0m")
        print(f"System: {platform.system()} {platform.release()}")
        print(f"Node Name: {platform.node()}")
        print(f"Version: {platform.version()}")
        print(f"Machine: {platform.machine()}")
        print(f"Processor: {platform.processor()}")
        
        # Network info
        print("\n\033[96mNetwork Information:\033[0m")
        hostname = socket.gethostname()
        print(f"Hostname: {hostname}")
        try:
            ip = socket.gethostbyname(hostname)
            print(f"IP Address: {ip}")
        except:
            print("IP Address: Could not determine")
        
        # Disk info
        print("\n\033[96mDisk Information:\033[0m")
        if platform.system() == 'Windows':
            import ctypes
            drives = []
            bitmask = ctypes.windll.kernel32.GetLogicalDrives()
            for letter in 'ABCDEFGHIJKLMNOPQRSTUVWXYZ':
                if bitmask & 1:
                    drives.append(letter)
                bitmask >>= 1
            
            for drive in drives:
                try:
                    free_bytes = ctypes.c_ulonglong(0)
                    total_bytes = ctypes.c_ulonglong(0)
                    ctypes.windll.kernel32.GetDiskFreeSpaceExW(
                        f"{drive}:\\", None, ctypes.pointer(total_bytes), ctypes.pointer(free_bytes))
                    total_gb = total_bytes.value / (1024**3)
                    free_gb = free_bytes.value / (1024**3)
                    print(f"Drive {drive}: Total {total_gb:.2f} GB, Free {free_gb:.2f} GB")
                except:
                    pass
        else:
            stat = os.statvfs('/')
            total_gb = (stat.f_blocks * stat.f_frsize) / (1024**3)
            free_gb = (stat.f_bfree * stat.f_frsize) / (1024**3)
            print(f"Root FS: Total {total_gb:.2f} GB, Free {free_gb:.2f} GB")
    
    except Exception as e:
        print(f"\033[91mError gathering system info: {e}\033[0m")

def password_hash_generator():
    """Generate password hashes"""
    print("\n\033[93mPassword Hash Generator\033[0m")
    password = input("Enter password to hash: ")
    
    if not password:
        print("\033[91mPlease enter a password\033[0m")
        return
    
    print("\n\033[96mGenerated Hashes:\033[0m")
    print(f"MD5:    {hashlib.md5(password.encode()).hexdigest()}")
    print(f"SHA1:   {hashlib.sha1(password.encode()).hexdigest()}")
    print(f"SHA256: {hashlib.sha256(password.encode()).hexdigest()}")
    print(f"SHA512: {hashlib.sha512(password.encode()).hexdigest()}")

def basic_vulnerability_check():
    """Basic system vulnerability check"""
    print("\n\033[93mBasic Vulnerability Check\033[0m")
    print("This will check for some common security issues on your system...\n")
    
    vulnerabilities_found = 0
    
    # Check 1: Outdated OS
    try:
        if platform.system() == 'Linux':
            last_update = subprocess.check_output("stat -c %Y /var/lib/apt/periodic/update-success-stamp", shell=True).decode().strip()
            last_update_date = datetime.fromtimestamp(int(last_update)).strftime('%Y-%m-%d')
            days_since_update = (datetime.now() - datetime.fromtimestamp(int(last_update))).days
            
            print(f"Last system update: {last_update_date} ({days_since_update} days ago)")
            if days_since_update > 30:
                print("\033[91m[!] WARNING: System updates are more than 30 days old\033[0m")
                vulnerabilities_found += 1
    except:
        pass
    
    # Check 2: Open ports on localhost
    print("\nChecking for open ports on localhost...")
    common_risky_ports = [21, 22, 23, 80, 443, 3389, 5900, 8080]
    open_ports = []
    
    def check_local_port(port):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(1)
                if s.connect_ex(('127.0.0.1', port)) == 0:
                    open_ports.append(port)
        except:
            pass
    
    threads = []
    for port in common_risky_ports:
        thread = threading.Thread(target=check_local_port, args=(port,))
        threads.append(thread)
        thread.start()
    
    for thread in threads:
        thread.join()
    
    if open_ports:
        print(f"\033[91m[!] WARNING: Open ports found: {', '.join(map(str, open_ports))}\033[0m")
        vulnerabilities_found += 1
    else:
        print("\033[92mNo risky open ports found on localhost\033[0m")
    
    # Check 3: World-writable files in home directory (Linux/Mac)
    if platform.system() in ['Linux', 'Darwin']:
        print("\nChecking for world-writable files in home directory...")
        try:
            result = subprocess.check_output("find ~ -perm -o+w -type f 2>/dev/null | wc -l", shell=True).decode().strip()
            if int(result) > 0:
                print(f"\033[91m[!] WARNING: {result} world-writable files found in home directory\033[0m")
                vulnerabilities_found += 1
            else:
                print("\033[92mNo world-writable files found in home directory\033[0m")
        except:
            pass
    
    # Summary
    print("\n\033[96mVulnerability Check Summary:\033[0m")
    if vulnerabilities_found == 0:
        print("\033[92mNo critical vulnerabilities found\033[0m")
    else:
        print(f"\033[91m[!] Found {vulnerabilities_found} potential security issues\033[0m")

def main():
    """Main program loop"""
    print_banner()
    
    while True:
        choice = get_user_choice()
        
        if choice == 1:
            network_scanner()
        elif choice == 2:
            port_scanner()
        elif choice == 3:
            system_info()
        elif choice == 4:
            password_hash_generator()
        elif choice == 5:
            basic_vulnerability_check()
        elif choice == 6:
            print("\n\033[94mThank you for using the Ethical Pentesting Toolkit!\033[0m")
            sys.exit(0)
        
        input("\nPress Enter to return to the main menu...")
        print_banner()

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\033[94m\nTool terminated by user. Goodbye!\033[0m")
        sys.exit(0)
