import socket
import concurrent.futures
from termcolor import colored

def scan_port(ip, port):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(1)
            if s.connect_ex((ip, port)) == 0:
                service = socket.getservbyport(port, 'tcp')
                print(colored(f"[+] Port {port} ({service}) is OPEN", 'green'))
    except:
        pass

def main():
    target = input("Target IP: ")
    ports = range(1, 1025)  # Standard ports (modificabile)
    
    print(f"\nScanning {target}...\n")
    with concurrent.futures.ThreadPoolExecutor(max_workers=100) as executor:
        executor.map(lambda p: scan_port(target, p), ports)

if __name__ == "__main__":
    main()