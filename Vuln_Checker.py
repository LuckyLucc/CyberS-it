import socket
import concurrent.futures
from colorama import init, Fore
import pyfiglet
import platform
import argparse

def initialize():
    init()  # Necessario per colorama su Windows
    if platform.system() == "Windows":
        socket.setdefaulttimeout(1)  # Timeout più corto per Windows

def scan_port(ip, port):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(1)
            if s.connect_ex((ip, port)) == 0:
                try:
                    service = socket.getservbyport(port, 'tcp')
                except:
                    service = "unknown"
                return port, service
    except:
        return None

def display_banner():
    banner = pyfiglet.figlet_format("PORT SCANNER", font="small")
    print(Fore.CYAN + banner)
    print(Fore.YELLOW + "="*60)
    print(Fore.WHITE + "Tool per il rilevamento delle porte aperte\n")

def main():
    initialize()
    display_banner()

    parser = argparse.ArgumentParser(description='Port Scanner')
    parser.add_argument('-t', '--target', help='Target IP address')
    parser.add_argument('-p', '--ports', type=int, nargs=2, 
                        metavar=('start', 'end'), default=[1, 1024],
                        help='Port range (default: 1-1024)')
    
    args = parser.parse_args()
    
    target = args.target if args.target else input(f"{Fore.GREEN}[?] Target IP: {Fore.WHITE}")
    start_port, end_port = args.ports
    ports = range(start_port, end_port + 1)

    print(f"\n{Fore.YELLOW}[*] Scanning {target} (ports {start_port}-{end_port})...\n")

    open_ports = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=100) as executor:
        results = executor.map(lambda p: scan_port(target, p), ports)
        
        for result in results:
            if result:
                port, service = result
                print(f"{Fore.GREEN}[+] Port {port:5} ({service}) is OPEN")
                open_ports.append(port)

    print(f"\n{Fore.YELLOW}[*] Scan completato!")
    print(f"{Fore.CYAN}[*] Porte aperte trovate: {', '.join(map(str, open_ports)) if open_ports else 'Nessuna'}")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{Fore.RED}[!] Scan interrotto dall'utente")
    except Exception as e:
        print(f"\n{Fore.RED}[!] Errore: {e}")
