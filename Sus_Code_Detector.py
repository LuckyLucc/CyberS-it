import ctypes
import psutil

def detect_shellcode():
    for proc in psutil.process_iter(['pid', 'name']):
        try:
            mem_regions = proc.memory_maps()
            for region in mem_regions:
                if "rwx" in region.perms:  # Segmento con permessi sospetti
                    print(f"[!] Potenziale shellcode in PID {proc.pid} ({proc.name()})")
        except:
            continue

if __name__ == "__main__":
    detect_shellcode()