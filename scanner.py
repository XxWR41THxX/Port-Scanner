import threading
from queue import Queue
from IPy import IP
import socket
from tqdm import tqdm
from colorama import Fore, Style, init

# Color Codes
init(autoreset=True)
GREEN = Fore.GREEN
RED = Fore.RED
BLUE = Fore.LIGHTBLUE_EX
YELLOW = Fore.YELLOW
WHITE = Fore.WHITE
RESET = Style.RESET_ALL

banner = BLUE + 'Port Scanner by: WR41TH' + RESET

known_ports = [80, 443, 445, 21, 22, 23, 25, 53, 110, 123, 143, 161, 389, 993, 995, 1433, 3306, 3389, 3390, 5432, 5900, 8080]

queue = Queue()
open_ports = []
print_lock = threading.Lock()
threads = 200

def check_ip(target):
    try:
        ip = IP(target)
        return ip
    except ValueError:
        return socket.gethostbyname(target)

def portscan(port, target):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.5)
        sock.connect((target, port))
        return True
    except:
        return False

def connector(target, progressbar):
    while not queue.empty():
        port = queue.get()
        if portscan(port, target):
            with print_lock:
                print(GREEN + f"[+] Port {port} is open on {target}" + RESET)
                open_ports.append(port)
        else:
            with print_lock:
                print(RED + f"[-] Port {port} is closed on {target}" + RESET)
        queue.task_done()
        progressbar.update(1)

def run_scanner(target, ports):
    for port in ports:
        queue.put(port)

    progressbar = tqdm(total=len(ports), desc=GREEN + "Scanning Ports", unit='port', position=0, leave=False)

    for _ in range(threads):
        thread = threading.Thread(target=connector, args=(target, progressbar))
        thread.daemon = True
        thread.start()

    queue.join()
    progressbar.close()
    print(GREEN + f"[+] Scan on {target} is complete" + RESET)
    print(GREEN + "Open Ports: " + str(sorted(open_ports)) + RESET)

def main():
    print(GREEN + banner)
    target = input(BLUE + "Enter Target IP or Domain: " + RESET)
    ports_input = input(BLUE + "Enter Port Range or Ports to Scan (1-100): " + RESET)

    if ports_input:
        if "-" in ports_input:
            start_port, end_port = map(int, ports_input.split("-"))
            ports = range(start_port, end_port + 1)
        else:
            ports = [int(port) for port in ports_input.split(",")]
    else:
        ports = known_ports

    run_scanner(target, ports)

if __name__ == "__main__":
    main()
