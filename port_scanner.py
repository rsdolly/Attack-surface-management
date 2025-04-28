import nmap
import json
import socket
import os
from datetime import datetime

os.environ["PATH"] += os.pathsep + r"C:\Program Files (x86)\Nmap"

def scan_target(target, nmap_args='-sV -T4'):
    scanner = nmap.PortScanner()

    try:
        print(f"\n[+] Scanning {target} with arguments: {nmap_args}")
        scanner.scan(hosts=target, arguments=nmap_args)

        if not scanner.all_hosts():
            print("[-] No host found or Nmap scan failed.")
            return None

        results = {
            "target": target,
            "scan_time": str(datetime.now()),
            "nmap_args": nmap_args,
            "open_ports": []
        }

        for host in scanner.all_hosts():
            print(f"\n[+] Host: {host} ({scanner[host].hostname()})")
            print(f"[+] State: {scanner[host].state()}")

            for proto in scanner[host].all_protocols():
                ports = scanner[host][proto].keys()
                for port in sorted(ports):
                    service = scanner[host][proto][port]
                    port_info = {
                        "port": port,
                        "state": service['state'],
                        "name": service['name'],
                        "product": service.get('product', ''),
                        "version": service.get('version', ''),
                        "extrainfo": service.get('extrainfo', ''),
                        "cpe": service.get('cpe', '')
                    }
                    results["open_ports"].append(port_info)
                    print(f" - Port {port}/{proto} is {service['state']} -> {service['name']} {service.get('product','')} {service.get('version','')}")

        return results

    except Exception as e:
        print(f"[!] Error scanning {target}: {e}")
        return None

def scan_ports(url, ports_arg=None):
    try:
        target = url.replace("https://", "").replace("http://", "").strip("/")
        nmap_args = '-sV -T4'

        if ports_arg:
            nmap_args += f' -p {ports_arg}'

        result = scan_target(target, nmap_args)

        if result:
            return result
        else:
            return {"error": "Nmap scan failed or no host found."}

    except Exception as e:
        return {"error": str(e)}

def save_results(result, filename="scan_results.json"):
    try:
        with open(filename, 'w') as f:
            json.dump(result, f, indent=4)
        print(f"\n[+] Scan results saved to {filename}")
    except Exception as e:
        print(f"[!] Failed to save results: {e}")

if __name__ == "__main__":
    target_input = input("Enter a single IP/domain or path to a .txt file with targets: ").strip()
    enable_scripts = input("Enable Nmap default scripts (-sC)? (y/n): ").strip().lower() == 'y'

    nmap_args = '-sV -T4'
    if enable_scripts:
        nmap_args += ' -sC'

    targets = []

    if os.path.isfile(target_input):
        with open(target_input, 'r') as f:
            targets = [line.strip() for line in f if line.strip()]
    else:
        try:
            socket.gethostbyname(target_input)
            targets = [target_input]
        except socket.gaierror:
            print("[-] Invalid IP/domain or file.")
            exit()

    all_results = []

    for target in targets:
        result = scan_target(target, nmap_args)
        if result:
            all_results.append(result)

    if all_results:
        save_results(all_results)