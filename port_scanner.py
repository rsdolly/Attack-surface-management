import subprocess
import re
import os
import platform

def is_valid_target(target):
    ip_regex = r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$"
    domain_regex = r"^(?!-)[A-Za-z0-9.-]+(?<!-)$"
    return re.match(ip_regex, target) or re.match(domain_regex, target)

def is_safe_script_name(script):
    return re.match(r"^[a-zA-Z0-9_,.-]+$", script)

def run_nmap_with_script(target, script):
    if not is_safe_script_name(script):
        print("[!] Invalid script name.")
        return
    try:
        print(f"\n[+] Running: nmap -sV --script {script} -T5 {target}\n")
        subprocess.run(["nmap", "-sV", f"--script={script}", "-T5", target], check=True)
    except subprocess.CalledProcessError as e:
        print(f"[!] Nmap scan failed: {e}")

def get_nmap_scripts_path():
    possible_paths = []

    if platform.system() == "Windows":
        possible_paths = [
            r"C:\Program Files (x86)\Nmap\scripts",
            r"C:\Program Files\Nmap\scripts"
        ]
    else:
        possible_paths = [
            "/usr/share/nmap/scripts",
            "/usr/local/share/nmap/scripts"
        ]

    for path in possible_paths:
        if os.path.isdir(path):
            return path
    return None

def search_nmap_scripts(keyword):
    script_path = get_nmap_scripts_path()
    if not script_path:
        print("[!] Could not find Nmap scripts directory.")
        return {}

    scripts = [f for f in os.listdir(script_path) if keyword.lower() in f.lower() and f.endswith(".nse")]

    if not scripts:
        print("[!] No matching scripts found.")
        return {}

    print("\n[+] Matching Nmap Scripts:")
    script_dict = {}
    for i, script in enumerate(scripts):
        print(f"  {i}: {script}")
        script_dict[str(i)] = script
    return script_dict

def main():
    target = input("Enter target domain or IP: ").strip()
    if not target or not is_valid_target(target):
        print("[!] Invalid target.")
        return

    script_choice = input("\nEnter script category (e.g., vuln, default) or press Enter for default: ").strip().lower()
    script_choice = script_choice if script_choice else "default"
    run_nmap_with_script(target, script_choice)

    while True:
        next_step = input("\nWould you like to search for any script? Type keyword or press Enter to exit: ").strip()
        if not next_step:
            break

        found = search_nmap_scripts(next_step)
        if found:
            run_choice = input("\nType 'run <serial>' to run that script, or press Enter to cancel: ").strip()
            if run_choice.startswith("run "):
                parts = run_choice.split()
                if len(parts) == 2 and parts[1] in found:
                    script_name = found[parts[1]]
                    run_nmap_with_script(target, script_name)
                else:
                    print("[!] Invalid serial number.")

if __name__ == "__main__":
    main()