import importlib
import os
import pyfiglet
import json

BANNER = pyfiglet.figlet_format("ASM")

SCANNERS = [
    ("Asset Discovery", "asset_discovery"),
    ("Port & Service Scanner", "port_scanner"),
    ("Technology Fingerprinting", "tech_fingerprints"),
    ("Vulnerability Detection", "vuln_detection"),
    ("Subdomain Takeover Detection", "subdomain_takeover"),
]

RESULTS = []

def run_scanner(choice):
    try:
        module_name = SCANNERS[choice][1]
        module = importlib.import_module(module_name)
        print(f"\n[+] Running {SCANNERS[choice][0]}...\n")
        result = module.main()
        RESULTS.append({
            "scanner": SCANNERS[choice][0],
            "output": result if result else "No output"
})
        # module.main()
        # RESULTS.append({
        #     "scanner": SCANNERS[choice][0],
        #     "output": "See console for full output"
        # })
    except Exception as e:
        print(f"[!] Error running scanner: {e}")

def save_to_json(filename):
    mode = 'a' if os.path.exists(filename) else 'w'
    if mode == 'a':
        print(f"\n[!] JSON file '{filename}' exists. Appending scan results...")
        with open(filename, 'r+', encoding='utf-8') as f:
            try:
                existing = json.load(f)
                if isinstance(existing, list):
                    existing.extend(RESULTS)
                else:
                    existing = [existing] + RESULTS
            except json.JSONDecodeError:
                existing = RESULTS
            f.seek(0)
            f.truncate()
            json.dump(existing, f, indent=4)
    else:
        print(f"\n[+] Creating new JSON report '{filename}'...")
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(RESULTS, f, indent=4)

    print("[+] Report saved successfully.")

def main():
    print(BANNER)
    
    while True:
        print("\nAvailable Scanners:")
        for i, (name, _) in enumerate(SCANNERS, start=1):
            print(f"{i}. {name}")
        
        choice = input("\nEnter scanner number to run (or 'q' to quit): ").strip().lower()
        
        if choice == 'q':
            break
        
        if choice.isdigit() and 1 <= int(choice) <= len(SCANNERS):
            run_scanner(int(choice) - 1)
        else:
            print("[!] Invalid input. Try again.")
            continue

        next_action = input("\nDo you want to run another scan? (y/n) or save to JSON (s): ").strip().lower()
        
        if next_action == 'y':
            continue
        elif next_action == 's':
            filename = input("Enter JSON filename (with .json extension): ").strip()
            if not filename.endswith(".json"):
                filename += ".json"
            save_to_json(filename)
        else:
            continue  # Show menu again instead of exiting

    print("\n[+] Exiting ASM CLI. Stay secure!")

if __name__ == "__main__":
    main()
