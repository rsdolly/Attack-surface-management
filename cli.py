import os
import json
from datetime import datetime
import subprocess
import sys
import csv
from fpdf import FPDF

# Import scan functions (as before)
from port_scanner import scan_ports
from tech_fingerprints import detect_technologies
from vuln_detection import analyze_vulnerabilities
from subdomain_takeover import main as subdomain_takeover_main
from asset_discovery import asset_discovery

def run_port_scan(target):
    print(f"[+] Running port scan on {target}...")
    results = scan_ports(target)
    return {"scan_type": "port_scan", "target": target, "result": results}

def run_tech_fingerprint(url):
    print(f"[+] Running tech fingerprint on {url}...")
    results = detect_technologies(url)
    return {"scan_type": "tech_fingerprint", "target": url, "result": results}

def run_vulnerability_scan(url):
    print(f"[+] Running vulnerability scan on {url}...")
    results = analyze_vulnerabilities(url)
    return {"scan_type": "vulnerability_scan", "target": url, "result": results}

def run_subdomain_takeover_scan():
    print("[+] Running subdomain takeover scan...")
    # Subdomain takeover script's main function handles its own output
    # We'll capture its output and consider it the result
    try:
        process = subprocess.run([sys.executable, "subdomain_takeover.py"], capture_output=True, text=True, check=False)
        output = process.stdout
        return {"scan_type": "subdomain_takeover", "result": output}
    except Exception as e:
        return {"scan_type": "subdomain_takeover", "error": str(e)}

def run_asset_discovery_scan(target):
    print(f"[+] Running asset discovery scan on {target}...")
    results = asset_discovery(target)
    return {"scan_type": "asset_discovery", "target": target, "result": results}

def display_results(results):
    print("\n--- Scan Results ---")
    if results['scan_type'] == 'subdomain_takeover':
        print(results['result']) 
    else:
        print(json.dumps(results['result'], indent=4))
    print("--- End of Results ---")

def save_results(results, format="json"):
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"scan_results_{timestamp}"
    data = {results['scan_type']: results['result']}
    try:
        if format == "json":
            with open(f"{filename}.json", 'w') as f:
                json.dump(data, f, indent=4)
            print(f"[+] Results saved to {filename}.json in JSON format.")
        elif format == "csv":
            with open(f"{filename}.csv", "w", newline='') as csvfile:
                writer = csv.writer(csvfile)
                for scan_type, scan_result in data.items():
                    writer.writerow([scan_type, json.dumps(scan_result)])
            print(f"[+] Results saved to {filename}.csv in CSV format.")
        elif format == "pdf":
            pdf = FPDF()
            pdf.add_page()
            pdf.set_font("Arial", size=12)
            for scan_type, scan_result in data.items():
                pdf.cell(200, 10, txt=scan_type.upper(), ln=True)
                pdf.multi_cell(0, 10, json.dumps(scan_result, indent=4))
                pdf.cell(200, 10, ln=True)
            pdf.output(f"{filename}.pdf")
            print(f"[+] Results saved to {filename}.pdf in PDF format.")
        else:
            print("[!] Invalid save format.")
    except ImportError as e:
        if "fpdf" in str(e):
            print("[!] Error: fpdf library is required to save as PDF. Please install it using 'pip install fpdf'.")
        else:
            print(f"[!] Error during saving: {e}")
    except Exception as e:
        print(f"[!] Error saving results to {format}: {e}")

def main():
    scan_results = None

    while True:
        print("\n--- Choose a Scan ---")
        print("1. Port Scanner")
        print("2. Technology Fingerprinting")
        print("3. Vulnerability Detection")
        print("4. Subdomain Takeover")
        print("5. Asset Discovery")
        print("6. Exit")

        choice = input("Enter your choice (1-6): ").strip()

        if choice == '1':
            target = input("Enter target IP/domain or path to a .txt file: ").strip()
            scan_results = run_port_scan(target)
        elif choice == '2':
            url = input("Enter target URL: ").strip()
            scan_results = run_tech_fingerprint(url)
        elif choice == '3':
            url = input("Enter the URL to analyze: ").strip()
            scan_results = run_vulnerability_scan(url)
        elif choice == '4':
            if not os.path.exists("subdomains.txt"):
                print("[!] subdomains.txt not found. Please run the following command in another terminal:")
                print("python ./Sublist3r/sublist3r.py -d <target_domain> -o subdomains.txt")
                input("[+] Press Enter once subdomains.txt is created...")
                if os.path.exists("subdomains.txt"):
                    print("[+] Found subdomains.txt. Proceeding with subdomain takeover scan.")
                    scan_results = run_subdomain_takeover_scan()
                else:
                    print("[!] subdomains.txt still not found. Subdomain takeover scan aborted.")
                    scan_results = None
            else:
                print("[+] Found subdomains.txt. Proceeding with subdomain takeover scan.")
                scan_results = run_subdomain_takeover_scan()
        elif choice == '5':
            target = input("Enter the target URL or domain to scan: ").strip()
            scan_results = run_asset_discovery_scan(target)
        elif choice == '6':
            print("Exiting...")
            break
        else:
            print("Invalid choice. Please enter a number between 1 and 6.")
            continue

        if scan_results:
            while True:
                print("\n--- Scan Options ---")
                print("1. View Result")
                print("2. Save Result")
                print("3. Run Another Scan")
                print("4. Exit")

                option_choice = input("Enter your option (1-4): ").strip()

                if option_choice == '1':
                    display_results(scan_results)
                elif option_choice == '2':
                    save_format = input("Enter save format (json, csv, pdf): ").lower().strip()
                    save_results(scan_results, save_format)
                elif option_choice == '3':
                    break # Go back to the main menu
                elif option_choice == '4':
                    print("Exiting...")
                    return
                else:
                    print("Invalid choice. Please enter a number between 1 and 4.")
        else:
            print("[!] No scan results to process.")

if __name__ == "__main__":
    main()