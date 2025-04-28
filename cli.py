import os
import json
import subprocess
import port_scanner
import tech_fingerprints
import vuln_detection
from subdomain_takeover import load_subdomains, load_cloud_service_patterns, detect_potential_takeovers, get_a_record, get_ip_info, is_orphaned

results = {}

def run_port_scanner():
    target = input("\nEnter target IP or domain for port scanning: ").strip()
    results['port_scanner'] = port_scanner.scan_target(target)
    print("[+] Port Scan results saved in memory!\n")
    post_scan_options()

def run_tech_fingerprints():
    url = input("\nEnter the URL to fingerprint: ").strip()
    results['tech_fingerprint'] = tech_fingerprints.detect_technologies(url)
    print("[+] Technology Fingerprint results saved in memory!\n")
    post_scan_options()

def run_vuln_detection():
    url = input("\nEnter the URL for vulnerability detection: ").strip()
    results['vuln_detection'] = vuln_detection.analyze_vulnerabilities(url)
    print("[+] Vulnerability Detection results saved in memory!\n")
    post_scan_options()


def run_subdomain_takeover():
    if not os.path.exists("subdomains.txt"):
        print("\n[!] 'subdomains.txt' not found!")
        print("[*] Please open a new terminal and run:")
        print("    python .\\Sublist3r\\sublist3r.py -d example.com -o subdomains.txt\n")
        input("[*] Press Enter after you've run the Sublist3r command...")
        
        # Check again
        if not os.path.exists("subdomains.txt"):
            print("\n[!] Still can't find 'subdomains.txt'. Please run Sublist3r correctly first.\n")
            return
        else:
            print("\n[+] 'subdomains.txt' found! Proceeding with Subdomain Takeover...\n")

    # Load subdomains and cloud patterns as required
    subdomains = load_subdomains()  # This function loads subdomains from the file
    cloud_patterns = load_cloud_service_patterns()  # This function loads cloud service patterns

    # Call the function to detect potential takeovers
    takeover_results = detect_potential_takeovers(subdomains, cloud_patterns)

    # Create a dictionary to store results
    results = {
        "subdomain_takeover": takeover_results
    }

    # Optionally save or display the results
    print(f"[+] {len(takeover_results)} potential takeover candidates identified.")
    print("[+] Subdomain Takeover results saved in memory!\n")

    post_scan_options()  # Call a function to show next options or return to main menu

def save_to_csv(data, filename):
    import csv
    with open(f"{filename}.csv", "w", newline='') as csvfile:
        writer = csv.writer(csvfile)
        for scan_type, scan_result in data.items():
            writer.writerow([scan_type, json.dumps(scan_result)])

def save_to_pdf(data, filename):
    from fpdf import FPDF
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Arial", size=12)
    for scan_type, scan_result in data.items():
        pdf.cell(200, 10, txt=scan_type.upper(), ln=True)
        pdf.multi_cell(0, 10, json.dumps(scan_result, indent=4))
        pdf.cell(200, 10, ln=True)
    pdf.output(f"{filename}.pdf")

def show_results():
    if not results:
        print("\n[!] No results to show yet.\n")
        return
    print("\n[+] Current Scan Results:\n")
    for scan_type, scan_data in results.items():
        print(f"=== {scan_type.upper()} ===")
        print(json.dumps(scan_data, indent=4))
        print("\n-------------------------------\n")

def save_results():
    if not results:
        print("\n[!] No results to save yet.\n")
        return

    save_format = input("Choose format to save (json/csv/pdf): ").lower()
    filename = input("Enter filename (without extension): ")

    if save_format == "json":
        with open(f"{filename}.json", "w") as f:
            json.dump(results, f, indent=4)
        print(f"[+] Results saved to {filename}.json\n")
    elif save_format == "csv":
        save_to_csv(results, filename)
        print(f"[+] Results saved to {filename}.csv\n")
    elif save_format == "pdf":
        save_to_pdf(results, filename)
        print(f"[+] Results saved to {filename}.pdf\n")
    else:
        print("[!] Invalid format. Please choose json, csv, or pdf.\n")

def post_scan_options():
    while True:
        print("\nWhat would you like to do next?")
        print("1. Run another scan")
        print("2. View current results")
        print("3. Save results")
        
        choice = input("Enter choice (1/2/3): ").strip()

        if choice == "1":
            main_menu()
            break
        elif choice == "2":
            show_results()
        elif choice == "3":
            save_results()
        else:
            print("[!] Invalid choice. Please choose 1, 2, or 3.\n")

def main_menu():
    print("\nSelect a scan to run:")
    print("1. Port Scanner")
    print("2. Technology Fingerprint")
    print("3. Vulnerability Detection")
    print("4. Subdomain Takeover")
    print("5. Exit")

    choice = input("Enter choice (1-5): ").strip()

    if choice == "1":
        run_port_scanner()
    elif choice == "2":
        run_tech_fingerprints()
    elif choice == "3":
        run_vuln_detection()
    elif choice == "4":
        run_subdomain_takeover()
    elif choice == "5":
        print("\n[+] Exiting. Goodbye!\n")
        exit()
    else:
        print("\n[!] Invalid choice. Please enter a number between 1-5.\n")
        main_menu()

def main():
    while True:
        main_menu()

if __name__ == "__main__":
    main()
