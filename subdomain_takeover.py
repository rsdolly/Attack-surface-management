import dns.resolver
import requests
import json
import ipaddress
import os
import time

def wait_for_subdomain_file(file_path, timeout=120):
    print(f"\n[!] Please run the following command in your terminal:\n")
    print(f"    python ./sublist3r/sublist3r.py -d {domain} -o subdomains.txt\n")
    print("[*] Waiting for subdomains.txt to be created...")

    start_time = time.time()
    while time.time() - start_time < timeout:
        if os.path.exists(file_path) and os.path.getsize(file_path) > 0:
            print("[+] subdomains.txt found. Proceeding...")
            return True
        time.sleep(3)

    print("[!] Timeout reached. subdomains.txt was not created.")
    return False


def check_service(subdomain, service_config):
    """Checks if a subdomain points to an unclaimed cloud service."""
    try:
        resolver = dns.resolver.Resolver()
        answers = resolver.resolve(subdomain, 'CNAME')
        for rdata in answers:
            if service_config['pattern'] in str(rdata).lower():
                url = f"http://{subdomain}"
                try:
                    response = requests.get(url, timeout=5)
                    for error_signature in service_config['error_signatures']:
                        if error_signature in response.text:
                            return True, service_config['name']
                except requests.exceptions.RequestException:
                    pass
        try:
            answers = resolver.resolve(subdomain, 'A')
            for rdata in answers:
                ip_address = str(rdata)
                for ip_range in service_config.get('ip_patterns', []):
                    if ipaddress.ip_address(ip_address) in ipaddress.ip_network(ip_range):
                        return True, service_config['name']

        except dns.resolver.NXDOMAIN:
            pass
        except dns.resolver.NoAnswer:
            pass

    except dns.resolver.NXDOMAIN:
        pass
    except dns.resolver.NoAnswer:
        pass
    return False, None

def get_risk_impact(service):
    data = {
        "AWS S3": {
            "risk": "Unauthorized access to unclaimed S3 bucket.",
            "threat": "Malicious content hosting or sensitive data exposure.",
            "vulnerability": "Dangling S3 DNS pointer.",
            "impact": "Data breach, malware delivery.",
            "severity": "High"
        },
        "GitHub Pages": {
            "risk": "Phishing or impersonation via abandoned GitHub Pages.",
            "threat": "Credential theft, reputation damage.",
            "vulnerability": "Unlinked GitHub repo or deleted project.",
            "impact": "Loss of trust, brand misuse.",
            "severity": "Medium"
        },
        "Heroku": {
            "risk": "Hosting of untrusted apps via unlinked subdomain.",
            "threat": "Malicious apps, data leakage.",
            "vulnerability": "Orphaned Heroku app name.",
            "impact": "Brand damage, user targeting.",
            "severity": "Medium"
        },
        "Bitbucket": {
            "risk": "Public or misleading content hosted on subdomain.",
            "threat": "Reputation loss, misinformation.",
            "vulnerability": "Deleted Bitbucket Pages repo.",
            "impact": "Brand impersonation.",
            "severity": "Low"
        },
        "Shopify": {
            "risk": "Creation of malicious store on forgotten subdomain.",
            "threat": "Phishing, scam store setup.",
            "vulnerability": "Unregistered Shopify store DNS.",
            "impact": "Fraudulent sales, customer deception.",
            "severity": "High"
        },
        "Fastly": {
            "risk": "Attacker takes control over the CDN endpoint.",
            "threat": "Malware distribution, fake site hosting.",
            "vulnerability": "DNS points to unused Fastly service.",
            "impact": "Brand impersonation, MITM.",
            "severity": "High"
        },
        "Google Cloud Storage": {
            "risk": "Exposure or abuse of previous GCS bucket.",
            "threat": "Serving infected files, credential leaks.",
            "vulnerability": "Dangling Google Cloud Storage bucket.",
            "impact": "Data breach, SEO poisoning.",
            "severity": "High"
        },
        "Microsoft Azure": {
            "risk": "Abandoned subdomain points to Azure App Service.",
            "threat": "Malicious web app hosting.",
            "vulnerability": "Unclaimed Azure subdomain.",
            "impact": "Reputation and trust loss.",
            "severity": "Medium"
        },
        "Cloudflare": {
            "risk": "Attacker configures orphaned domain in their account.",
            "threat": "Phishing, spoofed content delivery.",
            "vulnerability": "DNS points to Cloudflare without claim.",
            "impact": "Fake site delivery via CDN.",
            "severity": "Medium"
        }
    }
    return data.get(service, {
        "risk": "Unknown",
        "threat": "Unknown",
        "vulnerability": "Unknown",
        "impact": "Unknown",
        "severity": "Unknown"
    })


def main():
    global domain
    domain = input("Enter the target domain: ").strip()
    output_file = 'subdomains.txt'

    if not wait_for_subdomain_file(output_file, timeout=180):
        return


    try:
        with open('cloud_services.json', 'r') as f:
            cloud_services = json.load(f)
    except FileNotFoundError:
        print("Error: cloud_services.json not found.")
        return
    except json.JSONDecodeError:
        print("Error: Invalid JSON format in cloud_services.json.")
        return

    try:
        with open(output_file, 'r') as f:
            subdomains = [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        print("Error: subdomains.txt not found.")
        return

    print("\nChecking for potential subdomain takeovers...\n")

    vulnerable_subdomains = {}
    for subdomain in subdomains:
        print(f"Checking {subdomain}...")
        vulnerable_services = []
        for service_name, service_config in cloud_services.items():
            service_config['name'] = service_name
            is_takeover, service = check_service(subdomain, service_config)
            if is_takeover:
                print(f"[POTENTIAL TAKEOVER] {subdomain} might be vulnerable to {service} takeover!")
                vulnerable_services.append(service)

        if vulnerable_services:
            vulnerable_subdomains[subdomain] = vulnerable_services
        else:
            print(f"{subdomain} does not appear vulnerable to known takeovers.")

    print("\nScan complete.\n")
    print("--- Summary of Potential Takeovers ---")

    if vulnerable_subdomains:
        print("{:<35} {:<15} {:<20} {:<30} {:<35} {:<10}".format(
            "Subdomain", "Severity", "Risk", "Threat", "Vulnerability", "Impact"))
        print("=" * 150)

        for subdomain, services in vulnerable_subdomains.items():
            for service in services:
                info = get_risk_impact(service)
                severity = info["severity"]

                # Color-coded severity
                if severity == "High":
                    color = "\033[91m"  # Red
                elif severity == "Medium":
                    color = "\033[93m"  # Yellow
                elif severity == "Low":
                    color = "\033[92m"  # Green
                else:
                    color = "\033[0m"  

                reset = "\033[0m"
                print(f"{subdomain:<35} {color}{severity:<15}{reset} {info['risk']:<20} {info['threat']:<30} {info['vulnerability']:<35} {info['impact']:<10}")
    else:
        print("No potential subdomain takeovers found.")

if __name__ == "__main__":
    main()