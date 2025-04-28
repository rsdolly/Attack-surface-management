import requests
import dns.resolver
import json
import os
from ipwhois import IPWhois

# Load cloud service patterns and error signatures from a JSON file
def load_cloud_service_patterns(file="cloud_services.json"):
    if not os.path.exists(file):
        print(f"[!] {file} not found.")
        return {}
    with open(file, 'r') as f:
        return json.load(f)

# Load subdomains from the file
def load_subdomains(file="subdomains.txt"):
    if not os.path.exists(file):
        print(f"[!] {file} not found.")
        return []
    with open(file, "r") as f:
        return [line.strip() for line in f.readlines()]

# Resolve CNAME for a subdomain
def get_cname(subdomain):
    try:
        answers = dns.resolver.resolve(subdomain, 'CNAME')
        for rdata in answers:
            cname = str(rdata.target).rstrip('.')
            # Ignore self-referencing CNAMEs
            if cname == subdomain:
                return None
            return cname
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers, dns.exception.Timeout):
        return None

def get_a_record(subdomain):
    try:
        answers = dns.resolver.resolve(subdomain, 'A')
        return [rdata.to_text() for rdata in answers]
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers, dns.exception.Timeout):
        return []
    
# Check for potential takeover by matching the signature
def is_orphaned(subdomain, signatures):
    try:
        url = f"http://{subdomain}"
        response = requests.get(url, timeout=5)
        content = response.text
        for signature in signatures:
            if signature.lower() in content.lower():
                return True
    except requests.exceptions.RequestException:
        pass
    return False

def get_ip_info(ip):
    try:
        ipwhois = IPWhois(ip)
        result = ipwhois.lookup_rdap()
        return result.get("network", {}).get("name", "Unknown")
    except Exception as e:
        print(f"[!] Error looking up IP {ip}: {e}")
        return None
    
# Detect subdomain takeovers by matching CNAME and cloud service patterns
def detect_potential_takeovers(subdomains, cloud_patterns):
    results = []
    for sub in subdomains:
        cname = get_cname(sub)
        if cname:
            for service, info in cloud_patterns.items():
                pattern = info["pattern"]
                signatures = info["error_signatures"]
                if pattern in cname:
                    is_vulnerable = is_orphaned(sub, signatures)
                    if is_vulnerable:
                        print(f"[!!!] ALERT: Orphaned Subdomain Found → {sub} [{service}]")
                    results.append({
                        "subdomain": sub,
                        "cname": cname,
                        "matched_cloud_service": service,
                        "orphaned": is_vulnerable
                    })

        # If no CNAME, check A records
        if not cname:
            a_records = get_a_record(sub)
            if a_records:
                for ip in a_records:
                    print(f"Checking IP: {ip} for subdomain {sub}")  # Debug line
                    ip_info = get_ip_info(ip)
                    if ip_info:
                        for service, info in cloud_patterns.items():
                            if ip_info.lower() in info.get("ip_patterns", []):
                                is_vulnerable = is_orphaned(sub, info["error_signatures"])
                                if is_vulnerable:
                                    print(f"[!!!] ALERT: Orphaned Subdomain Found → {sub} [{service}]")
                                results.append({
                                    "subdomain": sub,
                                    "a_record": ip,
                                    "matched_cloud_service": service,
                                    "orphaned": is_vulnerable
                                })

    return results

# === MAIN EXECUTION ===
if __name__ == "__main__":
    # Load cloud service patterns from the JSON file
    cloud_patterns = load_cloud_service_patterns()

    if not cloud_patterns:
        print("[!] No cloud service patterns loaded.")
        exit()

    # Load subdomains from file
    subdomains = load_subdomains()

    if not subdomains:
        print("[!] No subdomains to check.")
        exit()

    # Print how many subdomains are being processed
    print(f"[+] {len(subdomains)} subdomains found. Checking for potential takeovers...")

    # Detect potential takeovers
    takeovers = detect_potential_takeovers(subdomains, cloud_patterns)

    # Print how many takeovers were detected
    print(f"[+] {len(takeovers)} potential takeover candidates identified.")

    print("[+] Script execution completed.")
