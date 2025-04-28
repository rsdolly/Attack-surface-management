import sys
import os
import requests
import json
import socket
from bs4 import BeautifulSoup
from dotenv import load_dotenv
import shodan
import subprocess
from urllib.parse import urlparse

# Load environment variables from .env
load_dotenv()

# Ensure Sublist3r and its submodules are importable
script_dir = os.path.dirname(__file__)
sublist3r_path = os.path.join(script_dir, 'Sublist3r', 'sublist3r.py')
subdomain_output_file = os.path.join(script_dir, 'subdomains.txt')

# Initialize Shodan client with API key
SHODAN_API_KEY = os.getenv("SHODAN_API_KEY")
if not SHODAN_API_KEY:
    print("[!] SHODAN_API_KEY not found in .env file. Shodan functionality will be limited.")
shodan_client = shodan.Shodan(SHODAN_API_KEY) if SHODAN_API_KEY else None

def get_domain_from_url(url):
    """Extracts the domain name from a URL."""
    parsed_url = urlparse(url)
    return parsed_url.netloc or parsed_url.path  # Handle cases where only domain is entered

def run_sublist3r(domain, output_file):
    """Runs Sublist3r to discover subdomains and saves them to the specified file."""
    print(f"[*] Discovering subdomains for {domain} using sublist3r.py...")
    try:
        command = [
            sys.executable,
            sublist3r_path,
            "-d",
            domain,
            "-o",
            output_file,
            "-silent"
        ]
        print(f"[DEBUG] Running command: {' '.join(command)}")
        subprocess.run(command, check=True, capture_output=True, text=True)
        print(f"[+] Subdomains saved to: {output_file}")
        return True
    except subprocess.CalledProcessError as e:
        print(f"[!] Error running sublist3r.py: {e}")
        print(f"[!] Stderr: {e.stderr}")
        return False
    except FileNotFoundError:
        print(f"[!] Error: sublist3r.py not found at {sublist3r_path}")
        return False
    except Exception as e:
        print(f"[!] An unexpected error occurred during subdomain discovery: {e}")
        return False

def discover_subdomains_local(domain):
    """Attempts to discover subdomains using Sublist3r and reads from the local output file."""
    if not os.path.exists(sublist3r_path):
        print(f"[!] Warning: Sublist3r not found at '{sublist3r_path}'. Subdomain discovery will be skipped.")
        return []

    if run_sublist3r(domain, subdomain_output_file):
        subdomains = []
        try:
            with open(subdomain_output_file, "r") as f:
                for line in f:
                    subdomains.append(line.strip())
            return list(set(subdomains))
        except FileNotFoundError:
            print(f"[!] Error: Subdomain output file not found at {subdomain_output_file}")
            return []
        except Exception as e:
            print(f"[!] An error occurred while reading subdomain file: {e}")
            return []
    else:
        return []

def resolve_ips(domains):
    """Resolves IP addresses for a list of domains."""
    print("[*] Resolving IP addresses...")
    ip_map = {}
    for domain in domains:
        try:
            ip_map[domain] = socket.gethostbyname(domain)
        except socket.gaierror:
            ip_map[domain] = None
            print(f"[!] Could not resolve IP for {domain}")
        except Exception as e:
            ip_map[domain] = None
            print(f"[!] An unexpected error occurred while resolving IP for {domain}: {e}")
    print(f"Resolved IPs: {ip_map}")
    return ip_map

def fetch_shodan_data(ip):
    """Fetches Shodan data for a given IP address."""
    if not shodan_client:
        print("[!] Shodan API key not configured. Skipping Shodan lookup.")
        return {"error": "Shodan API key not configured"}

    print(f"[*] Fetching Shodan data for IP: {ip}")
    try:
        host = shodan_client.host(ip)
        meta = {
            "Organization": host.get("org", "N/A"),
            "ISP": host.get("isp", "N/A"),
            "Ports": host.get("ports", []),
            "ASN": host.get("asn", "N/A"),
            "Country Code": host.get("country_code", "N/A"),
            "Hostnames": host.get("hostnames", []),
            "Operating System": host.get("os", "N/A")
            # Add more relevant Shodan data as needed
        }
        print(f"Fetched Shodan data for IP {ip}: {meta}")
        return meta
    except shodan.APIError as e:
        print(f"[!] Error fetching Shodan data for {ip}: {e}")
        return {"error": str(e)}
    except Exception as e:
        print(f"[!] An unexpected error occurred while fetching Shodan data for {ip}: {e}")
        return {"error": "Unexpected Shodan error"}

def perform_http_probe(url, timeout=5):
    """Performs a basic HTTP GET request to check accessibility and gather basic info."""
    try:
        response = requests.get(url, timeout=timeout, allow_redirects=True)
        return {
            "status_code": response.status_code,
            "title": BeautifulSoup(response.text, 'html.parser').title.string.strip() if response.status_code == 200 and response.text else "N/A",
            "headers": {k: v for k, v in response.headers.items()}
        }
    except requests.exceptions.RequestException as e:
        return {"error": f"HTTP request failed: {e}"}
    except Exception as e:
        return {"error": f"An unexpected error occurred during HTTP probe: {e}"}

def analyze_assets(ip_map):
    """Performs further analysis on the resolved IPs, like HTTP probing."""
    print("[*] Analyzing resolved IPs...")
    asset_analysis = {}
    for domain, ip in ip_map.items():
        asset_analysis[domain] = {"ip": ip}
        if ip:
            asset_analysis[domain]["shodan"] = fetch_shodan_data(ip)
            http_url = f"http://{domain}"
            https_url = f"https://{domain}"
            asset_analysis[domain]["http"] = perform_http_probe(http_url)
            asset_analysis[domain]["https"] = perform_http_probe(https_url)
    return asset_analysis

def asset_discovery(target):
    """Main function to perform asset discovery based on a URL or domain input."""
    domain = get_domain_from_url(target)
    if not domain:
        print("[!] Invalid URL or domain provided.")
        return {}
    print(f"[*] Starting asset discovery for target: {target} (domain: {domain})")
    subdomains = discover_subdomains_local(domain)
    if not subdomains:
        print("[!] No subdomains to process.")
        return {}

    ip_map = resolve_ips(subdomains)
    if not ip_map:
        print("[!] No IPs resolved.")
        return {}

    asset_data = {
        "target": target,
        "domain": domain,
        "subdomains": subdomains,
        "ip_map": ip_map,
        "analysis": analyze_assets(ip_map)
    }

    output_json_file = f"{domain.replace('.', '_')}_assets.json"
    with open(output_json_file, "w") as f:
        json.dump(asset_data, f, indent=4)

    print(f"[+] Discovery complete. Results saved to '{output_json_file}'")
    return asset_data

if __name__ == "__main__":
    target = input("Enter the target URL or domain to scan: ")
    results = asset_discovery(target)
    if results:
        print(json.dumps(results, indent=2))
    print("[*] Asset discovery completed.")