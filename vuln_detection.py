import requests
import re
import os
from bs4 import BeautifulSoup
import ssl
import socket
from urllib.parse import urlparse
from urllib.parse import urljoin
from tech_fingerprints import detect_technologies
from asset_discovery import shodan_lookup
from datetime import datetime, timedelta
import json
import time

def extract_name_version(text):
    if not text:
        return None, None
    match = re.match(r"^([a-zA-Z0-9_\-\.]+)[/ ]+([0-9\.]+)$", str(text).strip())
    if match:
        name = match.group(1).strip()
        version = match.group(2) if match.group(2) else None
        return name, version
    return text, None

def query_nvd(product=None, version=None, cpe_list=None):
    api_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    headers = {"User-Agent": "VulnScanner/1.0"}
    results = {}

    if cpe_list:
        for cpe in cpe_list:
            params = {"cpeName": cpe}
            try:
                print(f"[*] Searching CVEs for CPE: {cpe}")
                r = requests.get(api_url, headers=headers, params=params, timeout=20)
                r.raise_for_status()
                data = r.json()
                cve_items = data.get("vulnerabilities", [])
                results[cpe] = [item["cve"]["id"] for item in cve_items]
                time.sleep(1.5)  # rate-limiting
            except Exception as e:
                print(f"[!] Error for CPE {cpe}: {e}")

    elif product and version:
        keyword = f"{product} {version}"
        params = {"keywordSearch": keyword}
        try:
            print(f"[*] Searching CVEs for Product: {product}, Version: {version}")
            r = requests.get(api_url, headers=headers, params=params, timeout=20)
            r.raise_for_status()
            data = r.json()
            cve_items = data.get("vulnerabilities", [])
            results[keyword] = [item["cve"]["id"] for item in cve_items]
            time.sleep(1.5)
        except Exception as e:
            print(f"[!] Error for {product} {version}: {e}")

    else:
        print("[!] query_nvd: No valid input (product/version or CPE list) provided")

    return results

def check_ssl_misconfigs(url):
    results = {}
    try:
        parsed = urlparse(url)
        hostname = parsed.hostname
        port = 443

        context = ssl.create_default_context()
        with socket.create_connection((hostname, port), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()

                # Certificate validity
                valid_from = datetime.strptime(cert['notBefore'], "%b %d %H:%M:%S %Y %Z")
                valid_to = datetime.strptime(cert['notAfter'], "%b %d %H:%M:%S %Y %Z")
                now = datetime.utcnow()

                results["issuer"] = cert.get("issuer", "")
                results["valid_from"] = cert["notBefore"]
                results["valid_to"] = cert["notAfter"]
                results["expired"] = now > valid_to
                results["not_yet_valid"] = now < valid_from

                # TLS version
                results["tls_version"] = ssock.version()

                # Cipher details
                cipher = ssock.cipher()
                results["cipher"] = {
                    "name": cipher[0],
                    "protocol": cipher[1],
                    "bits": cipher[2]
                }

    except ssl.SSLError as e:
        results["error"] = f"SSL error: {str(e)}"
    except socket.timeout as e:
        results["error"] = f"Socket timeout during SSL check: {str(e)}"
    except socket.gaierror as e:
        results["error"] = f"Hostname resolution error: {str(e)}"
    except Exception as e:
        results["error"] = f"An unexpected error occurred during SSL check: {str(e)}"

    return results

def check_sensitive_files(url):
    sensitive_paths = [
        ".env", ".git/config", ".htaccess", "config.php", "wp-config.php",
        "database.yml", ".DS_Store", ".bash_history", "id_rsa", "docker-compose.yml",
        ".svn/entries", ".ftpconfig", ".editorconfig", "package-lock.json", "yarn.lock",
        "composer.json", "composer.lock", "credentials.json", "secrets.yml", "local.settings.json",
        "web.config", ".npmrc", ".ssh/config", ".ssh/authorized_keys", "settings.py",
        "manage.py", "config.json", "config.yml", "application.properties",
        "application.yml", ".vscode/settings.json", ".idea/workspace.xml", "env.php",
        "pub/errors/local.xml", "Gemfile", "Gemfile.lock"
    ]

    exposed = []
    headers = {"User-Agent": "Mozilla/5.0"}

    for path in sensitive_paths:
        try:
            full_url = urljoin(url + '/', path)
            res = requests.get(full_url, headers=headers, timeout=5)
            if res.status_code == 200 and len(res.text) > 20 and "Not Found" not in res.text:
                exposed.append({
                    "path": path,
                    "url": full_url,
                    "preview": res.text[:100]
                })
        except requests.RequestException:
            continue

    return exposed if exposed else None

def detect_outdated_versions(name, version):
    if not version:
        return {"status": "unknown", "reason": "Version not specified"}
    try:
        name = name.lower()
        current_match = re.findall(r'\d+', version)
        if not current_match:
            return {"status": "unknown", "reason": f"Could not parse version: {version}"}
        current = tuple(map(int, current_match))

        try:
            pypi_res = requests.get(f"https://pypi.org/pypi/{name}/json", timeout=5)
            if pypi_res.status_code == 200:
                latest = pypi_res.json().get("info", {}).get("version", "")
                latest_match = re.findall(r'\d+', latest)
                if latest_match:
                    latest_ver = tuple(map(int, latest_match))
                    if current < latest_ver:
                        return {"status": "outdated", "latest_version": latest, "source": "PyPI"}
                    else:
                        return {"status": "up-to-date", "latest_version": latest, "source": "PyPI"}
                else:
                    return {"status": "unknown", "reason": f"Could not parse latest version from PyPI: {latest}"}
        except requests.RequestException:
            pass

        # npm Check
        npm_url = f"https://registry.npmjs.org/{name}"
        try:
            npm_res = requests.get(npm_url, timeout=5)
            if npm_res.status_code == 200:
                latest = npm_res.json().get("dist-tags", {}).get("latest", "")
                latest_match = re.findall(r'\d+', latest)
                if latest_match:
                    latest_ver = tuple(map(int, latest_match))
                    if current < latest_ver:
                        return {"status": "outdated", "latest_version": latest, "source": "npm"}
                    else:
                        return {"status": "up-to-date", "latest_version": latest, "source": "npm"}
                else:
                    return {"status": "unknown", "reason": f"Could not parse latest version from npm: {latest}"}
        except requests.RequestException:
            pass

        return {"status": "unknown", "reason": "Package information not found on PyPI or npm"}

    except Exception as e:
        return {"status": "error", "error": str(e)}

def query_exploitdb(tech_name, version=None):
    try:
        if not tech_name or not tech_name.strip():
            raise ValueError("Technology name must not be empty.")

        tech_name = tech_name.strip()
        version = version.strip() if version else ""
        search_term = f"{tech_name} {version}".strip()

        search_url = f"https://www.exploit-db.com/search?q={search_term}"
        response = requests.get(search_url, timeout=10)
        response.raise_for_status()

        soup = BeautifulSoup(response.text, "html.parser")
        rows = soup.select("table tbody tr")
        exploits = []

        for row in rows[:5]:
            cols = row.find_all("td")
            if len(cols) >= 2:
                link = cols[1].find("a")
                if link and link.has_attr("href"):
                    exploit = {
                        "id": cols[0].text.strip(),
                        "title": cols[1].text.strip(),
                        "url": "https://www.exploit-db.com" + link["href"]
                    }
                    exploits.append(exploit)

        return exploits if exploits else None

    except requests.exceptions.RequestException as e:
        print(f"[!] Error querying ExploitDB: Network error - {str(e)}")
        return None
    except Exception as e:
        print(f"[!] An unexpected error occurred while querying ExploitDB: {str(e)}")
        return None

def get_ip_from_url(url):
    try:
        parsed = urlparse(url)
        domain = parsed.netloc if parsed.netloc else parsed.path  # Handles missing scheme
        return socket.gethostbyname(domain)
    except Exception as e:
        return f"Error resolving IP: {e}"

def analyze_vulns(url):
    result = {"target": url}
    ip_address = get_ip_from_url(url)
    result["ip_address"] = ip_address if not str(ip_address).startswith("Error") else None
    
    shodan_info = shodan_lookup(ip_address=ip_address)
    # if shodan_info and isinstance(shodan_info, dict):
    #     result["shodan_info"] = shodan_info

    # Detect technologies
    tech_result = detect_technologies(url)
    if tech_result and "detected_technologies" in tech_result:
        result["detected_technologies"] = tech_result["detected_technologies"]

    # SSL/TLS Misconfiguration
    ssl_info = check_ssl_misconfigs(url)
    if ssl_info:
        result["ssl_check"] = ssl_info

    # Sensitive File Discovery
    sensitive_files = check_sensitive_files(url)
    if sensitive_files:
        result["sensitive_files"] = sensitive_files

    # Analyze each detected tech for version issues, CVEs, exploits
    tech_vulns = []
    detected = tech_result.get("detected_technologies", {})
    for category, value in detected.items():
        if isinstance(value, list):
            items = value
        else:
            items = [value]

        for item in items:
            name, version = extract_name_version(item)
            entry = {
                "name": name,
                "version": version
            }

            outdated_info = detect_outdated_versions(name, version)
            if outdated_info:
                entry["outdated_check"] = outdated_info

            cve_result = query_nvd(product=name, version=version)
            if cve_result:
                entry["nvd_cves"] = cve_result

            exploitdb_result = query_exploitdb(name, version)
            if exploitdb_result:
                entry["exploitdb"] = exploitdb_result

            tech_vulns.append(entry)

    if tech_vulns:
        result["technology_vulnerabilities"] = tech_vulns

    return result



def main():
    url = input("Enter the url: ")
    
    result = analyze_vulns(url)
    
    print("\n=== Full Vulnerability Report ===")
    print(json.dumps(result, indent=4))
    
if __name__ == "__main__":
    main()