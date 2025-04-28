import requests
import re
import os
from bs4 import BeautifulSoup
import ssl
import socket
from urllib.parse import urlparse
from tech_fingerprints import detect_technologies
from datetime import datetime, timedelta
import json

def query_nvd(cpe_or_name, version=None):
    api_key = os.getenv("NVD_API_KEY")
    headers = {"apiKey": api_key} if api_key else {}

    base_url = f"https://services.nvd.nist.gov/rest/json/cves/2.0"
    params = {
        "keywordSearch": cpe_or_name,
        "resultsPerPage": 5,
        "sortBy": "cvssV3Severity"
    }

    if version:
        params["keywordSearch"] += f" {version}"

    start_date = datetime.now() - timedelta(days=3*365)
    params["pubStartDate"] = start_date.isoformat() + "Z"

    try:
        res = requests.get(base_url, headers=headers, params=params)
        res.raise_for_status()
        data = res.json()

        results = []
        for item in data.get("vulnerabilities", []):
            cve = item.get("cve", {})
            metrics = cve.get("metrics", {})
            cvss = metrics.get("cvssMetricV31") or metrics.get("cvssMetricV30") or [{}]

            results.append({
                "id": cve.get("id"),
                "published": cve.get("published"),
                "lastModified": cve.get("lastModified"),
                "description": cve.get("descriptions", [{}])[0].get("value"),
                "severity": cvss[0].get("cvssData", {}).get("baseSeverity"),
                "cvssScore": cvss[0].get("cvssData", {}).get("baseScore"),
                "vector": cvss[0].get("cvssData", {}).get("vectorString"),
                "url": f"https://nvd.nist.gov/vuln/detail/{cve.get('id')}"
            })

        return results if results else None

    except requests.exceptions.RequestException as e:
        print(f"[!] Failed to query NVD: Network error - {str(e)}")
        return None
    except json.JSONDecodeError as e:
        print(f"[!] Failed to decode NVD response: {str(e)}")
        return None
    except Exception as e:
        print(f"[!] An unexpected error occurred while querying NVD: {str(e)}")
        return None

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
    for path in sensitive_paths:
        try:
            full_url = url.rstrip('/') + '/' + path
            res = requests.get(full_url, timeout=5)
            if res.status_code == 200 and len(res.text) > 20 and "Not Found" not in res.text:
                exposed.append(path)
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

        # PyPI Check
        pypi_url = f"https://pypi.org/pypi/{name}/json"
        try:
            pypi_res = requests.get(pypi_url, timeout=5)
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
            pass # Ignore errors, try npm

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
            pass # Ignore npm errors if PyPI also failed

        return {"status": "unknown", "reason": "Package information not found on PyPI or npm"}

    except Exception as e:
        return {"status": "error", "error": str(e)}

def query_exploitdb(tech_name, version=None):
    try:
        search_term = tech_name if not version else f"{tech_name} {version}"
        search_url = f"https://www.exploit-db.com/search?q={search_term}"
        response = requests.get(search_url, timeout=10)
        response.raise_for_status()
        soup = BeautifulSoup(response.text, "html.parser")

        rows = soup.select("table tbody tr")
        exploits = []

        for row in rows[:5]:  # limit to top 5
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

def analyze_vulnerabilities(url):
    results = {
        "target": url,
        "vulnerabilities": {},
        "ssl_misconfigurations": check_ssl_misconfigs(url),
        "sensitive_files": check_sensitive_files(url),
        "outdated_technologies": {}
    }

    fingerprint_result = detect_technologies(url)
    detected_technologies = fingerprint_result.get("detected_technologies", {})

    for tech_type, value in detected_technologies.items():
        items = []
        if isinstance(value, str):
            items = [(value, None)]
        elif isinstance(value, list):
            for item in value:
                parts = item.split()
                name = parts[0]
                version = parts[1] if len(parts) > 1 else None
                items.append((name, version))
        elif isinstance(value, dict):
            items = [(k, v) for k, v in value.items()]

        for name, version in items:
            vuln_info = {}
            if name:
                vuln_info["CVE_NVD"] = query_nvd(name, version)
                vuln_info["ExploitDB"] = query_exploitdb(name, version)
                if version:
                    outdated_check = detect_outdated_versions(name, version)
                    vuln_info["OutdatedCheck"] = outdated_check
                    if outdated_check and outdated_check.get('status') == 'outdated':
                        results['outdated_technologies'][name] = outdated_check
            if vuln_info:
                results["vulnerabilities"][name] = vuln_info

    return results

if __name__ == "__main__":
    url = input("Enter the URL to analyze: ")
    vuln_result = analyze_vulnerabilities(url)
    print(json.dumps(vuln_result, indent=4))