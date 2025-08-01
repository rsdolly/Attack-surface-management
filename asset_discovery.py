import shodan
import os
from urllib.parse import urlparse
import json
import ipaddress
import socket
import dns.resolver
import dns.reversename
from dotenv import load_dotenv
import requests

load_dotenv()

def shodan_lookup(ip_address=None, domain=None):
    api_key = os.getenv("SHODAN_API_KEY")
    if not api_key:
        return {"error": "Shodan API key not found in environment."}

    if not ip_address and not domain:
        return {"error": "You must provide either an IP address or a domain."}

    if domain:
        try:
            import socket
            ip_address = socket.gethostbyname(domain)
        except Exception as e:
            return {"error": f"Failed to resolve domain '{domain}': {str(e)}"}

    try:
        # Validate resolved IP
        ipaddress.ip_address(ip_address)
    except ValueError:
        return {"error": "Invalid IP address format."}

    try:
        api = shodan.Shodan(api_key)
        host = api.host(ip_address)

        # Extract full details
        result = {
            "ip": host.get("ip_str", ip_address),
            "organization": host.get("org", "N/A"),
            "asn": host.get("asn", "N/A"),
            "isp": host.get("isp", "N/A"),
            "location": {
                "city": host.get("city", ""),
                "region": host.get("region_name", ""),
                "country": host.get("country_name", ""),
                "latitude": host.get("latitude", ""),
                "longitude": host.get("longitude", "")
            },
            "hostnames": host.get("hostnames", []),
            "domains": host.get("domains", []),
            "tags": host.get("tags", []),
            "open_ports_and_services": []
        }

        for item in host.get("data", []):
            internetdb_url = f"https://internetdb.shodan.io/{ip_address}"
            internetdb_response = requests.get(internetdb_url, timeout=10)
            internetdb_response.raise_for_status()
            internetdb_data = internetdb_response.json()
            result["open_ports_and_services"].append({
                "port": item.get("port"),
                "transport": item.get("transport"),
                "product": item.get("product"),
                "version": item.get("version"),
                "cpe": item.get("cpe"),
                "banner": item.get("data", "").strip()[:200],
                "tags": internetdb_data.get("tags", []),
                "vulns": internetdb_data.get("vulns", [])
            })

        return {"data": result}

    except shodan.APIError as e:
        return {"error": f"Shodan API error: {str(e)}"}
    except Exception as ex:
        return {"error": f"Unexpected error: {str(ex)}"}

def dns_lookup(input_value):
    if not input_value:
        return {"error": "Input (IP or domain) is required for DNS lookup."}

    try:
        records = {}
        resolver = dns.resolver.Resolver()

        # Determine if input is IP or domain
        try:
            ipaddress.ip_address(input_value)
            is_ip = True
        except ValueError:
            is_ip = False

        queries = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"]

        for qtype in queries:
            try:
                answers = resolver.resolve(input_value, qtype)
                records[qtype] = [str(r.to_text()) for r in answers]
            except:
                continue

        if is_ip:
            try:
                rev_name = dns.reversename.from_address(input_value)
                ptr_answers = resolver.resolve(rev_name, "PTR")
                records["PTR"] = [str(r) for r in ptr_answers]
            except:
                pass
        else:
            try:
                ip = socket.gethostbyname(input_value)
                rev_name = dns.reversename.from_address(ip)
                ptr_answers = resolver.resolve(rev_name, "PTR")
                records["PTR"] = [str(r) for r in ptr_answers]
            except:
                pass

        return {"dns_records_discovered": records}

    except Exception as e:
        return {"error": f"DNS lookup failed: {str(e)}"}


def crtsh_lookup(domain):
    if not domain:
        return {"error": "Domain input is required for crt.sh lookup."}

    try:
        url = f"https://crt.sh/?q=%25.{domain}&output=json"
        response = requests.get(url, timeout=20)
        if response.status_code != 200:
            return {"error": f"crt.sh request failed with status code {response.status_code}"}

        data = response.json()
        certs = set()
        for cert in data:
            name = cert.get("name_value")
            if name:
                for entry in name.split("\n"):
                    certs.add(entry.strip())

        return {"certificates_discovered": sorted(certs)}

    except Exception as e:
        return {"error": f"crt.sh lookup failed: {str(e)}"}

def main():
    domain= input("Enter the Domain: ").strip()
    print(f"\n[+] Extracted Domain: {domain}")
    print("\n[+] Running Shodan Lookup...")
    print(json.dumps(shodan_lookup(domain=domain), indent=2))

    print("\n[+] Running DNS Enumeration...")
    print(json.dumps(dns_lookup(domain), indent=2))

    print("\n[+] Running crt.sh Certificate Search...")
    print(json.dumps(crtsh_lookup(domain), indent=2))

if __name__ == "__main__":
    main()