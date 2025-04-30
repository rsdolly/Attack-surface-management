import dns.resolver
import requests
import json
import ipaddress

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

        # Additional check: verify IP address ranges
        try:
            answers = resolver.resolve(subdomain, 'A')
            for rdata in answers:
                ip_address = str(rdata)
                for ip_range in service_config.get('ip_patterns', []):
                    if ipaddress.ip_address(ip_address) in ipaddress.ip_network(ip_range):
                        # If CNAME check failed, but IP matches, it might be a takeover
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
    """Returns a brief risk and impact description for a given service."""
    risk_impact = {
        "AWS S3": (
            "Risk: Unauthorized access to data in a previously associated S3 bucket.",
            "Impact: Data breaches, data loss, serving malicious content."
        ),
        "GitHub Pages": (
            "Risk: Hosting malicious content or phishing pages on a trusted subdomain.",
            "Impact: Brand impersonation, credential theft, malware distribution."
        ),
        "Heroku": (
            "Risk: Hosting unwanted applications or content on the subdomain.",
            "Impact: Brand damage, misleading or malicious activity."
        ),
        "Bitbucket": (
            "Risk: Potential to host content if the Bitbucket Pages repo was deleted.",
            "Impact: Brand damage, potential for malicious content."
        ),
        "Shopify": (
            "Risk: An attacker could claim the subdomain for a new, malicious Shopify store.",
            "Impact: Phishing attacks, brand impersonation, fraudulent activities."
        ),
        "Fastly": (
            "Risk: An attacker could configure the subdomain in their Fastly account.",
            "Impact: Brand damage, serving malicious content or phishing pages."
        ),
        "Google Cloud Storage": (
            "Risk: Unauthorized access to or control over content in a GCS bucket.",
            "Impact: Data breaches, data loss, serving malicious content."
        ),
        "Microsoft Azure": (
            "Risk: Ability to host unwanted content or apps via Azure App Service.",
            "Impact: Brand damage, misleading or malicious activity."
        ),
        "Cloudflare": (
            "Risk: An attacker could add the subdomain to their Cloudflare account.",
            "Impact: Brand impersonation, serving malicious content or phishing pages."
        )
    }
    return risk_impact.get(service, ("Risk: Unknown", "Impact: Unknown"))

def main():
    # Load cloud services from JSON
    try:
        with open('cloud_services.json', 'r') as f:
            cloud_services = json.load(f)
    except FileNotFoundError:
        print("Error: cloud_services.json not found. Exiting.")
        return
    except json.JSONDecodeError:
         print("Error: Invalid JSON in cloud_services.json. Exiting.")
         return

    # Load subdomains from file
    try:
        with open('subdomains.txt', 'r') as f:
            subdomains = [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        print("Error: subdomains.txt not found. Exiting.")
        return

    print("Checking for potential subdomain takeovers...\n")

    vulnerable_subdomains = {}
    for subdomain in subdomains:
        print(f"Checking {subdomain}...")
        vulnerable_services = []
        for service_name, service_config in cloud_services.items():
            service_config['name'] = service_name # Add 'name' key for easier access
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
        for subdomain, services in vulnerable_subdomains.items():
            print(f"{subdomain}: POTENTIALLY VULNERABLE to {', '.join(services)}")
            risk, impact = get_risk_impact(services[0]) # Assuming only one potential service for summary
            print(f"  Risk: {risk}")
            print(f"  Impact: {impact}")
    else:
        print("No potential subdomain takeovers found.")

if __name__ == "__main__":
    main()