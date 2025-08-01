import requests
import time
import json
from bs4 import BeautifulSoup, Comment
import socket
import ssl
from urllib.parse import urlparse
import re

from tech_patterns import (
    cms_patterns,
    js_library_map,
    language_patterns,
    analytics_patterns,
    cdn_patterns,
    database_patterns,
    framework_patterns,
    security_headers,
    auth_patterns,
    ssl_tls_patterns,
    backend_api,
    dev_tools
)

def detect_cms(html, soup, patterns):
    detected_cms = {}
    for tag in soup.find_all('meta', attrs={'name': 'generator'}):
        content = tag.get('content', '')
        for pattern, name_version_regex in patterns:
            name, version_regex = name_version_regex
            if pattern.search(content):
                version_match = version_regex.search(content) if version_regex else None
                version = version_match.group(1) if version_match else "Unknown"
                detected_cms[name] = version

    # Check common paths in scripts/links
    tags = soup.find_all(['link', 'script'], href=True) + soup.find_all(['link', 'script'], src=True)
    for tag in tags:
        src = tag.get('src') or tag.get('href')
        if src:
            for pattern, name_version_regex in patterns:
                name, version_regex = name_version_regex
                if pattern.search(src):
                    version_match = version_regex.search(src) if version_regex else None
                    version = version_match.group(1) if version_match else "Unknown"
                    detected_cms[name] = version

    return detected_cms if detected_cms else None

def detect_js_libraries(soup, patterns):
    detected_js = set()

    for tag in soup.find_all('script', src=True):
        src = tag['src']

        for pattern, name in patterns:
            if pattern.search(src):
                version = None
                # Try to extract version from filename or query
                version_match = re.search(r'(?:[-_.]?v?|[?&]ver=)(\d+\.\d+(?:\.\d+)?)', src)
                if version_match:
                    version = version_match.group(1)
                detected_js.add(f"{name} {version}" if version else name)

    return sorted(detected_js) if detected_js else None


def detect_programming_languages(soup, headers, patterns):
    detected_langs = set()
    lang_versions = {}

    # Check headers for language hints
    for header_value in headers.values():
        for pattern, name in patterns:
            match = pattern.search(header_value)
            if match:
                detected_langs.add(name)
                if match.groups():
                    lang_versions[name] = match.group(1)

    # Check meta tags for language info
    for meta in soup.find_all('meta'):
        content = meta.get('content', '')
        for pattern, name in patterns:
            match = pattern.search(content)
            if match:
                detected_langs.add(name)
                if match.groups():
                    lang_versions[name] = match.group(1)

    # Combine language and version
    result = []
    for lang in detected_langs:
        if lang in lang_versions:
            result.append(f"{lang} {lang_versions[lang]}")
        else:
            result.append(lang)

    return sorted(result) if result else None

def detect_analytics(soup, patterns):
    detected_analytics = set()

    # Check all script/link/meta tags for analytics patterns
    for tag in soup.find_all(['script', 'link', 'meta', 'img', 'iframe', 'google-analytics']):
        src = tag.get('src') or tag.get('href') or tag.get('content') or ''
        for pattern, name in patterns:
            if pattern.search(src):
                detected_analytics.add(name)

    # Also scan inline script text
    for script in soup.find_all('script'):
        if script.string:
            for pattern, name in patterns:
                if pattern.search(script.string):
                    detected_analytics.add(name)

    return sorted(list(detected_analytics)) if detected_analytics else None

def detect_cdns(soup, headers, patterns):
    detected_cdns = set()

    # Check for known CDN URLs in tags
    tags = soup.find_all(['script', 'link', 'img'], src=True) + soup.find_all(['script', 'link'], href=True)
    for tag in tags:
        src = tag.get('src') or tag.get('href')
        if src:
            for pattern, name in patterns:
                if pattern.search(src):
                    detected_cdns.add(name)

    # Bonus: Check headers
    if headers:
        for key, val in headers.items():
            for pattern, name in patterns:
                if pattern.search(val):
                    detected_cdns.add(name)

    return sorted(list(detected_cdns)) if detected_cdns else None

def detect_frameworks(soup, headers, patterns):
    detected_frameworks = set()

    # Detect from script/src/meta
    for tag in soup.find_all(['script', 'meta', 'link']):
        for attr in ['src', 'href', 'content']:
            val = tag.get(attr, '')
            for pattern, name in patterns:
                if pattern.search(val):
                    detected_frameworks.add(name)

    # Detect from meta generator or framework tags
    for tag in soup.find_all('meta'):
        name = tag.get('name', '').lower()
        content = tag.get('content', '').lower()
        if any(fw in content for fw in ['next.js', 'nuxt', 'svelte', 'htmx']):
            detected_frameworks.add(content.strip())

    # Detect from headers
    if headers:
        for key, val in headers.items():
            for pattern, name in patterns:
                if pattern.search(val):
                    detected_frameworks.add(name)

    # Detect from cookies
    cookie_header = headers.get("Set-Cookie", "")
    if "csrftoken" in cookie_header or "sessionid" in cookie_header:
        detected_frameworks.add("Django")
    if "laravel_session" in cookie_header:
        detected_frameworks.add("Laravel")
    if "_rails_session" in cookie_header:
        detected_frameworks.add("Ruby on Rails")

    return sorted(detected_frameworks) if detected_frameworks else None

def detect_security_headers(headers, patterns):
    detected_headers = {}
    for header in patterns:
        if header in headers:
            detected_headers[header] = headers[header]
    return detected_headers if detected_headers else None

def detect_database(html, patterns):
    detected = set()

    # Search error-like messages in visible HTML
    for pattern, name in patterns:
        if pattern.search(html):
            detected.add(name)

    # Optionally, scan HTML comments (SQL error leaks may occur here)
    soup = BeautifulSoup(html, "html.parser")
    comments = soup.find_all(string=lambda text: isinstance(text, Comment))
    for comment in comments:
        for pattern, name in patterns:
            if pattern.search(comment):
                detected.add(name)

    return sorted(list(detected)) if detected else None

def detect_authentication(soup, patterns):
    detected_auth = set()

    # Check forms and input fields
    forms = soup.find_all('form')
    for form in forms:
        action = form.get('action', '')
        for pattern, name in patterns:
            if pattern.search(action):
                detected_auth.add(name)

        for input_tag in form.find_all('input'):
            input_name = input_tag.get('name', '')
            if pattern.search(input_name):
                detected_auth.add(name)

    # Inline script detection
    scripts = soup.find_all('script', 'Authorization', 'set-cookie')
    for script in scripts:
        script_text = script.string or ''
        for pattern, name in patterns:
            if script_text and pattern.search(script_text):
                detected_auth.add(name)

    return sorted(list(detected_auth)) if detected_auth else None

def detect_ssl_tls(headers, patterns):
    detected_ssl_tls = set()
    header_string = str(headers)
    for pattern, name in patterns:
        if pattern.search(header_string):
            detected_ssl_tls.add(name)
    return sorted(list(detected_ssl_tls)) if detected_ssl_tls else None

def fetch_page(url, retries=3, delay=5, timeout=40):
    headers = {
        "User-Agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/120.0.0.0 Safari/537.36"
        )
    }
    for attempt in range(retries):
        try:
            response = requests.get(url, headers=headers, timeout=timeout)
            response.raise_for_status()
            return response.text, response.headers
        except requests.exceptions.RequestException as e:
            print(f"[!] Attempt {attempt+1} failed: {str(e)}")
            time.sleep(delay)
        except Exception as e:
            print(f"[!] Attempt {attempt+1} failed: Unexpected error: {str(e)}")
            time.sleep(delay)

    return None, f"Failed to fetch {url} after {retries} attempts."

def detect_backend_apis(html, backend_api):
    detected = []
    html = html.lower()
    for api in backend_api:
        if api.lower() in html:
            detected.append(api)
    return detected

def detect_dev_tools(html, tools):
    detected = []
    html = html.lower()
    for tool in tools:
        if tool.lower() in html:
            detected.append(tool)
    return detected

def detect_technologies(url):
    try:
        html, headers = fetch_page(url)
        if not html:
            return {
                "target": url,
                "detected_technologies": {},
                "error": headers
            }
        soup = BeautifulSoup(html, "html.parser")
    except Exception as e:
        return {
            "target": url,
            "detected_technologies": {},
            "error": f"Failed to fetch page: {str(e)}"
        }

    detected = {
        "CMS": detect_cms(html, soup, cms_patterns),
        "JavaScript Libraries": detect_js_libraries(soup, js_library_map),
        "Web Server": headers.get("Server") or headers.get("X-Powered-By"),
        "Analytics": detect_analytics(soup, analytics_patterns),
        "Programming Languages": detect_programming_languages(soup, headers, language_patterns),
        "CDNs": detect_cdns(soup, headers, cdn_patterns),
        "Frameworks": detect_frameworks(soup, headers, framework_patterns),
        "Security Headers": detect_security_headers(headers, security_headers),
        "Databases": detect_database(html, database_patterns),
        "Authentication": detect_authentication(soup, auth_patterns),
        "SSL/TLS": detect_ssl_tls(headers, ssl_tls_patterns),
        "Hosting/CDN Info": headers.get("Via") or headers.get("CF-RAY"),
        "Backend APIs Detected": detect_backend_apis(html, backend_api),
        "Developer Tools Detected": detect_dev_tools(html, dev_tools)
    }
    
    filtered_detected = {}
    for key, value in detected.items():
        if value is not None and value != []:
            filtered_detected[key] = value

    return {
        "target": url,
        "detected_technologies": filtered_detected
    }

def is_reachable(url):
    try:
        response = requests.get(url, timeout=5)
        return response.status_code < 400
    except requests.RequestException:
        return False

def main():
    url = input("Enter the URL to fingerprint: ").strip()
    results = detect_technologies(url)
    print(json.dumps(results, indent=4))
    
if __name__ == "__main__":
    main()


