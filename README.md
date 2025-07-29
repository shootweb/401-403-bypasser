# 401/403 Bypass Tester

**401 Bypass Tester** is an advanced asynchronous Python tool that automates testing of common and obscure techniques to bypass HTTP 401 Unauthorized restrictions in APIs or web applications. It leverages combinations of manipulated headers, crafted URL payloads, and multiple HTTP methods to detect possible access control misconfigurations.

## Features

- Asynchronous and fast (built on `aiohttp` and `asyncio`)
- Extensive bypass payloads and query string injections
- Header manipulation (Authorization, Cookies, X-Forwarded-For, etc.)
- User-Agent rotation
- Tests multiple HTTP methods: `GET`, `POST`, `PUT`, `DELETE`, `PATCH`, `OPTIONS`, `HEAD`
- Outputs successful bypass attempts to a file

## Usage

```bash
python "401 bypass.py" <target_domain> <paths.txt> [--workers 10] [--rate-limit 0.1]
```

### Example:

```bash
python "401 bypass.py" api.example.com paths.txt --workers 20 --rate-limit 0.2
```

- `<target_domain>`: Target domain without protocol (e.g., `api.example.com`)
- `<paths.txt>`: File with newline-separated endpoint paths (e.g., `/admin`, `/api/user`)
- `--workers`: Maximum number of concurrent async requests (default: 10)
- `--rate-limit`: Delay in seconds between requests (default: 0.1)

## Output

Results are written to a file named `<paths>_bypassed.txt` showing:

- HTTP method used
- Bypassed full URL
- Headers that enabled the bypass
- Response size and request timing

## Example Output Snippet

```
[GET] https://api.example.com/%2e%2e/admin
     Headers: {'Authorization': 'Bearer null', 'User-Agent': 'curl/7.68.0'}
     Response Length: 1823
     Elapsed Time: 0.42s
------------------------------------------------------------
```

## Requirements

Install dependencies with:

```bash
pip install -r requirements.txt
```

## requirements.txt

```
aiohttp
requests
```

## Disclaimer

This tool is intended for educational and authorized security testing only. Unauthorized use against systems you do not own or have permission to test is illegal.

## Contribute

Feel free to open issues or pull requests to suggest improvements or new techniques.

---

Built for security researchers, red teamers, and bug bounty hunters.
