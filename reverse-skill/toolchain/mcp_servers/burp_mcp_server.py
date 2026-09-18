#!/usr/bin/env python3
"""
Burp Suite FastMCP Server
Provides HTTP Proxy Interception, Traffic History, and Repeater Diffing for Web & API CTF Exploitation.
"""

import time
import json
import httpx
from datetime import datetime
from mcp.server.fastmcp import FastMCP

mcp = FastMCP(
    "burp-suite",
    dependencies=["mcp", "httpx"]
)

DEFAULT_PROXY = "http://127.0.0.1:8080"
HISTORY_LOG = []

@mcp.tool()
def burp_ping(proxy_url: str = DEFAULT_PROXY) -> str:
    """Check if Burp Suite proxy daemon is active and listening."""
    try:
        with httpx.Client(proxies=proxy_url, verify=False, timeout=2.0) as client:
            resp = client.get("http://burp", timeout=2.0)
            return f"Burp Suite Status: OK (Proxy listening at {proxy_url})"
    except Exception as e:
        return (
            f"Burp Proxy Status: Offline or Not Responding at {proxy_url}.\n"
            f"Hint: Run 'python3 ctf.py burp <chal_name>' to launch headless Burp Suite in background.\n"
            f"(Direct web requests will still work with local history logging)."
        )

@mcp.tool()
def burp_send_request(
    method: str,
    url: str,
    headers: str = None,
    data: str = None,
    cookies: str = None,
    proxy_url: str = DEFAULT_PROXY,
    timeout: float = 10.0
) -> str:
    """
    Send an HTTP/HTTPS request through Burp Suite proxy (or directly if proxy offline).
    - method: GET, POST, PUT, DELETE, PATCH, OPTIONS, HEAD
    - headers: JSON string of headers or key: value lines
    - data: Request body (string / json / raw)
    - cookies: JSON string of cookies
    """
    method = method.upper()
    parsed_headers = {}
    if headers:
        try:
            parsed_headers = json.loads(headers)
        except Exception:
            for line in headers.strip().splitlines():
                if ":" in line:
                    k, v = line.split(":", 1)
                    parsed_headers[k.strip()] = v.strip()
    
    parsed_cookies = {}
    if cookies:
        try:
            parsed_cookies = json.loads(cookies)
        except Exception:
            pass

    proxies = proxy_url if proxy_url else None
    t0 = time.perf_counter()
    used_proxy = True

    try:
        client = httpx.Client(proxies=proxies, verify=False, timeout=timeout)
        resp = client.request(
            method=method,
            url=url,
            headers=parsed_headers,
            content=data.encode() if data else None,
            cookies=parsed_cookies
        )
    except Exception:
        # Fallback to direct connection if proxy fails
        used_proxy = False
        client = httpx.Client(verify=False, timeout=timeout)
        resp = client.request(
            method=method,
            url=url,
            headers=parsed_headers,
            content=data.encode() if data else None,
            cookies=parsed_cookies
        )

    t1 = time.perf_counter()
    elapsed_ms = (t1 - t0) * 1000

    record = {
        "timestamp": datetime.now().strftime("%H:%M:%S"),
        "method": method,
        "url": url,
        "status_code": resp.status_code,
        "elapsed_ms": round(elapsed_ms, 2),
        "proxy_used": used_proxy,
        "response_len": len(resp.text),
        "response_headers": dict(resp.headers),
        "response_body": resp.text[:2000]
    }
    HISTORY_LOG.append(record)
    if len(HISTORY_LOG) > 100:
        HISTORY_LOG.pop(0)

    output = [
        f"HTTP/1.1 {resp.status_code} ({elapsed_ms:.2f}ms | Proxy: {'Active' if used_proxy else 'Direct'})",
        f"URL: {url}",
        "\n--- Response Headers ---"
    ]
    for k, v in resp.headers.items():
        output.append(f"{k}: {v}")
    
    output.append("\n--- Response Body Preview ---")
    output.append(resp.text[:1500] if resp.text else "<empty>")
    if len(resp.text) > 1500:
        output.append(f"\n[... Truncated {len(resp.text) - 1500} bytes ...]")
    
    return "\n".join(output)

@mcp.tool()
def burp_get_history(limit: int = 20) -> str:
    """Retrieve the recent HTTP request/response history log."""
    if not HISTORY_LOG:
        return "No HTTP history recorded yet."
    
    items = HISTORY_LOG[-limit:]
    lines = [f"=== HTTP Traffic History (Last {len(items)} requests) ===", f"{'Time':<10} {'Method':<7} {'Status':<7} {'Latency':<10} {'URL'}"]
    lines.append("-" * 75)
    for r in items:
        lines.append(f"{r['timestamp']:<10} {r['method']:<7} {r['status_code']:<7} {r['elapsed_ms']:<6}ms   {r['url'][:45]}")
    return "\n".join(lines)

@mcp.tool()
def burp_repeater_diff(
    url: str,
    method: str = "GET",
    base_headers: str = None,
    base_data: str = None,
    test_headers: str = None,
    test_data: str = None,
    proxy_url: str = DEFAULT_PROXY
) -> str:
    """
    Perform differential repeater analysis between a baseline request and a test payload request.
    Useful for Time-Based Blind SQLi, Race Conditions, and Header/Auth bypasses.
    """
    # 1. Baseline
    t0 = time.perf_counter()
    r1 = burp_send_request(method, url, base_headers, base_data, None, proxy_url)
    t1 = time.perf_counter()
    time_base = (t1 - t0) * 1000

    # 2. Test payload
    t2 = time.perf_counter()
    r2 = burp_send_request(method, url, test_headers, test_data, None, proxy_url)
    t3 = time.perf_counter()
    time_test = (t3 - t2) * 1000

    delta_time = time_test - time_base

    output = [
        f"=== Differential Repeater Comparison ===",
        f"Target URL: {url}",
        f"Baseline Latency : {time_base:.2f} ms",
        f"Test Latency     : {time_test:.2f} ms",
        f"Delta (Δt)       : {delta_time:+.2f} ms",
        f"\n--- Baseline Response ---",
        r1[:500],
        f"\n--- Test Payload Response ---",
        r2[:500]
    ]
    return "\n".join(output)

if __name__ == "__main__":
    mcp.run(transport="stdio")
