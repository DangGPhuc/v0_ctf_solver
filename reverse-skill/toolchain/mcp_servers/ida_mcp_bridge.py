#!/usr/bin/env python3
"""
IDA Pro FastMCP Bridge Server (Smart Lazy-Loading Wrapper)
Connects LLM Agent to the IDA Pro Headless XML-RPC Daemon (127.0.0.1:1337) with On-Demand activation.
"""

import sys
from pathlib import Path

# Redirect to the unified Smart Wrapper
WRAPPER_PATH = Path(__file__).resolve().parent.parent / "ida_pro_wrapper.py"
if WRAPPER_PATH.exists():
    with open(WRAPPER_PATH) as f:
        code = compile(f.read(), str(WRAPPER_PATH), "exec")
        exec(code, globals(), locals())
else:
    raise RuntimeError(f"Wrapper not found at {WRAPPER_PATH}")
