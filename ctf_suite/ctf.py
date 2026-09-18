#!/usr/bin/env python3
import sys
from pathlib import Path

# Thêm đường dẫn gói vào sys.path
BASE_DIR = Path(__file__).resolve().parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

from ctf_core.cli.main import app

if __name__ == "__main__":
    app()
