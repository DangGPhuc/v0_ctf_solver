"""CTF Platforms Package."""
from .base import BasePlatform, PlatformAdapter
from .registry import create_platform, detect_platform_type, register_platform
from .ctfd import CTFdPlatform
from .gzctf import GZCTFPlatform
from .rctf import RCTFPlatform
from .noctf import NoCTFPlatform
from .cyberhx import CyberHXPlatform

__all__ = [
    "BasePlatform",
    "register_platform",
    "create_platform",
    "detect_platform_type",
    "CTFdPlatform",
    "GZCTFPlatform",
    "RCTFPlatform",
    "NoCTFPlatform",
    "CyberHXPlatform",
]

