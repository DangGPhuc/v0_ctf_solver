import tempfile
import shutil
import unittest
from pathlib import Path

from ctf_core.triage.fingerprint import FingerprintEngine
from ctf_core.models import ChallengeFingerprint


class TestTriageFingerprintEngine(unittest.TestCase):
    def setUp(self):
        self.test_dir = Path(tempfile.mkdtemp())
        self.input_dir = self.test_dir / "input"
        self.work_dir = self.test_dir / "work"
        self.input_dir.mkdir()
        self.work_dir.mkdir()

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_fingerprint_elf_binary(self):
        """Simulate an x86-64 ELF binary and verify architecture detection."""
        fake_elf = self.input_dir / "vuln"
        # Construct minimal ELF 64-bit Little Endian header with machine EM_X86_64 (0x3E)
        header = bytearray(b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 8)
        header += b"\x02\x00"  # e_type = ET_EXEC
        header += b"\x3e\x00"  # e_machine = EM_X86_64
        header += b"\x00" * 32
        fake_elf.write_bytes(header)

        meta = {
            "name": "baby_bof",
            "category": "Pwnable",
            "description": "Exploit the buffer overflow in main() to get a shell.",
            "hints": ["Check out the return address on the stack."],
        }

        fp = FingerprintEngine.extract(meta, self.test_dir)
        self.assertEqual(fp.category, "pwn")
        self.assertIn("elf", fp.file_types)
        self.assertIn("x86-64", fp.architectures)
        self.assertIn("overflow", fp.suspicious_patterns)
        self.assertIn("stack-overflow", fp.primitives)

    def test_fingerprint_firmware_zephyr(self):
        """Verify embedded firmware heuristics (Zephyr OS detection)."""
        firmware = self.input_dir / "app.bin"
        firmware.write_bytes(b"\x00\x10\x00\x20\x01\x00\x00\x08" + b"Zephyr kernel booting..." + b"\x00" * 100)

        meta = {
            "name": "ble_lock",
            "category": "Reverse Engineering",
            "description": "Reverse the Bluetooth Low Energy GATT service.",
        }

        fp = FingerprintEngine.extract(meta, self.test_dir)
        self.assertEqual(fp.category, "rev")
        self.assertIn("zephyr", fp.frameworks)
        self.assertIn("arm-cortex-m", fp.architectures)
        self.assertIn("ble", fp.suspicious_patterns)

    def test_fingerprint_web_framework_and_primitives(self):
        """Verify Web SQLi / SSTI primitive extraction from metadata and code."""
        meta = {
            "name": "login_portal",
            "category": "Web Exploitation",
            "description": "A database login portal vulnerable to blind sqli and ssti.",
            "tags": ["web", "database"],
        }

        fp = FingerprintEngine.extract(meta, self.test_dir)
        self.assertEqual(fp.category, "web")
        self.assertIn("sqli", fp.primitives)
        self.assertIn("ssti", fp.suspicious_patterns)

    def test_fingerprint_to_knowledge_query_conversion(self):
        """Verify seamless transformation from ChallengeFingerprint to KnowledgeQuery."""
        fp = ChallengeFingerprint(
            category="pwn",
            tags=["rop"],
            file_types=["elf"],
            architectures=["x86-64"],
            protections=["no-canary", "no-pie"],
            primitives=["stack-overflow"],
            suspicious_patterns=["syscall", "execve"],
        )

        query = fp.to_knowledge_query(hypothesis="Overwriting saved RIP")
        self.assertEqual(query.category, "pwn")
        self.assertIn("x86-64", query.tags)
        self.assertIn("stack-overflow", query.tags)
        self.assertIn("elf", query.file_types)
        self.assertIn("no-canary", query.protections)
        self.assertIn("syscall", query.keywords)
        self.assertEqual(query.current_hypothesis, "Overwriting saved RIP")


if __name__ == "__main__":
    unittest.main()
