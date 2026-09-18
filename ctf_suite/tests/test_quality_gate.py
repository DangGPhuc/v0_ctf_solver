import shutil
import tempfile
import unittest
from pathlib import Path
import yaml

from ctf_core.knowledge.outbox import KnowledgeOutbox


class TestKnowledgeQualityGate(unittest.TestCase):
    def setUp(self):
        self.test_dir = Path(tempfile.mkdtemp())
        self.outbox = KnowledgeOutbox(outbox_dir=self.test_dir)

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def _write_card(self, filename: str, content: dict) -> Path:
        p = self.test_dir / filename
        p.write_text(yaml.dump(content, sort_keys=False), encoding="utf-8")
        return p

    def test_valid_technique_card_passes(self):
        valid_card = {
            "schema_version": 1,
            "id": "crypto.lwe.left-nullspace",
            "title": "Left Nullspace Small Noise Recovery",
            "kind": "technique",
            "category": "crypto",
            "tags": ["lwe", "lattice"],
            "status": "candidate",
            "summary": "Recover small secret/noise using left kernel lattice basis reduction.",
            "signals": ["Linear equation system over Z_q with small perturbation noise"],
            "technique": {
                "steps": [
                    "Formulate matrix A and target vector b",
                    "Compute left nullspace lattice modulo q",
                    "Apply LLL/BKZ reduction to find short vector",
                    "Reconstruct secret via rational reconstruction",
                ]
            }
        }
        cp = self._write_card("valid.yaml", valid_card)
        errors = self.outbox.validate_candidate(cp)
        self.assertEqual(errors, [])

    def test_rejects_plaintext_flag(self):
        card = {
            "id": "pwn.rop.simple",
            "category": "pwn",
            "signals": ["ELF 64-bit no canary"],
            "technique": {"steps": ["ROP to system", "Found FLAG{real_secret_flag_1337}"]}
        }
        cp = self._write_card("flag_leak.yaml", card)
        errors = self.outbox.validate_candidate(cp)
        self.assertTrue(any("Plaintext flag" in e for e in errors))

    def test_rejects_leaked_credentials(self):
        card = {
            "id": "web.jwt.bypass",
            "category": "web",
            "signals": ["JWT with alg=none"],
            "technique": {"steps": ["Craft token with API_TOKEN=sk-live-1234567890abcdef"]}
        }
        cp = self._write_card("cred_leak.yaml", card)
        errors = self.outbox.validate_candidate(cp)
        self.assertTrue(any("Leaked credentials" in e for e in errors))

    def test_rejects_invalid_taxonomy(self):
        card = {
            "id": "pwn.bad-tax",
            "category": "pwn (rop",  # Non-canonical taxonomy
            "signals": ["Buffer overflow"],
            "technique": {"steps": ["Overwrite RIP"]}
        }
        cp = self._write_card("bad_tax.yaml", card)
        errors = self.outbox.validate_candidate(cp)
        self.assertTrue(any("Invalid category taxonomy" in e for e in errors))

    def test_rejects_generic_static_triage_only(self):
        card = {
            "id": "rev.generic-triage",
            "category": "rev",
            "signals": ["ELF file"],
            "technique": {"steps": ["Static triage"]}  # Generic step only
        }
        cp = self._write_card("generic.yaml", card)
        errors = self.outbox.validate_candidate(cp)
        self.assertTrue(any("Low quality" in e for e in errors))

    def test_rejects_misc_happy(self):
        card = {
            "id": "misc.misc_happy",
            "category": "misc",
            "signals": ["Challenge happy"],
            "technique": {"steps": ["Execute script"]}
        }
        cp = self._write_card("misc_happy.yaml", card)
        errors = self.outbox.validate_candidate(cp)
        self.assertTrue(any("happy" in e.lower() for e in errors))


if __name__ == "__main__":
    unittest.main()
