import shutil
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch, MagicMock

from ctf_core.knowledge.outbox import KnowledgeOutbox
from ctf_core.meta.knowledge_compiler import KnowledgeCompiler


class TestCandidateOutbox(unittest.TestCase):
    def setUp(self):
        self.test_dir = Path(tempfile.mkdtemp())
        self.outbox_dir = self.test_dir / "outbox"
        self.outbox = KnowledgeOutbox(outbox_dir=self.outbox_dir)

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_stage_candidate_preserves_data_and_redacts_flags(self):
        """stage_candidate must create valid YAML candidate and sanitize raw flags."""
        cand_path = self.outbox.stage_candidate(
            challenge_id="chal_99",
            title="Pwn Fastbin Attack",
            category="pwn",
            strategy=[
                "Allocate chunk A and B",
                "Trigger double free on chunk A",
                "Leaked FLAG{super_secret_flag_in_memory}",
            ],
            signals=["Glibc 2.23 fastbin dup"],
            tags=["pwn", "heap", "fastbin"],
        )

        self.assertTrue(cand_path.is_file())
        content = cand_path.read_text(encoding="utf-8")
        self.assertNotIn("super_secret_flag_in_memory", content, "Raw flag must be redacted from candidate steps")
        self.assertIn("pwn.fastbin-attack", cand_path.name)
        self.assertIn("candidate", content)

    def test_list_candidates(self):
        """list_candidates must discover all staged YAML candidates in outbox directory."""
        self.outbox.stage_candidate(
            challenge_id=1,
            title="Crypto LWE",
            category="crypto",
            strategy=["Build lattice"],
        )
        self.outbox.stage_candidate(
            challenge_id=2,
            title="Web SSTI",
            category="web",
            strategy=["Inject payload"],
        )

        candidates = self.outbox.list_candidates()
        self.assertEqual(len(candidates), 2)
        titles = [c.get("title") for c in candidates]
        self.assertTrue(any("Crypto LWE" in t for t in titles))
        self.assertTrue(any("Web SSTI" in t for t in titles))

    def test_knowledge_compiler_stages_to_outbox(self):
        """KnowledgeCompiler.compile_card must stage a candidate into KnowledgeOutbox."""
        compiler = KnowledgeCompiler(outbox=self.outbox)

        challenge_meta = {
            "name": "Buffer Overflow 101",
            "category": "Pwn",
            "tags": ["bof", "rop"],
            "findings": ["Stack buffer overflow at read()", "No canary"],
            "strategy": ["Find offset 72", "Build ROP chain to puts"],
        }

        cand_file = compiler.compile_card(
            challenge_id=101,
            challenge_meta=challenge_meta,
            execution_history=[],
            solve_script="print('Solved')",
        )

        self.assertTrue(cand_file.is_file())
        self.assertTrue(cand_file.is_relative_to(self.outbox_dir))
        content = cand_file.read_text(encoding="utf-8")
        self.assertIn("pwn.buffer-overflow-101", cand_file.name)
        self.assertIn("No canary", content)


if __name__ == "__main__":
    unittest.main()
