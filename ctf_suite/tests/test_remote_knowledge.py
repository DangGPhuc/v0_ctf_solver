import json
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from ctf_core.knowledge.models import KnowledgeQuery, KnowledgeHit, KnowledgeDocument
from ctf_core.knowledge.cache import KnowledgeCache
from ctf_core.knowledge.provider import score_entry
from ctf_core.knowledge.local_provider import LocalKnowledgeProvider
from ctf_core.knowledge.github_provider import GitHubKnowledgeProvider


class TestRemoteKnowledgeProvider(unittest.TestCase):
    def setUp(self):
        self.test_dir = Path(tempfile.mkdtemp())
        self.cache_dir = self.test_dir / "cache"
        self.mock_repo_dir = self.test_dir / "mock_repo"
        self.mock_repo_dir.mkdir(parents=True)

        # Create mock index.jsonl with two pwn cards and one web card
        self.cards = [
            {
                "id": "pwn.rop.static-elf-syscall-chain",
                "title": "Static ELF ROP and Syscall Chaining",
                "kind": "technique",
                "category": "pwn",
                "tags": ["rop", "static-elf", "syscall", "x86-64"],
                "path": "cards/pwn/static-elf-syscall.yaml",
                "status": "active",
                "summary": "Building execve syscall ROP chains in statically linked ELF binaries.",
                "quality_score": 0.95,
                "confidence": "high",
            },
            {
                "id": "pwn.heap.tcache-poisoning",
                "title": "Glibc Tcache Poisoning and Fastbin Dup",
                "kind": "technique",
                "category": "pwn",
                "tags": ["heap", "tcache", "glibc", "fastbin"],
                "path": "cards/pwn/tcache-poisoning.yaml",
                "status": "active",
                "summary": "Corrupting next pointer in single-linked tcache entries.",
                "quality_score": 0.9,
                "confidence": "high",
            },
            {
                "id": "web.sqli.blind-time-based",
                "title": "Time-based Blind SQL Injection",
                "kind": "technique",
                "category": "web",
                "tags": ["sqli", "blind", "time-based"],
                "path": "cards/web/blind-sqli.yaml",
                "status": "active",
                "summary": "Extracting database data via SLEEP() or benchmark timing differences.",
                "quality_score": 0.85,
                "confidence": "medium",
            }
        ]

        index_file = self.mock_repo_dir / "index.jsonl"
        with open(index_file, "w", encoding="utf-8") as f:
            for card in self.cards:
                f.write(json.dumps(card) + "\n")

        # Create card files with valid YAML
        import yaml
        for card in self.cards:
            cp = self.mock_repo_dir / card["path"]
            cp.parent.mkdir(parents=True, exist_ok=True)
            cp.write_text(yaml.dump({
                "id": card["id"],
                "title": card["title"],
                "category": card["category"],
                "tags": card["tags"],
                "status": card["status"],
                "summary": card["summary"],
                "technique": {"steps": ["pop rdi", "ret"]},
            }, sort_keys=False), encoding="utf-8")

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_ranking_prefers_exact_tags_and_keywords(self):
        """Query with pwn + rop + static-elf MUST rank ROP card strictly above tcache heap card."""
        query = KnowledgeQuery(
            category="pwn",
            tags=["rop", "static-elf"],
            keywords=["syscall", "execve"],
        )

        rop_card = self.cards[0]
        heap_card = self.cards[1]
        web_card = self.cards[2]

        score_rop, matches_rop = score_entry(rop_card, query)
        score_heap, matches_heap = score_entry(heap_card, query)
        score_web, matches_web = score_entry(web_card, query)

        self.assertGreater(score_rop, score_heap, "ROP card must score higher than Heap card for ROP query")
        self.assertGreater(score_heap, score_web, "Heap card (category pwn) must score higher than Web card")
        self.assertTrue(any("category" in m for m in matches_rop))
        self.assertTrue(any("tags:" in m for m in matches_rop))
        self.assertTrue(any("keyword:" in m for m in matches_rop))

    def test_local_knowledge_provider_search_and_fetch(self):
        """Test LocalKnowledgeProvider indexing, searching, and on-demand fetching."""
        provider = LocalKnowledgeProvider(root_dir=self.mock_repo_dir)

        query = KnowledgeQuery(category="pwn", tags=["rop"])
        hits = provider.search(query, limit=5)
        self.assertEqual(len(hits), 2)
        self.assertEqual(hits[0].id, "pwn.rop.static-elf-syscall-chain")

        # Fetch selected card on-demand
        doc = provider.fetch(hits[0].id)
        self.assertIsNotNone(doc)
        self.assertEqual(doc.id, "pwn.rop.static-elf-syscall-chain")
        self.assertIn("Static ELF ROP", doc.content)

    def test_knowledge_cache_stores_and_retrieves(self):
        """Test KnowledgeCache index caching and object caching."""
        cache = KnowledgeCache(base_dir=self.cache_dir)

        index_entries = self.cards
        cache.save_index("test_repo", "main", index_entries)

        loaded = cache.get_index("test_repo", "main")
        self.assertEqual(len(loaded), 3)

        # Cache document object
        cache.save_object("test_repo", "cards/pwn/static-elf-syscall.yaml", "fake_content_abc")
        cached_content = cache.get_object("cards/pwn/static-elf-syscall.yaml", repo="test_repo")
        self.assertEqual(cached_content, "fake_content_abc")

    @patch("httpx.Client.get")
    def test_github_knowledge_provider_drive_mode(self, mock_get):
        """Test GitHubKnowledgeProvider fetches index and card on-demand via remote HTTP without cloning repo."""
        index_jsonl_text = "\n".join(json.dumps(c) for c in self.cards)
        card_yaml_text = "id: pwn.rop.static-elf-syscall-chain\ntitle: Static ELF ROP\ncategory: pwn\ntechnique:\n  steps: [pop rdi, ret]\n"

        def fake_get(url, **kwargs):
            mock_resp = MagicMock()
            mock_resp.status_code = 200
            if "index.jsonl" in str(url):
                mock_resp.text = index_jsonl_text
            else:
                mock_resp.text = card_yaml_text
            return mock_resp

        mock_get.side_effect = fake_get

        cache = KnowledgeCache(base_dir=self.cache_dir)
        provider = GitHubKnowledgeProvider(
            repo="DangGPhuc/v0_ctf_knowledge",
            ref="main",
            cache=cache,
            offline=False,
        )

        query = KnowledgeQuery(category="pwn", tags=["rop"])
        hits = provider.search(query, limit=1)
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0].id, "pwn.rop.static-elf-syscall-chain")

        # Fetch on demand
        doc = provider.fetch("pwn.rop.static-elf-syscall-chain")
        self.assertIsNotNone(doc)
        self.assertIn("Static ELF ROP", doc.content)

        # Verify cached locally
        cached = cache.get_object("cards/pwn/static-elf-syscall.yaml", repo="DangGPhuc/v0_ctf_knowledge")
        self.assertIsNotNone(cached)

    def test_github_provider_graceful_offline_fallback(self):
        """Ensure that network error does not crash solver; provider degrades gracefully."""
        cache = KnowledgeCache(base_dir=self.cache_dir)
        # Prepopulate cache with empty index
        cache.save_index("DangGPhuc/v0_ctf_knowledge", "main", [])

        provider = GitHubKnowledgeProvider(
            repo="DangGPhuc/v0_ctf_knowledge",
            ref="main",
            cache=cache,
            offline=True,  # offline mode forced
        )

        query = KnowledgeQuery(category="pwn")
        hits = provider.search(query)
        self.assertEqual(hits, [], "Offline mode with empty cache should return empty hits without raising exception")


if __name__ == "__main__":
    unittest.main()
