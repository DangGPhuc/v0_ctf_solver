import os
import re
import json
import shutil
import hashlib
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch, MagicMock

from ctf_core.models import (
    AdvisorGuidance,
    Hypothesis,
    Action,
    ExecutionResult,
    ExecutionAction,
    AdvisorResult,
    Challenge,
)
from ctf_core.execution.container_executor import ContainerExecutor
from ctf_core.execution.restricted_executor import RestrictedLocalExecutor
from ctf_core.knowledge.models import KnowledgeQuery
from ctf_core.knowledge.provider import score_entry
from ctf_core.knowledge.cache import KnowledgeCache
from ctf_core.knowledge.github_provider import GitHubKnowledgeProvider
from ctf_core.services.advisor_service import AdvisorService, BrowserBridge
from ctf_core.services.orchestrator import ChallengeOrchestrator
from ctf_core.runtime.manager import RuntimeManager


class TestMergeGateSecurity(unittest.TestCase):
    def setUp(self):
        self.test_dir = Path(tempfile.mkdtemp())
        self.work_dir = self.test_dir / "work"
        self.input_dir = self.test_dir / "input"
        self.cache_dir = self.test_dir / "cache"
        self.work_dir.mkdir(parents=True)
        self.input_dir.mkdir(parents=True)
        self.cache_dir.mkdir(parents=True)

        self.context = {
            "challenge_id": "chall_gate_1",
            "name": "Gate Challenge",
            "category": "pwn",
            "work_dir": self.work_dir,
            "input_dir": self.input_dir,
            "iteration": 1,
            "active_hypothesis": "Test Stack Overflow",
        }

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    # 1. Container success never calls host fallback
    @patch("shutil.which")
    @patch("subprocess.run")
    def test_container_success_never_calls_host_fallback(self, mock_subproc, mock_which):
        """ContainerExecutor MUST parse container stdout/stderr directly and NEVER call host fallback."""
        mock_which.return_value = "/usr/bin/docker"
        (self.work_dir / "solve.py").write_text("print('hello')", encoding="utf-8")

        mock_proc = MagicMock()
        mock_proc.returncode = 0
        mock_proc.stdout = "Executing solver in container...\nFound: FLAG{container_isolation_verified_1337}\n"
        mock_proc.stderr = ""
        mock_subproc.return_value = mock_proc

        executor = ContainerExecutor(
            image="v0-solver:latest",
            allow_local_fallback=False,
            flag_format=r"^FLAG\{.+\}$",
        )
        executor.fallback.execute = MagicMock()

        guidance = AdvisorGuidance(
            assessment="Test container",
            execution_plan=[ExecutionAction(kind="run_solver", path="solve.py")]
        )

        result = executor.execute(self.context, guidance)

        # Verify container subprocess was called
        self.assertTrue(mock_subproc.called)
        # Find the docker run call
        docker_run_calls = [c for c in mock_subproc.call_args_list if len(c[0]) > 0 and len(c[0][0]) > 1 and c[0][0][1] == "run"]
        self.assertEqual(len(docker_run_calls), 1)
        cmd_args = docker_run_calls[0][0][0]

        self.assertIn("docker", cmd_args)
        self.assertIn("--network=none", cmd_args)
        self.assertIn("--cap-drop=ALL", cmd_args)
        self.assertIn("--security-opt=no-new-privileges", cmd_args)

        # Verify host fallback executor was NOT called
        executor.fallback.execute.assert_not_called()

        # Verify result was built directly from container output
        self.assertEqual(result.status, "FLAG_FOUND")
        self.assertIn("FLAG{container_isolation_verified_1337}", result.flag_candidates)
        self.assertIn("Executing solver in container", result.stdout_tail)

    # 2. Container failure does not silently execute on host
    @patch("shutil.which")
    @patch("subprocess.run")
    def test_container_failure_does_not_silently_execute_on_host(self, mock_subproc, mock_which):
        """Container failure must return ERROR directly and not rerun untrusted workload on host."""
        mock_which.return_value = "/usr/bin/docker"
        (self.work_dir / "solve.py").write_text("print('fail')", encoding="utf-8")

        mock_proc = MagicMock()
        mock_proc.returncode = 1
        mock_proc.stdout = "Failed inside container"
        mock_proc.stderr = "Traceback (most recent call last): Error"
        mock_subproc.return_value = mock_proc

        executor = ContainerExecutor(
            image="v0-solver:latest",
            allow_local_fallback=False,
        )
        executor.fallback.execute = MagicMock()

        guidance = AdvisorGuidance(
            assessment="Test container fail",
            execution_plan=[ExecutionAction(kind="run_solver", path="solve.py")]
        )

        result = executor.execute(self.context, guidance)

        # Assert fallback was NOT called
        executor.fallback.execute.assert_not_called()
        self.assertEqual(result.status, "ERROR")

    # 3. Arbitrary executable from advisor is rejected
    def test_arbitrary_executable_from_advisor_is_rejected(self):
        """RestrictedLocalExecutor must reject unallowlisted binaries / arbitrary tools."""
        executor = RestrictedLocalExecutor(timeout=10)

        # Test arbitrary tool
        guidance = AdvisorGuidance(
            assessment="Attack with bash",
            execution_plan=[ExecutionAction(kind="analysis_tool", tool="bash", argv=["bash", "-c", "whoami"])]
        )
        result = executor.execute(self.context, guidance)
        self.assertEqual(result.status, "ERROR")
        self.assertIn("allowed registry", result.observed)

        # Test tool not in ALLOWED_ANALYSIS_TOOLS
        guidance_curl = AdvisorGuidance(
            assessment="Attack with curl",
            execution_plan=[ExecutionAction(kind="analysis_tool", tool="curl", argv=["curl", "http://evil.com"])]
        )
        result = executor.execute(self.context, guidance_curl)
        self.assertEqual(result.status, "ERROR")
        self.assertIn("allowed registry", result.observed)

    # 4. Path traversal execution action is rejected
    def test_path_traversal_execution_action_is_rejected(self):
        """RestrictedLocalExecutor must reject path traversal outside work directory."""
        executor = RestrictedLocalExecutor(timeout=10)

        # Attempt to read /etc/passwd or ../../
        guidance_read = AdvisorGuidance(
            assessment="Traverse read",
            execution_plan=[ExecutionAction(kind="read_file", path="../../etc/passwd")]
        )
        result = executor.execute(self.context, guidance_read)
        self.assertEqual(result.status, "ERROR")
        self.assertIn("Path traversal blocked", result.observed)

        # Attempt to run binary outside work directory
        guidance_bin = AdvisorGuidance(
            assessment="Traverse binary",
            execution_plan=[ExecutionAction(kind="run_binary", path="/bin/ls")]
        )
        result = executor.execute(self.context, guidance_bin)
        self.assertEqual(result.status, "ERROR")
        self.assertIn("Path traversal blocked", result.observed)

        # Attempt to run python file outside work dir
        guidance_py = AdvisorGuidance(
            assessment="Traverse python",
            execution_plan=[ExecutionAction(kind="run_python_file", path="../../../test.py")]
        )
        result = executor.execute(self.context, guidance_py)
        self.assertEqual(result.status, "ERROR")
        self.assertIn("Path traversal blocked", result.observed)

    # 5. Non-READY advisor state never executes
    def test_non_ready_advisor_state_never_executes(self):
        """Orchestrator must halt and never execute actions when advisor status is not READY."""
        mock_executor = MagicMock()
        mock_runtime = MagicMock()
        mock_runtime.materialize_challenge.return_value = self.test_dir

        mock_advisor = MagicMock()

        orchestrator = ChallengeOrchestrator(
            workspace_dir=self.test_dir,
            runtime_manager=mock_runtime,
            executor=mock_executor,
            advisor=mock_advisor,
            event_id="test_event",
            max_iterations_per_chall=1,
        )

        chall_info = {"id": "1", "name": "Test Chall", "category": "pwn", "points": 100}

        # 1. PROVIDER_UNAVAILABLE
        mock_advisor.consult.return_value = AdvisorResult(
            status="PROVIDER_UNAVAILABLE",
            guidance=None,
            message="No provider",
        )
        solved = orchestrator.execute_challenge_cycle(chall_info)
        self.assertFalse(solved)
        mock_executor.execute.assert_not_called()

        # 2. ERROR
        mock_advisor.consult.return_value = AdvisorResult(
            status="ERROR",
            guidance=None,
            message="Critical crash",
        )
        solved = orchestrator.execute_challenge_cycle(chall_info)
        self.assertFalse(solved)
        mock_executor.execute.assert_not_called()

        # 3. WAITING_FOR_MANUAL_RESPONSE
        mock_advisor.consult.return_value = AdvisorResult(
            status="WAITING_FOR_MANUAL_RESPONSE",
            guidance=None,
            message="Awaiting user input",
        )
        solved = orchestrator.execute_challenge_cycle(chall_info)
        self.assertFalse(solved)
        mock_executor.execute.assert_not_called()

    # 6. BrowserBridge mock actually intercepts calls
    @patch("subprocess.run")
    def test_browser_bridge_mock_intercepts_calls(self, mock_subproc):
        """AdvisorService consult fallback must call injected BrowserBridge methods directly."""
        mock_subproc.side_effect = FileNotFoundError("oracle not found")

        mock_bridge = MagicMock()
        rt = RuntimeManager(base_dir=self.test_dir / ".runtime")
        rt.materialize_challenge("test_event", Challenge(id="test_chall", name="Test Chall", category="pwn"))

        advisor = AdvisorService(
            workspace_dir=self.test_dir,
            runtime_manager=rt,
            event_id="test_event",
            browser_bridge=mock_bridge,
        )
        advisor.init_challenge_advisor("test_chall")

        res = advisor.consult("test_chall")

        mock_bridge.copy_to_clipboard.assert_called_once()
        mock_bridge.open_firefox.assert_called_once()
        self.assertEqual(res["status"], "WAITING_FOR_MANUAL_RESPONSE")

    # 7. Remote provider uses GitHub Contents API
    @patch("httpx.Client")
    def test_remote_provider_uses_github_contents_api(self, mock_client_cls):
        """GitHubKnowledgeProvider must use REST Contents API with auth header and raw accept header."""
        mock_client = MagicMock()
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.text = "id: pwn.rop.test\ntitle: Test ROP\nstatus: active\ncategory: pwn\n"
        mock_client.get.return_value = mock_resp
        mock_client.__enter__.return_value = mock_client
        mock_client_cls.return_value = mock_client

        cache = KnowledgeCache(base_dir=self.cache_dir)
        provider = GitHubKnowledgeProvider(
            repo="DangGPhuc/v0_ctf_knowledge",
            ref="main",
            token="test_gh_secret_token",
            cache=cache,
            offline=False,
        )
        provider._index_entries = [{"id": "pwn.rop.test", "path": "cards/pwn/test.yaml"}]

        doc = provider.fetch("pwn.rop.test")
        self.assertTrue(mock_client.get.called)
        call_url = mock_client.get.call_args[0][0]

        self.assertIn("api.github.com/repos/DangGPhuc/v0_ctf_knowledge/contents/cards/pwn/test.yaml", call_url)
        self.assertIn("ref=main", call_url)

        headers = mock_client_cls.call_args[1]["headers"]
        self.assertEqual(headers.get("Authorization"), "Bearer test_gh_secret_token")
        self.assertEqual(headers.get("Accept"), "application/vnd.github.raw+json")
        self.assertEqual(headers.get("X-GitHub-Api-Version"), "2022-11-28")

    # 8. Remote provider stale cache fallback
    @patch("httpx.Client")
    def test_remote_provider_stale_cache_fallback(self, mock_client_cls):
        """When network fails, remote provider must gracefully fall back to stale cache without crashing."""
        mock_client = MagicMock()
        mock_client.get.side_effect = Exception("Network unreachable")
        mock_client.__enter__.return_value = mock_client
        mock_client_cls.return_value = mock_client

        cache = KnowledgeCache(base_dir=self.cache_dir, default_ttl_seconds=0)
        cards = [{
            "id": "pwn.rop.test",
            "title": "Stale ROP Technique",
            "kind": "technique",
            "category": "pwn",
            "tags": ["rop"],
            "path": "cards/pwn/test.yaml",
            "status": "active",
            "summary": "Stale cached entry",
            "quality_score": 0.9,
            "confidence": "high",
        }]
        cache.store_index("DangGPhuc/v0_ctf_knowledge", "main", cards, ttl_seconds=0)
        self.assertFalse(cache.is_index_fresh("DangGPhuc/v0_ctf_knowledge", "main"))

        provider = GitHubKnowledgeProvider(
            repo="DangGPhuc/v0_ctf_knowledge",
            token="dummy",
            cache=cache,
            offline=False,
        )

        query = KnowledgeQuery(category="pwn", tags=["rop"])
        hits = provider.search(query)
        self.assertGreater(len(hits), 0)
        self.assertEqual(hits[0].id, "pwn.rop.test")

    # 9. Advisor rich fingerprint query
    def test_advisor_rich_fingerprint_query(self):
        """Advisor must construct KnowledgeQuery from rich challenge context (protections, tags, keywords)."""
        advisor = AdvisorService(
            workspace_dir=self.test_dir,
            runtime_manager=RuntimeManager(base_dir=self.test_dir / ".runtime"),
            event_id="test_event",
        )

        chall_context = {
            "name": "chall_overflow_pwn",
            "category": "pwn",
            "tags": ["rop", "static-elf", "x86-64"],
            "file_types": ["elf"],
            "protections": ["no-pie", "no-canary"],
            "keywords": ["syscall", "overflow"],
            "current_hypothesis": "stack overflow with static libc gadgets",
            "triage_notes": "Statically linked 64-bit ELF with NX enabled and no PIE",
        }

        query = advisor._build_knowledge_query(chall_context)
        self.assertEqual(query.category, "pwn")
        self.assertIn("rop", query.tags)
        self.assertIn("static-elf", query.tags)
        self.assertIn("elf", query.file_types)
        self.assertIn("no-pie", query.protections)
        self.assertIn("no-canary", query.protections)
        self.assertIn("syscall", query.keywords)
        self.assertEqual(query.current_hypothesis, "stack overflow with static libc gadgets")

        rop_card = {
            "id": "pwn.rop.static-elf-syscall-chain",
            "title": "Static ELF ROP and Syscall Chaining",
            "category": "pwn",
            "tags": ["rop", "static-elf", "syscall", "x86-64"],
            "summary": "Building execve syscall ROP chains in statically linked ELF binaries without PIE.",
            "quality_score": 0.95,
        }
        heap_card = {
            "id": "pwn.heap.tcache-poisoning",
            "title": "Glibc Tcache Poisoning and Fastbin Dup",
            "category": "pwn",
            "tags": ["heap", "tcache", "glibc", "fastbin"],
            "summary": "Corrupting next pointer in single-linked tcache entries.",
            "quality_score": 0.9,
        }

        score_rop, _ = score_entry(rop_card, query)
        score_heap, _ = score_entry(heap_card, query)
        self.assertGreater(score_rop, score_heap)

    # 10. Knowledge source_refs exist
    def test_knowledge_source_refs_exist(self):
        """All source_refs in active knowledge cards must resolve to existing files."""
        knowledge_dir = Path("/home/kali/Documents/v0_ctf_knowledge")
        if not knowledge_dir.exists():
            self.skipTest("Knowledge repo not present locally at /home/kali/Documents/v0_ctf_knowledge")

        import yaml
        cards_dir = knowledge_dir / "cards"
        dangling = []
        for card_path in cards_dir.rglob("*.yaml"):
            try:
                data = yaml.safe_load(card_path.read_text(encoding="utf-8"))
                for ref in data.get("source_refs", []):
                    ref_path = knowledge_dir / ref
                    if not ref_path.exists():
                        dangling.append(f"{card_path.name} -> {ref}")
            except Exception as e:
                dangling.append(f"{card_path.name}: {e}")
        self.assertEqual(dangling, [], f"Found dangling source_refs: {dangling}")

    # 11. Full knowledge repo flag scan
    def test_full_knowledge_repo_flag_scan(self):
        """Knowledge repo must not contain unredacted plaintext flags."""
        knowledge_dir = Path("/home/kali/Documents/v0_ctf_knowledge")
        if not knowledge_dir.exists():
            self.skipTest("Knowledge repo not present locally at /home/kali/Documents/v0_ctf_knowledge")

        flag_pattern = re.compile(r"\b(FLAG|CTF|NNS|Null0rigin|HTB|picoCTF)\{([a-zA-Z0-9_\-!@#$%^&*+=?]+)\}", re.IGNORECASE)

        def is_placeholder(val: str) -> bool:
            v = val.lower().strip()
            return "<redacted>" in v or "..." in v or "fake" in v or v in ["xxx", "test", "example", "0"]

        violations = []
        for check_dir in ["cards", "references", "writeups", "legacy", "inbox"]:
            dir_path = knowledge_dir / check_dir
            if not dir_path.exists():
                continue
            for fpath in dir_path.rglob("*"):
                if fpath.is_file() and not fpath.name.startswith("."):
                    try:
                        content = fpath.read_text(encoding="utf-8", errors="ignore")
                        for line_no, line in enumerate(content.splitlines(), start=1):
                            if 'b"flag{"' in line or 'b"FLAG{"' in line:
                                continue
                            for m in flag_pattern.finditer(line):
                                flag_val = m.group(2)
                                if not is_placeholder(flag_val):
                                    violations.append(f"{fpath.relative_to(knowledge_dir)}:{line_no}: {m.group(0)}")
                    except Exception:
                        pass
        self.assertEqual(violations, [], f"Found unredacted flags: {violations}")

    # 12. Skill size budget
    def test_skill_size_budget(self):
        """Core repository .agents/skills directory must be lightweight (< 500 KB)."""
        skills_dir = Path(__file__).resolve().parent.parent.parent / ".agents" / "skills"
        total_size = sum(f.stat().st_size for f in skills_dir.rglob("*") if f.is_file())
        max_budget = 500 * 1024  # 500 KB
        self.assertLess(total_size, max_budget, f"Skills directory size ({total_size / 1024:.1f} KB) exceeds 500 KB budget!")

    # 13. No cross-repo duplicates
    def test_no_cross_repo_duplicates(self):
        """Assert zero exact duplicate files between .agents/skills and v0_ctf_knowledge/references/."""
        knowledge_refs = Path("/home/kali/Documents/v0_ctf_knowledge/references")
        skills_dir = Path(__file__).resolve().parent.parent.parent / ".agents" / "skills"
        if not knowledge_refs.exists() or not skills_dir.exists():
            self.skipTest("Paths not found for cross-repo dedupe check")

        def file_hash(p: Path) -> str:
            return hashlib.sha256(p.read_bytes()).hexdigest()

        skills_hashes = {}
        for f in skills_dir.rglob("*"):
            if f.is_file() and f.stat().st_size > 0:
                skills_hashes[file_hash(f)] = f.name

        duplicates = []
        for f in knowledge_refs.rglob("*"):
            if f.is_file() and f.stat().st_size > 0:
                h = file_hash(f)
                if h in skills_hashes:
                    duplicates.append(f"{f.name} (matches skill file {skills_hashes[h]})")

        self.assertEqual(duplicates, [], f"Found exact cross-repo duplicate files: {duplicates}")

    # 14. Legacy production tokens absent
    def test_legacy_production_tokens_absent(self):
        """Codebase must not contain hardcoded production tokens or secrets."""
        core_root = Path(__file__).resolve().parent.parent.parent
        secret_patterns = [
            re.compile(r"ghp_[A-Za-z0-9]{36}"),
            re.compile(r"github_pat_[A-Za-z0-9_]{82}"),
        ]
        violations = []
        for f in core_root.rglob("*.py"):
            if ".git" in f.parts or ".pytest_cache" in f.parts:
                continue
            text = f.read_text(encoding="utf-8", errors="ignore")
            for pat in secret_patterns:
                if pat.search(text):
                    violations.append(str(f.relative_to(core_root)))
        self.assertEqual(violations, [], f"Found production tokens in files: {violations}")


if __name__ == "__main__":
    unittest.main()
