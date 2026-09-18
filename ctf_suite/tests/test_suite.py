import os
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock

from ctf_core.config import CTFSettings, load_config, save_env_file, find_env_file
from ctf_core.models import Challenge, ContainerInfo, CTFInfo, SubmitResult
from ctf_core.runtime.manager import RuntimeManager
from ctf_core.services.instance_service import InstanceService
from ctf_core.services.submit_service import SubmitService
from ctf_core.services.advisor_service import AdvisorService


class TestCTFSuite(unittest.TestCase):
    def setUp(self):
        self.test_dir = Path(tempfile.mkdtemp())
        self.runtime_manager = RuntimeManager(base_dir=self.test_dir / ".runtime")
        self.event_id = "test_event"

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_config_and_env(self):
        """Test nạp và lưu tệp .env"""
        env_file = self.test_dir / ".env"
        save_env_file(env_file, {
            "PLATFORM_URL": "https://ctf.example.com",
            "SESSION_COOKIE": "session=abc123xyz",
            "FLAG_FORMAT": r"^CTF\{.+\}$"
        })
        self.assertTrue(env_file.is_file())

        cfg = load_config(explicit_env=env_file)
        self.assertEqual(cfg.platform_url, "https://ctf.example.com")
        self.assertEqual(cfg.session_cookie, "session=abc123xyz")
        self.assertEqual(cfg.flag_format, r"^CTF\{.+\}$")

    def test_runtime_manager_materialize(self):
        """Test khởi tạo ephemeral challenge runtime (input, work, solve.py, state.json)"""
        chall = Challenge(
            id=101,
            name="Buffer Overflow 101",
            category="Pwn",
            points=150,
            description="Exploit the buffer!",
            connection_info="nc 10.10.10.5 9999"
        )
        chall_dir = self.runtime_manager.materialize_challenge(self.event_id, chall)

        self.assertTrue((chall_dir / "input").is_dir())
        self.assertTrue((chall_dir / "work").is_dir())
        self.assertTrue((chall_dir / "state.json").is_file())
        self.assertTrue((chall_dir / "work" / "solve.py").is_file())

        solve_code = (chall_dir / "work" / "solve.py").read_text(encoding="utf-8")
        self.assertIn("10.10.10.5", solve_code)
        self.assertIn("9999", solve_code)

    def test_instance_service_autopatch(self):
        """Test bật container và tự động patch HOST:PORT vào work/solve.py trong runtime"""
        chall = Challenge(
            id=42,
            name="SQLi Baby",
            category="Web",
            points=100,
            description="Web challenge",
            connection_info="http://old-target.ctf"
        )
        chall_dir = self.runtime_manager.materialize_challenge(self.event_id, chall)

        service = InstanceService(
            workspace_dir=self.test_dir,
            platform_url="http://mock.ctf",
            platform_type="ctfd",
            runtime_manager=self.runtime_manager,
            event_id=self.event_id
        )
        service.platform.start_instance = MagicMock(return_value=ContainerInfo(
            status="running",
            entry="192.168.1.50:31337",
            host="192.168.1.50",
            port=31337
        ))

        info = service.start(42)
        self.assertEqual(info.status, "running")

        # Kiểm tra work/solve.py đã được cập nhật
        solve_content = (chall_dir / "work" / "solve.py").read_text(encoding="utf-8")
        self.assertIn("192.168.1.50", solve_content)
        self.assertIn("31337", solve_content)

    def test_submit_service_immediate_and_alert(self):
        """Test nộp flag tức thì, cập nhật runtime state và masked flag ledger"""
        chall = Challenge(
            id=77,
            name="Super Crypto",
            category="Crypto",
            points=200
        )
        self.runtime_manager.materialize_challenge(self.event_id, chall)

        service = SubmitService(
            workspace_dir=self.test_dir,
            platform_url="http://mock.ctf",
            flag_format=r"^FLAG\{.+\}$",
            platform_type="ctfd",
            runtime_manager=self.runtime_manager,
            event_id=self.event_id
        )

        # 1. Test nộp thành công
        service.platform.submit_flag = MagicMock(return_value=SubmitResult(
            verdict="correct",
            message="Chính xác!",
            challenge_id=77,
            flag="FLAG{crypto_win}"
        ))
        res = service.submit(77, "FLAG{crypto_win}")
        self.assertEqual(res.verdict, "correct")

        # Kiểm tra đã đánh dấu solved trong runtime state
        state = self.runtime_manager.read_challenge_state(self.event_id, 77)
        self.assertTrue(state.get("solved"))

        # 2. Test nộp thất bại -> Ghi log failed_flags.jsonl với MASKED FLAG (không lộ plaintext)
        service.platform.submit_flag = MagicMock(return_value=SubmitResult(
            verdict="ratelimited",
            message="Too many attempts",
            challenge_id=77,
            flag="FLAG{rate_limited_secret}"
        ))
        res_fail = service.submit(77, "FLAG{rate_limited_secret}")
        self.assertEqual(res_fail.verdict, "ratelimited")

        log_file = self.runtime_manager.event_path(self.event_id) / ".failed_flags.jsonl"
        self.assertTrue(log_file.is_file())
        log_content = log_file.read_text(encoding="utf-8")
        self.assertNotIn("FLAG{rate_limited_secret}", log_content, "Plaintext flag must NEVER be logged")
        self.assertIn("flag_masked", log_content)
        self.assertIn("flag_hash", log_content)

    def test_advisor_service_runtime_initialization(self):
        """Test AdvisorService khởi tạo .advisor/ trong ephemeral challenge runtime"""
        chall = Challenge(
            id=99,
            name="Blind SQLi",
            category="Web",
            points=250,
            description="Can you extract admin password?",
            hints=[{"content": "Try time based"}]
        )
        chall_dir = self.runtime_manager.materialize_challenge(self.event_id, chall)

        advisor = AdvisorService(
            workspace_dir=self.test_dir,
            runtime_manager=self.runtime_manager,
            event_id=self.event_id
        )
        res = advisor.init_challenge_advisor(99)

        advisor_dir = chall_dir / ".advisor"
        self.assertTrue(advisor_dir.is_dir())
        self.assertTrue((advisor_dir / "state.json").is_file())
        self.assertTrue((advisor_dir / "findings.md").is_file())
        self.assertTrue((advisor_dir / "hypotheses.md").is_file())
        self.assertTrue((advisor_dir / "guidance.md").is_file())


if __name__ == "__main__":
    unittest.main()
