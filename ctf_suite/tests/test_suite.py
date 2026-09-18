import os
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from ctf_core.config import CTFSettings, load_config, save_env_file, find_env_file
from ctf_core.models import Challenge, ContainerInfo, CTFInfo, SubmitResult
from ctf_core.workspace.builder import WorkspaceBuilder
from ctf_core.workspace.repo import WorkspaceRepo
from ctf_core.services.instance_service import InstanceService
from ctf_core.services.submit_service import SubmitService

class TestCTFSuite(unittest.TestCase):
    def setUp(self):
        self.test_dir = Path(tempfile.mkdtemp())

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

    def test_workspace_builder(self):
        """Test khởi tạo workspace 4 tầng chuẩn (challenge, script, solver, writeup)"""
        chall = Challenge(
            id=101,
            name="Buffer Overflow 101",
            category="Pwn",
            points=150,
            description="Exploit the buffer!",
            connection_info="nc 10.10.10.5 9999"
        )
        chall_dir = WorkspaceBuilder.create_challenge_workspace(self.test_dir, chall)
        
        self.assertTrue((chall_dir / "challenge" / "README.md").is_file())
        self.assertTrue((chall_dir / "challenge" / "metadata.json").is_file())
        self.assertTrue((chall_dir / "script").is_dir())
        self.assertTrue((chall_dir / "solver" / "solve.py").is_file())
        self.assertTrue((chall_dir / "writeup" / "README.md").is_file())

        solve_code = (chall_dir / "solver" / "solve.py").read_text(encoding="utf-8")
        self.assertIn("HOST = \"10.10.10.5\"", solve_code)
        self.assertIn("PORT = 9999", solve_code)
        self.assertIn("from pwn import *", solve_code)

    def test_instance_service_autopatch(self):
        """Test bật container và tự động patch HOST:PORT vào solve.py"""
        chall = Challenge(
            id=42,
            name="SQLi Baby",
            category="Web",
            points=100,
            description="Web challenge",
            connection_info="http://old-target.ctf"
        )
        chall_dir = WorkspaceBuilder.create_challenge_workspace(self.test_dir, chall)
        repo = WorkspaceRepo(self.test_dir)
        repo.write_challenges({"challenges": [chall.model_dump()]})

        service = InstanceService(
            workspace_dir=self.test_dir,
            platform_url="http://mock.ctf",
            platform_type="ctfd"
        )
        # Mock platform.start_instance trả về host:port mới
        service.platform.start_instance = MagicMock(return_value=ContainerInfo(
            status="running",
            entry="192.168.1.50:31337",
            host="192.168.1.50",
            port=31337
        ))

        info = service.start(42)
        self.assertEqual(info.status, "running")

        # Kiểm tra solve.py đã được cập nhật
        solve_content = (chall_dir / "solver" / "solve.py").read_text(encoding="utf-8")
        readme_content = (chall_dir / "challenge" / "README.md").read_text(encoding="utf-8")
        
        self.assertIn("nc 192.168.1.50 31337", readme_content)

    def test_submit_service_immediate_and_alert(self):
        """Test nộp flag tức thì, cập nhật solved và cảnh báo khi thất bại"""
        chall = Challenge(
            id=77,
            name="Super Crypto",
            category="Crypto",
            points=200
        )
        WorkspaceBuilder.create_challenge_workspace(self.test_dir, chall)
        repo = WorkspaceRepo(self.test_dir)
        repo.write_challenges({"challenges": [chall.model_dump()]})

        service = SubmitService(
            workspace_dir=self.test_dir,
            platform_url="http://mock.ctf",
            flag_format=r"^FLAG\{.+\}$",
            platform_type="ctfd"
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
        
        # Kiểm tra đã đánh dấu solved trong challenges.json
        updated = repo.read_challenges()
        self.assertTrue(updated["challenges"][0]["solved_by_me"])

        # 2. Test nộp thất bại (Rate limit) -> Ghi log failed_flags.log
        service.platform.submit_flag = MagicMock(return_value=SubmitResult(
            verdict="ratelimited",
            message="Too many attempts",
            challenge_id=77,
            flag="FLAG{rate_limited}"
        ))
        res_fail = service.submit(77, "FLAG{rate_limited}")
        self.assertEqual(res_fail.verdict, "ratelimited")
        
        log_file = self.test_dir / ".failed_flags.log"
        self.assertTrue(log_file.is_file())
        self.assertIn("FLAG{rate_limited}", log_file.read_text(encoding="utf-8"))

    def test_chatgpt_service(self):
        """Test sinh Prompt cho ChatGPT và đồng bộ sang reverse-skill"""
        chall = Challenge(
            id=99,
            name="Blind SQLi",
            category="Web",
            points=250,
            description="Can you extract admin password?",
            hints=[{"content": "Try time based"}]
        )
        chall_dir = WorkspaceBuilder.create_challenge_workspace(self.test_dir, chall)
        repo = WorkspaceRepo(self.test_dir)
        repo.write_challenges({"challenges": [chall.model_dump()]})

        rs_dir = self.test_dir / "mock_reverse_skill"
        rs_dir.mkdir()

        from ctf_core.services.chatgpt_service import ChatGPTService
        service = ChatGPTService(workspace_dir=self.test_dir, reverse_skill_dir=rs_dir)
        res = service.prepare_triage_prompt(99)

        self.assertTrue(res["prompt_file"].is_file())
        self.assertIn("Blind SQLi", res["prompt_text"])
        self.assertIn("Try time based", res["prompt_text"])

        # Kiểm tra đồng bộ sang reverse-skill
        rs_prompt = rs_dir / "work" / "web" / "Blind_SQLi" / "chatgpt_prompt.md"
        self.assertTrue(rs_prompt.is_file())

        # Test lưu guidance
        service.save_chatgpt_guidance(99, "## Hướng giải: Sử dụng SLEEP(5)")
        guidance_file = chall_dir / "script" / "chatgpt_guidance.md"
        self.assertTrue(guidance_file.is_file())
        self.assertIn("SLEEP(5)", guidance_file.read_text(encoding="utf-8"))

    def test_chatgpt_deadlock_escalation(self):
        """Test quy trình đóng gói Deadlock Escalation Prompt và đồng bộ reverse-skill"""
        chall = Challenge(
            id=105,
            name="Custom Crypto Vault",
            category="Crypto",
            points=400,
            description="Decrypt the cipher vault",
        )
        chall_dir = WorkspaceBuilder.create_challenge_workspace(self.test_dir, chall)
        repo = WorkspaceRepo(self.test_dir)
        repo.write_challenges({"challenges": [chall.model_dump()]})

        rs_dir = self.test_dir / "mock_reverse_skill_deadlock"
        rs_dir.mkdir()

        from ctf_core.services.chatgpt_service import ChatGPTService
        service = ChatGPTService(workspace_dir=self.test_dir, reverse_skill_dir=rs_dir)

        # Kích hoạt Deadlock Escalation
        res = service.prepare_deadlock_prompt(
            challenge_id=105,
            progress="Đã bóc tách ma trận hoán vị 64x64",
            blocker="Z3 solver timeout sau 120s và không gian mẫu 2^48",
            failed_attempts="Thử brute-force byte đầu; Thử Z3 trực tiếp",
            error_trace="z3.z3types.Z3Exception: timeout",
            code_snippet="s = Solver(); s.set('timeout', 120000)"
        )

        # Kiểm tra file sinh ra trong workspace
        deadlock_file = chall_dir / "script" / "chatgpt_deadlock_prompt.md"
        self.assertTrue(deadlock_file.is_file())
        self.assertEqual(res["prompt_file"], deadlock_file)
        
        prompt_content = deadlock_file.read_text(encoding="utf-8")
        self.assertIn("BẾ TẮC NGHIÊM TRỌNG", prompt_content)
        self.assertIn("Đã bóc tách ma trận hoán vị 64x64", prompt_content)
        self.assertIn("Z3 solver timeout sau 120s và không gian mẫu 2^48", prompt_content)
        self.assertIn("Thử brute-force byte đầu", prompt_content)
        self.assertIn("z3.z3types.Z3Exception: timeout", prompt_content)

        # Kiểm tra đồng bộ sang reverse-skill/work/crypto/Custom_Crypto_Vault/
        rs_deadlock = rs_dir / "work" / "crypto" / "Custom_Crypto_Vault" / "chatgpt_deadlock_prompt.md"
        self.assertTrue(rs_deadlock.is_file())

        # Kiểm tra lưu metadata deadlock
        meta = repo.read_challenge_metadata(chall_dir)
        self.assertEqual(len(meta.get("deadlock_history", [])), 1)
        self.assertEqual(meta["deadlock_history"][0]["blocker"], "Z3 solver timeout sau 120s và không gian mẫu 2^48")

if __name__ == "__main__":
    unittest.main()


