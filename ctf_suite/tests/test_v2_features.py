import os
import stat
import shutil
import tempfile
import unittest
from pathlib import Path

from ctf_core.config import save_env_file, load_config
from ctf_core.downloaders.manager import DownloadManager
from ctf_core.services.submit_service import SubmitService
from ctf_core.models import SubmitResult
from ctf_core.platforms.cyberhx import CyberHXPlatform

class TestV2Features(unittest.TestCase):
    def setUp(self):
        self.test_dir = Path(tempfile.mkdtemp())

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_downloader_path_traversal_sanitization(self):
        """Kiểm tra Downloader chặn đứng Path Traversal và sanitize filename."""
        dm = DownloadManager()
        safe_name = dm._sanitize_filename("../../etc/passwd")
        self.assertEqual(safe_name, "passwd")

        safe_name2 = dm._sanitize_filename("/root/.ssh/id_rsa")
        self.assertEqual(safe_name2, "id_rsa")

        safe_name3 = dm._sanitize_filename("..\\..\\windows\\system32\\calc.exe")
        self.assertNotIn("..", safe_name3)

        dm.close()

    def test_env_file_security_and_permissions(self):
        """Kiểm tra hàm save_env_file luôn thiết lập chmod 0600."""
        env_file = self.test_dir / ".env"
        save_env_file(env_file, {
            "API_TOKEN": "secret_access_token",
            "REFRESH_TOKEN": "secret_refresh_token",
            "TOKEN_EXPIRES_AT": 1789799999.0
        })

        self.assertTrue(env_file.exists())
        mode = stat.S_IMODE(os.stat(env_file).st_mode)
        self.assertEqual(mode, 0o600, f"Quyền tệp .env phải là 0600 nhưng nhận được {oct(mode)}")

        cfg = load_config(explicit_env=env_file)
        self.assertEqual(cfg.api_token, "secret_access_token")
        self.assertEqual(cfg.refresh_token, "secret_refresh_token")
        self.assertEqual(cfg.token_expires_at, 1789799999.0)

    def test_strict_flag_validation(self):
        """Kiểm tra van an toàn nộp flag: từ chối placeholder và kiểm tra regex fullmatch."""
        service = SubmitService(
            workspace_dir=self.test_dir,
            platform_url="https://ctf.example.com",
            flag_format=r"^Null0rigin\{[a-zA-Z0-9_\-]+\}$",
            platform_type="ctfd"
        )

        # Hợp lệ
        self.assertTrue(service.validate_format("Null0rigin{web_sqli_bypass_123}"))

        # Sai regex
        self.assertFalse(service.validate_format("FLAG{wrong_prefix}"))

        # Placeholders bị cấm
        self.assertFalse(service.validate_format("Null0rigin{...}"))
        self.assertFalse(service.validate_format("flag{...}"))
        self.assertFalse(service.validate_format("Null0rigin{flag_here}"))

        # Chuỗi rác / xuống dòng
        self.assertFalse(service.validate_format("I think the flag is Null0rigin{abc}"))
        self.assertFalse(service.validate_format("Null0rigin{abc}\nsome other text"))

    def test_submission_dedup_ledger(self):
        """Kiểm tra sổ cái deduplication submitted_flags.jsonl."""
        service = SubmitService(
            workspace_dir=self.test_dir,
            platform_url="https://ctf.example.com",
            flag_format=r"^FLAG\{.+\}$",
            platform_type="ctfd"
        )

        # Ban đầu chưa nộp
        self.assertIsNone(service.has_been_submitted("chall_1", "FLAG{test_1}"))

        # Ghi nhận kết quả
        mock_res = SubmitResult(verdict="incorrect", message="Wrong flag", challenge_id="chall_1", flag="FLAG{test_1}")
        service._record_submission("chall_1", "FLAG{test_1}", mock_res)

        # Kiểm tra lại ledger
        prev = service.has_been_submitted("chall_1", "FLAG{test_1}")
        self.assertEqual(prev, "incorrect")

        # Flag khác chưa nộp
        self.assertIsNone(service.has_been_submitted("chall_1", "FLAG{test_2}"))

    def test_jwt_exp_decoding(self):
        """Kiểm tra giải mã exp từ token JWT."""
        platform = CyberHXPlatform(url="https://ctf.cyberhx.com")
        
        # Tạo sample payload base64: {"exp": 1789799999, "email": "test@cyberhx.com"}
        import base64
        import json
        payload = {"exp": 1789799999, "email": "test@cyberhx.com"}
        payload_b64 = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=")
        dummy_jwt = f"header.{payload_b64}.signature"

        decoded_exp = platform._decode_jwt_exp(dummy_jwt)
        self.assertEqual(decoded_exp, 1789799999.0)
        platform.close()

if __name__ == "__main__":
    unittest.main()
