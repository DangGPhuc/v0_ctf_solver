import pytest
from pathlib import Path
from unittest.mock import MagicMock, patch
from typer.testing import CliRunner

from ctf_core.downloaders.manager import DownloadManager
from ctf_core.cli.main import app
from ctf_core.models import Challenge
from ctf_core.runtime.manager import RuntimeManager

runner = CliRunner()


def test_downloader_redirect_dest_file_and_credential_stripping(tmp_path):
    dm = DownloadManager(
        platform_url="https://ctf.example.com",
        session_cookie="secret_session=123",
        api_token="secret_token_abc",
    )

    # 1. Test cross-origin redirect strips credentials and passes dest_file
    mock_resp = MagicMock()
    mock_resp.is_redirect = True
    mock_resp.headers = {"Location": "https://s3.amazonaws.com/bucket/chall.zip"}

    with patch.object(dm.auth_client, "get", return_value=mock_resp), \
         patch.object(dm, "_stream_download", return_value=True) as mock_stream:
        out = dm.download_file("https://ctf.example.com/files/chall.zip", tmp_path)
        assert out is not None
        # Must call anon_client (NOT auth_client) for cross-origin!
        mock_stream.assert_called_once()
        client_arg, url_arg, dest_arg = mock_stream.call_args[0]
        assert client_arg == dm.anon_client
        assert url_arg == "https://s3.amazonaws.com/bucket/chall.zip"
        assert dest_arg == tmp_path / "chall.zip"

    # 2. Test same-origin redirect retains auth and passes dest_file
    mock_same_resp = MagicMock()
    mock_same_resp.is_redirect = True
    mock_same_resp.headers = {"Location": "https://ctf.example.com/cdn/chall.zip"}

    with patch.object(dm.auth_client, "get", return_value=mock_same_resp), \
         patch.object(dm, "_stream_download", return_value=True) as mock_stream:
        out = dm.download_file("https://ctf.example.com/files/chall.zip", tmp_path)
        assert out is not None
        # Must call auth_client for same-origin!
        mock_stream.assert_called_once()
        client_arg, url_arg, dest_arg = mock_stream.call_args[0]
        assert client_arg == dm.auth_client
        assert url_arg == "https://ctf.example.com/cdn/chall.zip"
        assert dest_arg == tmp_path / "chall.zip"


def test_solve_cmd_not_found_does_not_fabricate_challenge(tmp_path):
    """When challenge does not exist on platform and is not in runtime, solve must fail with NOT_FOUND."""
    with patch("ctf_core.cli.main.ChallengeOrchestrator") as MockOrch:
        mock_orch = MagicMock()
        mock_orch.event_id = "test_event"
        mock_orch.platform_url = "https://mock.ctf"
        mock_orch.sync_challenges.return_value = [
            {"id": "1", "name": "ExistingChall", "category": "pwn"}
        ]
        MockOrch.return_value = mock_orch

        # Challenge 999 does not exist
        res = runner.invoke(app, ["solve", "999", "-u", "https://mock.ctf"])
        assert res.exit_code != 0
        assert "NOT_FOUND" in res.stdout
        # Orchestrator execute_challenge_cycle must NEVER be called with fabricated challenge!
        mock_orch.execute_challenge_cycle.assert_not_called()


def test_solve_cmd_runtime_only_resume(tmp_path):
    """When challenge exists in local ephemeral runtime, solve resumes without fabricating fake metadata."""
    rt = RuntimeManager(base_dir=tmp_path / ".runtime")
    rt.materialize_challenge(
        "test_event",
        Challenge(id="local_chall", name="MaterializedLocal", category="rev", points=250)
    )

    with patch("ctf_core.cli.main.RuntimeManager", return_value=rt), \
         patch("ctf_core.cli.main.ChallengeOrchestrator") as MockOrch:
        mock_orch = MagicMock()
        mock_orch.event_id = "test_event"
        mock_orch.platform_url = "https://mock.ctf"
        # Platform returns empty (e.g. offline or unlisted)
        mock_orch.sync_challenges.return_value = []
        mock_orch.execute_challenge_cycle.return_value = True
        MockOrch.return_value = mock_orch

        res = runner.invoke(app, ["solve", "local_chall", "-u", "https://mock.ctf"])
        assert res.exit_code == 0
        assert "RUNTIME_ONLY_RESUME" in res.stdout
        mock_orch.execute_challenge_cycle.assert_called_once()
        target = mock_orch.execute_challenge_cycle.call_args[0][0]
        assert target["id"] == "local_chall"
        assert target["name"] == "MaterializedLocal"
        assert target["category"] == "rev"
        assert target["points"] == 250
