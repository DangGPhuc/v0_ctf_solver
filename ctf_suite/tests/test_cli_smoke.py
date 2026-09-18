import pytest
from unittest.mock import patch, MagicMock
from typer.testing import CliRunner

from ctf_core.cli.main import app
from ctf_core.models import CTFInfo, Challenge

runner = CliRunner()


def test_cli_smoke_help():
    res = runner.invoke(app, ["--help"])
    assert res.exit_code == 0
    assert "Autonomous CTF Lifecycle" in res.stdout


def test_cli_smoke_list():
    mock_platform = MagicMock()
    mock_platform.list_challenges.return_value = [
        Challenge(id="1", name="SmokeChall", category="pwn", points=100)
    ]
    with patch("ctf_core.cli.main.create_platform", return_value=mock_platform):
        res = runner.invoke(app, ["list", "-u", "http://smoke.ctf"])
        assert res.exit_code == 0
        assert "SmokeChall" in res.stdout


def test_cli_smoke_pull():
    mock_info = CTFInfo(
        title="Smoke CTF",
        challenges=[Challenge(id="1", name="SmokeChall", category="pwn", points=100)]
    )
    with patch("ctf_core.cli.main.PullService") as MockPull:
        mock_instance = MagicMock()
        mock_instance.execute.return_value = mock_info
        MockPull.return_value = mock_instance

        res = runner.invoke(app, ["pull", "-u", "http://smoke.ctf"])
        assert res.exit_code == 0
        assert "Đã đồng bộ thành công" in res.stdout


def test_cli_smoke_auto():
    with patch("ctf_core.cli.main.ChallengeOrchestrator") as MockOrch:
        mock_orch = MagicMock()
        MockOrch.return_value = mock_orch

        res = runner.invoke(app, ["auto", "-u", "http://smoke.ctf", "-m", "1"])
        assert res.exit_code == 0
        mock_orch.run_tournament_loop.assert_called_once()


def test_cli_smoke_triage(tmp_path):
    with patch("ctf_core.cli.main.RuntimeManager") as MockRT:
        mock_rt = MagicMock()
        mock_rt.list_events.return_value = ["test_event"]
        mock_rt.read_challenge_state.return_value = {
            "name": "SmokeTriage",
            "category": "pwn",
            "description": "Buffer overflow with ROP gadgets",
        }
        mock_rt.event_path.return_value = tmp_path
        MockRT.return_value = mock_rt

        res = runner.invoke(app, ["triage", "1"])
        assert res.exit_code == 0
        assert "PWN" in res.stdout


def test_cli_smoke_knowledge_doctor():
    with patch("ctf_core.knowledge.github_provider.GitHubKnowledgeProvider.check_doctor") as mock_doc:
        mock_doc.return_value = {
            "provider": "github",
            "repo": "DangGPhuc/v0_ctf_knowledge",
            "ref": "main",
            "authenticated": True,
            "remote_reachable": True,
            "cache_status": "fresh",
            "index_entry_count": 12,
            "last_sync": "2026-09-18T10:00:00Z",
            "ttl_seconds": 3600,
        }
        res = runner.invoke(app, ["knowledge", "doctor"])
        assert res.exit_code == 0
        assert "Knowledge Subsystem Diagnostics" in res.stdout
