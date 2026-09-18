import pytest
from pathlib import Path
from unittest.mock import MagicMock, patch
from typer.testing import CliRunner

from ctf_core.cli.main import app
from ctf_core.services.pull_service import PullService
from ctf_core.services.orchestrator import ChallengeOrchestrator
from ctf_core.models import CTFInfo, Challenge

runner = CliRunner()


def test_pull_service_contract_canonical():
    """Test PullService accepts both url and platform_url, and provides pull() alias."""
    # Using platform_url
    p1 = PullService(platform_url="http://localhost:8000", preload_all=False)
    assert p1.url == "http://localhost:8000"
    assert p1.download_attachments is False

    # Using url with preload_all=True
    p2 = PullService(url="http://localhost:8000", preload_all=True)
    assert p2.url == "http://localhost:8000"
    assert p2.preload_all is True
    assert p2.download_attachments is True

    # Check pull alias
    with patch.object(p2, "execute", return_value=CTFInfo(title="Test", challenges=[])) as mock_exec:
        res = p2.pull()
        assert mock_exec.called
        assert isinstance(res, CTFInfo)


def test_orchestrator_run_canonical_alias(tmp_path):
    """Test ChallengeOrchestrator provides run() alias for run_tournament_loop()."""
    orch = ChallengeOrchestrator(workspace_dir=tmp_path, platform_url="http://localhost:8000")
    with patch.object(orch, "run_tournament_loop") as mock_loop:
        orch.run(auto_wait_waves=False, poll_interval=10)
        mock_loop.assert_called_once_with(auto_wait_waves=False, poll_interval=10)


def test_cli_auto_invokes_orchestrator_correctly(tmp_path):
    """Test ctf auto passes executor_mode, allow_local_fallback, and allow_network."""
    with patch("ctf_core.cli.main.ChallengeOrchestrator") as MockOrch:
        mock_instance = MagicMock()
        MockOrch.return_value = mock_instance

        res = runner.invoke(app, [
            "auto",
            "-u", "http://localhost:8000",
            "-e", "restricted",
            "--allow-local-fallback",
            "--allow-network",
            "-m", "3",
        ])

        assert res.exit_code == 0
        MockOrch.assert_called_once()
        kwargs = MockOrch.call_args[1]
        assert kwargs["executor_mode"] == "restricted"
        assert kwargs["allow_local_fallback"] is True
        assert kwargs["allow_network"] is True
        assert kwargs["max_iterations_per_chall"] == 3
        mock_instance.run_tournament_loop.assert_called_once()


def test_cli_pull_invokes_pull_service_correctly(tmp_path):
    """Test ctf pull executes correctly without AttributeError or TypeError."""
    mock_ctf_info = CTFInfo(
        title="Test CTF",
        challenges=[
            Challenge(id="1", name="BabyPwn", category="pwn", points=100)
        ]
    )
    with patch("ctf_core.cli.main.PullService") as MockPull:
        mock_pull_instance = MagicMock()
        mock_pull_instance.execute.return_value = mock_ctf_info
        MockPull.return_value = mock_pull_instance

        res = runner.invoke(app, ["pull", "-u", "http://localhost:8000", "-a"])
        assert res.exit_code == 0
        MockPull.assert_called_once()
        kwargs = MockPull.call_args[1]
        assert kwargs["url"] == "http://localhost:8000"
        assert kwargs["preload_all"] is True
        mock_pull_instance.execute.assert_called_once()
