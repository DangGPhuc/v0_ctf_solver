import pytest
from pathlib import Path
from unittest.mock import patch, MagicMock

from ctf_core.execution.artifacts import ArtifactResolver, ArtifactResolutionError
from ctf_core.execution.restricted_executor import RestrictedLocalExecutor
from ctf_core.execution.container_executor import ContainerExecutor
from ctf_core.models import AdvisorGuidance, ExecutionAction


def test_artifact_resolver_logical_specs(tmp_path):
    input_dir = tmp_path / "input"
    work_dir = tmp_path / "work"
    input_dir.mkdir()
    work_dir.mkdir()

    (input_dir / "vuln").write_text("dummy binary")
    (work_dir / "solve.py").write_text("print('hello')")

    # Local resolution
    assert ArtifactResolver.resolve_local("input:vuln", input_dir, work_dir) == input_dir / "vuln"
    assert ArtifactResolver.resolve_local("work:solve.py", input_dir, work_dir) == work_dir / "solve.py"
    assert ArtifactResolver.resolve_local("vuln", input_dir, work_dir) == input_dir / "vuln"
    assert ArtifactResolver.resolve_local("solve.py", input_dir, work_dir) == work_dir / "solve.py"

    # Container resolution
    assert ArtifactResolver.resolve_container("input:vuln", input_dir, work_dir) == "/input/vuln"
    assert ArtifactResolver.resolve_container("work:solve.py", input_dir, work_dir) == "/work/solve.py"
    assert ArtifactResolver.resolve_container("vuln", input_dir, work_dir) == "/input/vuln"


def test_artifact_resolver_traversal_blocked(tmp_path):
    input_dir = tmp_path / "input"
    work_dir = tmp_path / "work"
    input_dir.mkdir()
    work_dir.mkdir()

    with pytest.raises(ArtifactResolutionError):
        ArtifactResolver.resolve_local("input:../../etc/passwd", input_dir, work_dir)

    with pytest.raises(ArtifactResolutionError):
        ArtifactResolver.resolve_local("work:../../etc/passwd", input_dir, work_dir)

    with pytest.raises(ArtifactResolutionError):
        ArtifactResolver.resolve_container("input:../../etc/passwd", input_dir, work_dir)


def test_artifact_resolver_argv_translation(tmp_path):
    input_dir = tmp_path / "input"
    work_dir = tmp_path / "work"
    input_dir.mkdir()
    work_dir.mkdir()

    # Container translation
    raw_argv = ["checksec", "--file=input:vuln", "work:output.log"]
    c_argv = ArtifactResolver.translate_argv(raw_argv, input_dir, work_dir, in_container=True)
    assert c_argv == ["checksec", "--file=/input/vuln", "/work/output.log"]

    # Local translation
    l_argv = ArtifactResolver.translate_argv(raw_argv, input_dir, work_dir, in_container=False)
    assert l_argv == ["checksec", f"--file={input_dir / 'vuln'}", str(work_dir / "output.log")]


def test_restricted_executor_run_sage_file(tmp_path):
    input_dir = tmp_path / "input"
    work_dir = tmp_path / "work"
    input_dir.mkdir()
    work_dir.mkdir()

    sage_script = work_dir / "solve.sage"
    sage_script.write_text("print('FLAG{sage_test_flag}')")

    context = {
        "challenge_id": "crypto1",
        "work_dir": work_dir,
        "input_dir": input_dir,
    }
    guidance = AdvisorGuidance(
        assessment="Run sage script",
        execution_plan=[
            ExecutionAction(kind="run_sage_file", path="work:solve.sage")
        ]
    )

    executor = RestrictedLocalExecutor(flag_format_regex=r"FLAG\{[^\}]+\}")

    # Case 1: sage is not installed on host PATH
    with patch("shutil.which", return_value=None):
        res = executor.execute(context, guidance)
        assert res.status == "ERROR"
        assert "SageMath executable ('sage') not installed" in res.observed

    # Case 2: sage is mocked as available
    with patch("shutil.which", return_value="/usr/bin/sage"), \
         patch("subprocess.run") as mock_run:
        mock_proc = MagicMock()
        mock_proc.returncode = 0
        mock_proc.stdout = "FLAG{sage_test_flag}\n"
        mock_proc.stderr = ""
        mock_run.return_value = mock_proc

        res = executor.execute(context, guidance)
        assert res.status == "FLAG_FOUND"
        assert "FLAG{sage_test_flag}" in res.flag_candidates

