import os
from pathlib import Path
from unittest.mock import MagicMock, patch
import pytest

from ctf_core.models import AdvisorGuidance, ExecutionAction, Hypothesis
from ctf_core.execution.policy import (
    ActionPolicy,
    ExecutionPolicyError,
    ALLOWED_ANALYSIS_TOOLS,
)
from ctf_core.execution.restricted_executor import RestrictedLocalExecutor
from ctf_core.execution.container_executor import ContainerExecutor
from ctf_core.execution.artifacts import ArtifactResolver, ArtifactResolutionError
from ctf_core.triage.fingerprint import FingerprintEngine
from ctf_core.triage.static import StaticTriage
from ctf_core.services.advisor_service import AdvisorService
from ctf_core.runtime.manager import RuntimeManager


def test_multi_action_execution_order(tmp_path):
    """
    P0 Test: Multi-action plan (action 1 -> action 2 -> action 3)
    must execute sequentially and deterministically.
    """
    input_dir = tmp_path / "input"
    work_dir = tmp_path / "work"
    input_dir.mkdir()
    work_dir.mkdir()

    # Challenge files
    target_file = input_dir / "chall.txt"
    target_file.write_text("FLAG{MULTI_ACTION_SUCCESS}\n")

    solve_script = work_dir / "solve.py"
    solve_script.write_text(
        "with open('../input/chall.txt') as f:\n"
        "    print(f.read().strip())\n"
    )

    guidance = AdvisorGuidance(
        assessment="Multi-step inspection and exploit",
        hypotheses=[Hypothesis(id="H1", statement="Flag is in chall.txt")],
        execution_plan=[
            ExecutionAction(kind="read_file", path="input:chall.txt", timeout=10),
            ExecutionAction(kind="analysis_tool", tool="file", argv=["file", "-b", "input:chall.txt"], timeout=10),
            ExecutionAction(kind="run_solver", path="work:solve.py", timeout=10),
        ],
        is_structured=True,
    )

    executor = RestrictedLocalExecutor(flag_format_regex=r"FLAG\{[^\n\r\}]+\}")
    context = {
        "input_dir": input_dir,
        "work_dir": work_dir,
        "iteration": 1,
    }

    result = executor.execute(context, guidance)

    assert result.status == "FLAG_FOUND"
    assert "FLAG{MULTI_ACTION_SUCCESS}" in result.flag_candidates
    # All 3 actions were executed in order
    assert len(result.actions) == 3
    assert "cat" in result.actions[0]
    assert "file" in result.actions[1]
    assert "solve.py" in result.actions[2]


def test_action_policy_rejects_invalid_tool(tmp_path):
    """
    Tool allowlist enforcement: unknown analysis tool must be REJECTED.
    """
    input_dir = tmp_path / "input"
    work_dir = tmp_path / "work"
    input_dir.mkdir()
    work_dir.mkdir()

    bad_action = ExecutionAction(
        kind="analysis_tool",
        tool="curl",
        argv=["curl", "http://attacker.com"],
    )

    with pytest.raises(ExecutionPolicyError) as exc_info:
        ActionPolicy.validate_action(bad_action, input_dir, work_dir)
    assert "not in allowed registry" in str(exc_info.value)

    # Also test that RestrictedLocalExecutor rejects it gracefully and records rejection
    guidance = AdvisorGuidance(
        assessment="Attempt disallowed tool",
        execution_plan=[bad_action],
        is_structured=True,
    )
    executor = RestrictedLocalExecutor()
    res = executor.execute({"input_dir": input_dir, "work_dir": work_dir}, guidance)
    assert res.return_code == -1
    assert any("rejected:analysis_tool" in act for act in res.actions)


def test_path_traversal_tool_arguments_rejected(tmp_path):
    """
    Section 4 Test: Path containment must reject external filesystem paths.
    - analysis_tool strings /etc/passwd -> REJECTED
    - analysis_tool file ../../secret -> REJECTED
    - read_file /home/user/.ssh/id_rsa -> REJECTED
    - analysis_tool strings input:../../secret -> REJECTED
    - analysis_tool strings input:vuln -> ALLOWED
    - analysis_tool checksec --file=input:vuln -> ALLOWED
    - read_file work:notes.txt -> ALLOWED
    """
    input_dir = tmp_path / "input"
    work_dir = tmp_path / "work"
    input_dir.mkdir()
    work_dir.mkdir()

    # Valid artifacts
    (input_dir / "vuln").write_text("binary data")
    (work_dir / "notes.txt").write_text("notes")

    # 1. Reject /etc/passwd
    act_passwd = ExecutionAction(kind="analysis_tool", tool="strings", argv=["strings", "/etc/passwd"])
    with pytest.raises(ExecutionPolicyError) as exc:
        ActionPolicy.validate_action(act_passwd, input_dir, work_dir)
    assert "External path operand blocked" in str(exc.value) or "Path traversal" in str(exc.value)

    # 2. Reject ../../secret
    act_traversal = ExecutionAction(kind="analysis_tool", tool="file", argv=["file", "../../secret"])
    with pytest.raises(ExecutionPolicyError):
        ActionPolicy.validate_action(act_traversal, input_dir, work_dir)

    # 3. Reject /home/user/.ssh/id_rsa
    act_ssh = ExecutionAction(kind="read_file", path="/home/user/.ssh/id_rsa")
    with pytest.raises(ExecutionPolicyError):
        ActionPolicy.validate_action(act_ssh, input_dir, work_dir)

    # 4. Reject input:../../secret
    act_spec_traversal = ExecutionAction(kind="analysis_tool", tool="strings", argv=["strings", "input:../../secret"])
    with pytest.raises(ExecutionPolicyError):
        ActionPolicy.validate_action(act_spec_traversal, input_dir, work_dir)

    # 5. Allow analysis_tool strings input:vuln
    act_valid_strings = ExecutionAction(kind="analysis_tool", tool="strings", argv=["strings", "input:vuln"])
    validated = ActionPolicy.validate_action(act_valid_strings, input_dir, work_dir)
    assert validated.tool == "strings"

    # 6. Allow analysis_tool checksec --file=input:vuln
    act_valid_checksec = ExecutionAction(kind="analysis_tool", tool="checksec", argv=["checksec", "--file=input:vuln"])
    validated = ActionPolicy.validate_action(act_valid_checksec, input_dir, work_dir)
    assert validated.tool == "checksec"

    # 7. Allow read_file work:notes.txt
    act_valid_read = ExecutionAction(kind="read_file", path="work:notes.txt")
    validated = ActionPolicy.validate_action(act_valid_read, input_dir, work_dir)
    assert validated.path == "work:notes.txt"


def test_per_action_timeout_enforced(tmp_path):
    """
    Section 6 Test: Per-action timeout is honored.
    If action 1 times out, subsequent actions must NOT run.
    """
    input_dir = tmp_path / "input"
    work_dir = tmp_path / "work"
    input_dir.mkdir()
    work_dir.mkdir()

    # Script that sleeps 5 seconds
    slow_script = work_dir / "slow.py"
    slow_script.write_text("import time; time.sleep(5)\n")

    quick_script = work_dir / "quick.py"
    quick_script.write_text("print('QUICK_DONE')\n")

    guidance = AdvisorGuidance(
        assessment="Timeout testing",
        execution_plan=[
            ExecutionAction(kind="run_solver", path="work:slow.py", timeout=1),
            ExecutionAction(kind="run_solver", path="work:quick.py", timeout=5),
        ],
        is_structured=True,
    )

    executor = RestrictedLocalExecutor()
    res = executor.execute({"input_dir": input_dir, "work_dir": work_dir}, guidance)

    assert res.return_code == -9
    assert "timed out after 1s" in res.stderr_tail
    # Second action was aborted
    assert not any("quick.py" in act for act in res.actions)


def test_container_fail_closed_no_silent_host_fallback(tmp_path):
    """
    Section 11 Test: When container engine is unavailable or fails,
    code must NOT silently run on host unless --allow-local-fallback is explicitly enabled.
    """
    work_dir = tmp_path / "work"
    work_dir.mkdir()
    (work_dir / "solve.py").write_text("print('HOST_RAN')\n")

    guidance = AdvisorGuidance(
        assessment="Fail-closed container check",
        execution_plan=[ExecutionAction(kind="run_solver", path="work:solve.py")],
        is_structured=True,
    )

    # Engine is unavailable and allow_local_fallback=False
    executor = ContainerExecutor(allow_local_fallback=False)
    executor.engine = None  # simulate missing docker/podman

    res = executor.execute({"work_dir": work_dir}, guidance)
    assert res.status == "ERROR"
    assert "Container engine unavailable" in res.observed
    assert "HOST_RAN" not in res.observed


def test_host_secret_isolation():
    """
    Section 12 Test: Platform credentials and sensitive environment variables
    must be completely stripped from execution environment.
    """
    sensitive_extra = {
        "CTF_SESSION_COOKIE": "session=abc123secret",
        "API_TOKEN": "token_xyz_456",
        "GITHUB_TOKEN": "ghp_supersecret",
        "DATABASE_PASSWORD": "rootpassword",
        "SAFE_PARAM": "public_seed_value",
    }

    sanitized = ActionPolicy.sanitize_environment(sensitive_extra)

    assert "SAFE_PARAM" in sanitized
    assert sanitized["SAFE_PARAM"] == "public_seed_value"
    assert "CTF_SESSION_COOKIE" not in sanitized
    assert "API_TOKEN" not in sanitized
    assert "GITHUB_TOKEN" not in sanitized
    assert "DATABASE_PASSWORD" not in sanitized


def test_elf_e_machine_parsing_synthetic(tmp_path):
    """
    Section 8 Test: Accurate 2-byte e_machine parsing with endianness
    for x86, x86-64, ARM, AArch64, MIPS, and RISC-V.
    """
    test_cases = [
        # (name, is_64, is_le, e_machine, expected_arch, expected_endian)
        ("x86", False, True, 0x03, "x86", "little"),
        ("x86_64", True, True, 0x3E, "x86-64", "little"),
        ("arm", False, True, 0x28, "arm", "little"),
        ("aarch64", True, True, 0xB7, "aarch64", "little"),
        ("mips_be", False, False, 0x08, "mips", "big"),
        ("mips_le", False, True, 0x0A, "mips", "little"),
        ("riscv", True, True, 0xF3, "riscv", "little"),
    ]

    input_dir = tmp_path / "input"
    input_dir.mkdir(exist_ok=True)

    for name, is_64, is_le, machine_code, exp_arch, exp_endian in test_cases:
        elf_file = input_dir / f"test_{name}.elf"
        header = bytearray(64)
        header[0:4] = b"\x7fELF"
        header[4] = 2 if is_64 else 1
        header[5] = 1 if is_le else 2  # 1=LE, 2=BE
        header[6] = 1  # EV_CURRENT
        header[16:18] = (2).to_bytes(2, byteorder="little" if is_le else "big")  # ET_EXEC
        header[18:20] = machine_code.to_bytes(2, byteorder="little" if is_le else "big")

        elf_file.write_bytes(bytes(header))

        fp = FingerprintEngine.extract(
            meta={"name": name, "category": "pwn"},
            chall_dir=tmp_path,
        )

        assert exp_arch in fp.architectures, f"Failed for {name}: expected {exp_arch} in {fp.architectures}"
        assert fp.runtime_signals.get("endianness") == exp_endian
        elf_file.unlink()


def test_static_triage_pure_python_no_host_subprocess(tmp_path):
    """
    Section 7 Test: Static triage must run pure-Python inspection
    without spawning any uncontrolled host subprocesses.
    """
    test_bin = tmp_path / "vuln.elf"
    header = bytearray(64)
    header[0:4] = b"\x7fELF"
    header[4] = 2  # 64-bit
    header[5] = 1  # Little endian
    header[16:18] = (2).to_bytes(2, "little")  # ET_EXEC -> no-pie
    header[18:20] = (0x3E).to_bytes(2, "little")  # x86-64
    content = bytes(header) + b"Here is some flag{fake_test_flag} and system calls"
    test_bin.write_bytes(content)

    with patch("subprocess.run") as mock_subproc:
        report = StaticTriage.analyze_file(test_bin)
        # Verify subprocess.run was NEVER called on host
        mock_subproc.assert_not_called()

    assert "x86-64" in report
    assert "ELF 64-bit LSB" in report
    assert "flag{fake_test_flag}" in report


def test_escalate_strategic_honesty(tmp_path):
    """
    Section 10 Test: PAL escalation is honestly reframed as Strategic Assumption Challenge.
    """
    from ctf_core.models import Challenge
    mgr = RuntimeManager(base_dir=tmp_path)
    chall = Challenge(
        id="101",
        name="BufferOverflow101",
        category="pwn",
        description="Exploit binary",
    )
    mgr.materialize_challenge("test_event", chall)

    service = AdvisorService(workspace_dir=tmp_path, runtime_manager=mgr, event_id="test_event")
    service.init_challenge_advisor("101")

    with patch.object(service, "consult", return_value={"status": "READY"}) as mock_consult:
        res = service.escalate_strategic("101", "Exploit payload offset did not hijack control flow")
        mock_consult.assert_called_once()
        call_kwargs = mock_consult.call_args.kwargs
        assert "STRATEGIC ESCALATION REVIEW: CHALLENGE ASSUMPTIONS" in call_kwargs.get("extra_instruction", "")

    # Also test backward-compatible alias escalate_pal
    with patch.object(service, "consult", return_value={"status": "READY"}) as mock_consult:
        res = service.escalate_pal("101", "Same failure")
        mock_consult.assert_called_once()
