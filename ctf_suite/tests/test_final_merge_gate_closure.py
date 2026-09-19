import os
import subprocess
from pathlib import Path
from unittest.mock import MagicMock, patch
import pytest

from ctf_core.models import Challenge, AdvisorGuidance, AdvisorResult, ExecutionAction, Hypothesis
from ctf_core.execution.policy import ActionPolicy, ExecutionPolicyError
from ctf_core.execution.runner import ExecutionRunner
from ctf_core.execution.restricted_executor import RestrictedLocalExecutor
from ctf_core.execution.container_executor import ContainerExecutor
from ctf_core.advisor.guidance_parser import GuidanceParser
from ctf_core.services.advisor_service import AdvisorService
from ctf_core.runtime.manager import RuntimeManager


def test_production_triage_no_host_subprocess(tmp_path):
    """
    Section 2 Test: Real production call path
    RuntimeManager.materialize_challenge -> AdvisorService.init_challenge_advisor -> _generate_initial_findings
    MUST delegate to pure-Python StaticTriage and NEVER invoke host analysis tools
    (file, checksec, strings, readelf, objdump) via subprocess.run against challenge artifacts.
    """
    rm = RuntimeManager(base_dir=tmp_path / "runtime")
    chall = Challenge(
        id="chall_sec_triage",
        name="SecureService",
        category="Pwn",
        description="Challenge triage test",
    )
    chall_dir = rm.materialize_challenge("event_triage", chall)
    input_dir = chall_dir / "input"
    input_dir.mkdir(parents=True, exist_ok=True)

    # Create dummy challenge artifact (synthetic ELF)
    fake_elf = (
        b"\x7fELF\x02\x01\x01\x00"  # 64-bit LE ELF
        + b"\x00" * 8
        + (2).to_bytes(2, "little")   # ET_EXEC
        + (0x3E).to_bytes(2, "little")  # x86-64
        + b"\x00" * 40
        + b"admin_password_secret_key_flag{triage_test}"
    )
    (input_dir / "vuln_bin").write_bytes(fake_elf)

    adv = AdvisorService(workspace_dir=tmp_path, runtime_manager=rm, event_id="event_triage")

    # Patch subprocess.run to intercept any host command invocations
    with patch("subprocess.run") as mock_subproc:
        res = adv.init_challenge_advisor("chall_sec_triage", force=True)

        # Assert no artifact analysis subprocess was spawned
        for call_args in mock_subproc.call_args_list:
            cmd = call_args[0][0] if call_args[0] else []
            tool_name = cmd[0] if isinstance(cmd, list) and cmd else str(cmd)
            assert tool_name not in [
                "file", "checksec", "strings", "readelf", "objdump", "nm"
            ], f"Host tool '{tool_name}' was unexpectedly invoked on host against untrusted artifact!"

    findings_file = Path(res["findings_file"])
    assert findings_file.is_file()
    content = findings_file.read_text(encoding="utf-8")
    assert "Confirmed Findings & Evidence" in content
    assert "vuln_bin" in content
    assert "ELF 64-bit LSB executable, x86-64" in content


def test_advisor_service_wires_advisor_provider_ready(tmp_path):
    """
    Section 3 Test: AdvisorService.consult() must route through self.advisor_provider.consult(),
    consume the typed AdvisorResult, record events, and update state.
    """
    rm = RuntimeManager(base_dir=tmp_path / "runtime")
    chall = Challenge(id="chall_wire_1", name="WireTest", category="Web")
    rm.materialize_challenge("event_wire", chall)

    adv = AdvisorService(workspace_dir=tmp_path, runtime_manager=rm, event_id="event_wire")
    adv.init_challenge_advisor("chall_wire_1", force=True)

    fake_guidance_json = """```json
{
  "assessment": "Observed SQL injection in user parameter",
  "hypotheses": [
    {"id": "H1", "statement": "Authentication bypass via SQLi"}
  ],
  "execution_plan": [
    {"kind": "run_solver", "path": "solve.py", "timeout": 30}
  ]
}
```"""
    mock_result = AdvisorResult(
        status="READY",
        provider="chatgpt-web",
        session_id="sess_wire_999",
        raw_response=fake_guidance_json,
        guidance=GuidanceParser.parse(fake_guidance_json),
    )

    with patch.object(adv.advisor_provider, "consult", return_value=mock_result) as mock_consult:
        out = adv.consult("chall_wire_1")

        assert mock_consult.called
        assert out["status"] == "READY"
        assert out["oracle_session"] == "sess_wire_999"
        assert out["provider"] == "chatgpt-web"
        assert out["guidance"].is_structured is True
        assert len(out["guidance"].execution_plan) == 1
        assert out["guidance"].execution_plan[0].path == "solve.py"

        # Verify state file was updated
        chall_dir = adv._find_chall_dir("chall_wire_1")
        state_file = chall_dir / ".advisor" / "state.json"
        assert state_file.is_file()


def test_advisor_service_wires_advisor_provider_fallback(tmp_path):
    """
    Section 4 Test: When AdvisorProvider returns PROVIDER_UNAVAILABLE,
    AdvisorService must fallback to copying prompt to clipboard, opening browser,
    and returning status WAITING_FOR_MANUAL_RESPONSE without crashing.
    """
    rm = RuntimeManager(base_dir=tmp_path / "runtime")
    chall = Challenge(id="chall_wire_2", name="FallbackTest", category="Crypto")
    rm.materialize_challenge("event_fallback", chall)

    adv = AdvisorService(workspace_dir=tmp_path, runtime_manager=rm, event_id="event_fallback")
    adv.init_challenge_advisor("chall_wire_2", force=True)

    mock_result = AdvisorResult(
        status="PROVIDER_UNAVAILABLE",
        provider="oracle",
        message="Neither 'oracle' nor 'npx' executable found on PATH.",
    )

    with patch.object(adv.advisor_provider, "consult", return_value=mock_result) as mock_consult, \
         patch.object(adv.browser_bridge, "copy_to_clipboard") as mock_clip, \
         patch.object(adv.browser_bridge, "open_firefox") as mock_fox:

        out = adv.consult("chall_wire_2")

        assert mock_consult.called
        assert mock_clip.called
        assert mock_fox.called
        assert out["status"] == "WAITING_FOR_MANUAL_RESPONSE"
        assert out["provider"] == "firefox-fallback"


def test_container_executor_multi_action_deterministic_order(tmp_path):
    """
    Section 6 Test: ContainerExecutor must execute multi-action plans sequentially
    (action 1 -> action 2 -> action 3) in deterministic order.
    Guards against reintroducing the historical execution_plan[0] bug.
    """
    work_dir = tmp_path / "work"
    input_dir = tmp_path / "input"
    work_dir.mkdir()
    input_dir.mkdir()

    (input_dir / "vuln").write_text("dummy")
    (work_dir / "solve.py").write_text("print('FLAG{CONTAINER_MULTI_SUCCESS}')")

    guidance = AdvisorGuidance(
        assessment="Multi-step inspection in container",
        execution_plan=[
            ExecutionAction(kind="analysis_tool", tool="checksec", argv=["checksec", "--file=input:vuln"], timeout=15),
            ExecutionAction(kind="analysis_tool", tool="strings", argv=["strings", "input:vuln"], timeout=20),
            ExecutionAction(kind="run_solver", path="work:solve.py", timeout=25),
        ],
        is_structured=True,
    )

    executor = ContainerExecutor(
        image="test:latest",
        allow_local_fallback=False,
        flag_format_regex=r"FLAG\{[^\n\r\}]+\}",
    )
    executor.engine = "docker"

    executed_docker_commands = []

    def fake_subprocess_run(cmd, capture_output=True, text=True, timeout=None):
        executed_docker_commands.append((list(cmd), timeout))
        mock_proc = MagicMock()
        mock_proc.returncode = 0
        if "checksec" in cmd:
            mock_proc.stdout = "RELRO: Full\nStack: Canary"
        elif "strings" in cmd:
            mock_proc.stdout = "hello\nworld\nflag"
        elif any("solve.py" in str(arg) for arg in cmd):
            mock_proc.stdout = "Solver output: FLAG{CONTAINER_MULTI_SUCCESS}"
        else:
            mock_proc.stdout = "OK"
        mock_proc.stderr = ""
        return mock_proc

    with patch("subprocess.run", side_effect=fake_subprocess_run):
        result = executor.execute({"work_dir": work_dir, "input_dir": input_dir}, guidance)

        # Assert all 3 actions executed in exact order
        assert len(executed_docker_commands) == 3
        # Action 1: checksec with timeout 15
        assert executed_docker_commands[0][1] == 15
        assert any("checksec" in str(arg) for arg in executed_docker_commands[0][0])
        # Action 2: strings with timeout 20
        assert executed_docker_commands[1][1] == 20
        assert any("strings" in str(arg) for arg in executed_docker_commands[1][0])
        # Action 3: python3 solve.py with timeout 25
        assert executed_docker_commands[2][1] == 25
        assert any("solve.py" in str(arg) for arg in executed_docker_commands[2][0])

        assert result.status == "FLAG_FOUND"
        assert "FLAG{CONTAINER_MULTI_SUCCESS}" in result.flag_candidates


def test_container_executor_action2_failure_halts_action3(tmp_path):
    """
    Section 6 Test: If action 2 fails (non-zero return code),
    action 3 must NOT execute.
    """
    work_dir = tmp_path / "work"
    input_dir = tmp_path / "input"
    work_dir.mkdir()
    input_dir.mkdir()

    (input_dir / "vuln").write_text("dummy")

    guidance = AdvisorGuidance(
        assessment="Failure halting check",
        execution_plan=[
            ExecutionAction(kind="analysis_tool", tool="checksec", argv=["checksec", "--file=input:vuln"]),
            ExecutionAction(kind="analysis_tool", tool="strings", argv=["strings", "input:vuln"]),
            ExecutionAction(kind="run_solver", path="work:solve.py"),
        ],
        is_structured=True,
    )

    executor = ContainerExecutor(image="test:latest", allow_local_fallback=False)
    executor.engine = "docker"

    call_count = 0

    def fake_subprocess_run(cmd, capture_output=True, text=True, timeout=None):
        nonlocal call_count
        call_count += 1
        mock_proc = MagicMock()
        if call_count == 1:
            mock_proc.returncode = 0
            mock_proc.stdout = "Checksec ok"
            mock_proc.stderr = ""
        elif call_count == 2:
            mock_proc.returncode = 2
            mock_proc.stdout = ""
            mock_proc.stderr = "Strings binary failed"
        else:
            mock_proc.returncode = 0
            mock_proc.stdout = "Should never run"
            mock_proc.stderr = ""
        return mock_proc

    with patch("subprocess.run", side_effect=fake_subprocess_run):
        result = executor.execute({"work_dir": work_dir, "input_dir": input_dir}, guidance)

        # Only action 1 and action 2 were attempted; action 3 was aborted
        assert call_count == 2
        assert result.return_code == 2


def test_container_executor_action2_timeout_halts_action3(tmp_path):
    """
    Section 6 Test: If action 2 times out,
    action 3 must NOT execute.
    """
    work_dir = tmp_path / "work"
    input_dir = tmp_path / "input"
    work_dir.mkdir()
    input_dir.mkdir()

    guidance = AdvisorGuidance(
        assessment="Timeout halting check",
        execution_plan=[
            ExecutionAction(kind="list_files", timeout=10),
            ExecutionAction(kind="analysis_tool", tool="strings", argv=["strings", "input:vuln"], timeout=5),
            ExecutionAction(kind="run_solver", path="work:solve.py", timeout=10),
        ],
        is_structured=True,
    )

    executor = ContainerExecutor(image="test:latest", allow_local_fallback=False)
    executor.engine = "docker"

    call_count = 0

    def fake_subprocess_run(cmd, capture_output=True, text=True, timeout=None):
        nonlocal call_count
        call_count += 1
        if call_count == 1:
            mock_proc = MagicMock()
            mock_proc.returncode = 0
            mock_proc.stdout = "total 0"
            mock_proc.stderr = ""
            return mock_proc
        elif call_count == 2:
            raise subprocess.TimeoutExpired(cmd=cmd, timeout=timeout)
        else:
            mock_proc = MagicMock()
            mock_proc.returncode = 0
            mock_proc.stdout = "Should not run"
            return mock_proc

    with patch("subprocess.run", side_effect=fake_subprocess_run):
        result = executor.execute({"work_dir": work_dir, "input_dir": input_dir}, guidance)

        # Action 3 must NOT execute
        assert call_count == 2
        assert result.status == "ERROR"
        assert "timed out" in result.observed.lower()


def test_symlink_operand_escape_rejected(tmp_path):
    """
    Section 7 Test: A symlink operand inside work/ pointing outside challenge boundaries
    (e.g., work/link -> /etc/passwd) must be rejected by canonical path containment.
    """
    work_dir = tmp_path / "work"
    input_dir = tmp_path / "input"
    work_dir.mkdir()
    input_dir.mkdir()

    # Create symlink pointing outside challenge boundaries
    symlink = work_dir / "link_escape"
    try:
        symlink.symlink_to("/etc/passwd")
    except OSError:
        pytest.skip("Symlink creation not permitted in this test environment")

    # 1. ActionPolicy direct validation
    action = ExecutionAction(
        kind="analysis_tool",
        tool="strings",
        argv=["strings", "link_escape"],
    )
    with pytest.raises(ExecutionPolicyError) as exc_info:
        ActionPolicy.validate_action(action, input_dir, work_dir)
    assert "escapes challenge boundaries" in str(exc_info.value)

    # 2. Execution via RestrictedLocalExecutor
    executor = RestrictedLocalExecutor()
    guidance = AdvisorGuidance(
        assessment="Symlink escape attack",
        execution_plan=[action],
        is_structured=True,
    )
    res = executor.execute({"work_dir": work_dir, "input_dir": input_dir}, guidance)
    assert res.status == "ERROR"
    assert "escapes challenge boundaries" in res.observed


def test_symlink_operand_safe_containment_allowed(tmp_path):
    """
    Section 7 Test: Symlinks pointing inside challenge boundaries and logical
    artifact references (input:..., work:...) must be allowed.
    """
    work_dir = tmp_path / "work"
    input_dir = tmp_path / "input"
    work_dir.mkdir()
    input_dir.mkdir()

    safe_file = work_dir / "target.txt"
    safe_file.write_text("SAFE_DATA")

    safe_link = work_dir / "safe_link"
    try:
        safe_link.symlink_to(safe_file)
    except OSError:
        pytest.skip("Symlink creation not permitted in this test environment")

    # Safe link inside work_dir
    action_safe = ExecutionAction(
        kind="analysis_tool",
        tool="strings",
        argv=["strings", "safe_link"],
    )
    validated = ActionPolicy.validate_action(action_safe, input_dir, work_dir)
    assert validated is not None

    # Logical artifact reference input:vuln
    (input_dir / "vuln").write_text("VULN_DATA")
    action_input = ExecutionAction(
        kind="analysis_tool",
        tool="file",
        argv=["file", "input:vuln"],
    )
    validated_input = ActionPolicy.validate_action(action_input, input_dir, work_dir)
    assert validated_input is not None

    # Logical artifact reference work:target.txt
    action_work = ExecutionAction(
        kind="analysis_tool",
        tool="strings",
        argv=["strings", "work:target.txt"],
    )
    validated_work = ActionPolicy.validate_action(action_work, input_dir, work_dir)
    assert validated_work is not None


def test_execution_fallback_malformed_json_fails_closed(tmp_path):
    """
    Section 8 Test: Malformed structured advisor JSON + existing solve.py
    MUST fail closed (return []), and solve.py MUST NOT be executed.
    """
    work_dir = tmp_path / "work"
    work_dir.mkdir()
    solve_file = work_dir / "solve.py"
    solve_file.write_text("print('MALICIOUS_SOLVER_EXECUTED')\n")

    # Guidance with malformed JSON (contains json codeblock with invalid syntax)
    raw_bad = '```json\n{ "assessment": "test", broken_json_syntax: true }\n```'
    guidance = GuidanceParser.parse(raw_bad)
    assert guidance.validation_error is not None
    assert guidance.is_structured is False

    # 1. ExecutionRunner.resolve_actions_to_run must return []
    actions = ExecutionRunner.resolve_actions_to_run(guidance, work_dir)
    assert actions == [], "Malformed JSON guidance must fail closed and return empty action list!"

    # 2. RestrictedLocalExecutor must fail closed with ERROR and never run solve.py
    executor = RestrictedLocalExecutor()
    res = executor.execute({"work_dir": work_dir}, guidance)
    assert res.status == "ERROR"
    assert "MALICIOUS_SOLVER_EXECUTED" not in (res.stdout_tail or "")
    assert "MALICIOUS_SOLVER_EXECUTED" not in res.observed
    assert "Malformed structured guidance failed closed" in res.observed


def test_execution_fallback_prose_guidance_non_executable(tmp_path):
    """
    Section 8 Test: Prose advisor guidance + next_actions
    MUST NOT execute next_actions or fall back to existing solve.py.
    """
    work_dir = tmp_path / "work"
    work_dir.mkdir()
    solve_file = work_dir / "solve.py"
    solve_file.write_text("print('SOLVER_ACCIDENTALLY_EXECUTED')\n")

    raw_prose = """
    Assessment: The binary contains a stack overflow in vuln().
    Hypothesis 1: Overwrite return address with win function.
    Action 1: rm -rf /
    Action 2: python3 solve.py
    """
    guidance = GuidanceParser.parse(raw_prose)
    assert guidance.is_structured is False
    assert len(guidance.next_actions) > 0

    actions = ExecutionRunner.resolve_actions_to_run(guidance, work_dir)
    assert actions == [], "Prose guidance must not produce executable actions or fall back to solver!"

    executor = RestrictedLocalExecutor()
    res = executor.execute({"work_dir": work_dir}, guidance)
    assert res.status == "ERROR"
    assert "SOLVER_ACCIDENTALLY_EXECUTED" not in (res.stdout_tail or "")
    assert "SOLVER_ACCIDENTALLY_EXECUTED" not in res.observed
    assert "Prose guidance and unstructured text actions cannot be executed" in res.observed


def test_execution_fallback_valid_structured_plan_executes(tmp_path):
    """
    Section 8 Test: Valid structured execution_plan executes normally.
    """
    work_dir = tmp_path / "work"
    work_dir.mkdir()
    solve_file = work_dir / "solve.py"
    solve_file.write_text("print('FLAG{VALID_STRUCTURED_EXECUTION}')\n")

    raw_json = """```json
{
  "assessment": "Validated exploit script",
  "hypotheses": [
    {"id": "H1", "statement": "Exploit script succeeds"}
  ],
  "execution_plan": [
    {"kind": "run_solver", "path": "solve.py"}
  ]
}
```"""
    guidance = GuidanceParser.parse(raw_json)
    assert guidance.is_structured is True
    assert len(guidance.execution_plan) == 1

    actions = ExecutionRunner.resolve_actions_to_run(guidance, work_dir)
    assert len(actions) == 1

    executor = RestrictedLocalExecutor(flag_format_regex=r"FLAG\{[^\n\r\}]+\}")
    res = executor.execute({"work_dir": work_dir}, guidance)
    assert res.status == "FLAG_FOUND"
    assert "FLAG{VALID_STRUCTURED_EXECUTION}" in res.flag_candidates


def test_execution_fallback_empty_guidance_does_not_execute_solver(tmp_path):
    """
    Test A: Empty AdvisorGuidance() must NOT fall back to executing an existing solver script.
    Trust is NEVER inferred from emptiness.
    """
    work_dir = tmp_path / "work"
    work_dir.mkdir()
    solve_file = work_dir / "solve.py"
    solve_file.write_text("print('SOLVER_SHOULD_NOT_EXECUTE')\n")

    empty_guidance = AdvisorGuidance()

    actions = ExecutionRunner.resolve_actions_to_run(empty_guidance, work_dir, allow_trusted_fallback=False)
    assert actions == [], "Empty AdvisorGuidance must not produce actions or trigger fallback!"

    executor = RestrictedLocalExecutor()
    res = executor.execute({"work_dir": work_dir}, empty_guidance, allow_trusted_fallback=False)
    assert "SOLVER_SHOULD_NOT_EXECUTE" not in (res.stdout_tail or "")
    assert "SOLVER_SHOULD_NOT_EXECUTE" not in res.observed
    assert res.actions == [] or "no_actions_resolved" in res.actions[0]


def test_execution_fallback_none_guidance_untrusted_rejected(tmp_path):
    """
    Test B: guidance=None without explicit trust (allow_trusted_fallback=False)
    must NOT fall back to executing an existing solver script.
    """
    work_dir = tmp_path / "work"
    work_dir.mkdir()
    solve_file = work_dir / "solve.py"
    solve_file.write_text("print('UNTRUSTED_NONE_EXECUTED')\n")

    actions = ExecutionRunner.resolve_actions_to_run(None, work_dir, allow_trusted_fallback=False)
    assert actions == [], "None guidance without allow_trusted_fallback=True must return []!"

    executor = RestrictedLocalExecutor()
    res = executor.execute({"work_dir": work_dir}, guidance=None, allow_trusted_fallback=False)
    assert "UNTRUSTED_NONE_EXECUTED" not in (res.stdout_tail or "")
    assert "UNTRUSTED_NONE_EXECUTED" not in res.observed


def test_execution_fallback_trusted_internal_path(tmp_path):
    """
    Section 8 Test: Trusted internal default path (guidance=None, allow_trusted_fallback=True)
    executes existing solve.py as intended.
    """
    work_dir = tmp_path / "work"
    work_dir.mkdir()
    solve_file = work_dir / "solve.py"
    solve_file.write_text("print('FLAG{TRUSTED_DEFAULT_RUN}')\n")

    # 1. resolve_actions_to_run returns solver action when allow_trusted_fallback=True
    actions = ExecutionRunner.resolve_actions_to_run(None, work_dir, allow_trusted_fallback=True)
    assert len(actions) == 1
    assert actions[0].kind == "run_solver"
    assert actions[0].path == "solve.py"

    # 2. executor.execute runs solver when allow_trusted_fallback=True
    executor = RestrictedLocalExecutor(flag_format_regex=r"FLAG\{[^\n\r\}]+\}")
    res = executor.execute({"work_dir": work_dir}, guidance=None, allow_trusted_fallback=True)
    assert res.status == "FLAG_FOUND"
    assert "FLAG{TRUSTED_DEFAULT_RUN}" in res.flag_candidates
