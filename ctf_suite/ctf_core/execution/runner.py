from pathlib import Path
from typing import Any, Callable, Dict, List, Optional
import subprocess
from rich.console import Console

from ..models import AdvisorGuidance, ExecutionAction, ExecutionResult
from .evaluator import ExecutionResultEvaluator
from .policy import ActionPolicy, ExecutionPolicyError

console = Console()


class ExecutionRunner:
    """
    Canonical Multi-Action Execution Runner.
    Coordinates sequential deterministic execution of ExecutionAction objects:
      action 1 -> action 2 -> action 3
    until:
      - all actions complete successfully,
      - an action returns a non-zero exit code or error,
      - an action times out,
      - ActionPolicy rejects an action,
      - or a stop condition / flag is satisfied.
    """

    @classmethod
    def resolve_actions_to_run(
        cls,
        guidance: Optional[AdvisorGuidance],
        work_dir: Path,
        default_timeout: int = 60,
        allow_trusted_fallback: bool = False,
    ) -> List[ExecutionAction]:
        """
        Extracts execution plan from guidance or falls back to standard solver files ONLY
        on explicitly trusted internal paths.

        Trust boundary invariants:
        1. If guidance has a validation_error (e.g. malformed JSON), it MUST fail closed (return []).
        2. If guidance contains prose text (raw_text or next_actions) without a valid structured
           execution_plan, human-readable prose is NEVER executed and MUST NOT trigger fallback execution (return []).
        3. Only an explicitly validated, structured execution_plan is executed.
        4. Fallback execution of solve.py / solve.sage is strictly prohibited when advisor guidance
           is present, preventing malformed or prose advisor output from accidentally becoming execution authority.
        """
        if guidance is not None:
            # Invariant 1: Malformed structured JSON must fail closed.
            if getattr(guidance, "validation_error", None):
                return []

            # Invariant 2: Explicit structured execution plan
            plan = getattr(guidance, "execution_plan", None)
            if plan:
                return list(plan)

            # Invariant 3: Guidance provided by advisor (raw_text or next_actions)
            # but lacking an execution_plan. Prose must remain non-executable.
            # Must NOT silently fall back to solve.py/solve.sage!
            if getattr(guidance, "raw_text", None) or getattr(guidance, "next_actions", None):
                return []

        # Internal trusted fallback path: only reachable if allow_trusted_fallback is True,
        # or if guidance is None/empty default guidance (e.g. manual './ctf run' without advisor).
        if allow_trusted_fallback or guidance is None or (
            not getattr(guidance, "raw_text", None)
            and not getattr(guidance, "assessment", None)
            and not getattr(guidance, "next_actions", None)
            and not getattr(guidance, "execution_plan", None)
        ):
            solve_sage = work_dir / "solve.sage"
            solve_script = work_dir / "solve.py"
            if solve_sage.is_file():
                return [ExecutionAction(
                    kind="run_sage_file",
                    argv=["sage", "solve.sage"],
                    path="solve.sage",
                    timeout=default_timeout,
                )]
            elif solve_script.is_file():
                return [ExecutionAction(
                    kind="run_solver",
                    argv=["python3", "solve.py"],
                    path="solve.py",
                    timeout=default_timeout,
                )]
            else:
                return [ExecutionAction(
                    kind="list_files",
                    argv=["ls", "-la"],
                    timeout=10,
                )]

        return []

    @classmethod
    def run_plan(
        cls,
        challenge_context: Dict[str, Any],
        guidance: AdvisorGuidance,
        work_dir: Path,
        input_dir: Path,
        single_action_executor: Callable[[ExecutionAction, Dict[str, Any]], Dict[str, Any]],
        flag_format_regex: str,
        default_timeout: int = 60,
    ) -> ExecutionResult:
        """
        Runs the full execution plan using the provided single_action_executor callable.
        """
        iteration = challenge_context.get("iteration", 1)
        experiment_id = f"EXP-{iteration:03d}"

        actions_to_run = cls.resolve_actions_to_run(guidance, work_dir, default_timeout)

        if not actions_to_run:
            if getattr(guidance, "validation_error", None):
                err = f"Malformed structured guidance failed closed: {guidance.validation_error}"
                return ExecutionResultEvaluator.build_result(
                    experiment_id=experiment_id,
                    return_code=-1,
                    stdout="",
                    stderr=err,
                    actions_performed=["validation_error_fail_closed"],
                    work_dir=work_dir,
                    guidance=guidance,
                    flag_format_regex=flag_format_regex,
                    error_message=err,
                )
            if guidance and (getattr(guidance, "raw_text", None) or getattr(guidance, "next_actions", None)) and not getattr(guidance, "is_structured", False):
                err = "Prose guidance and unstructured text actions cannot be executed. A structured JSON execution plan is required."
                return ExecutionResultEvaluator.build_result(
                    experiment_id=experiment_id,
                    return_code=-1,
                    stdout="",
                    stderr=err,
                    actions_performed=["prose_guidance_non_executable"],
                    work_dir=work_dir,
                    guidance=guidance,
                    flag_format_regex=flag_format_regex,
                    error_message=err,
                )
            return ExecutionResultEvaluator.build_result(
                experiment_id=experiment_id,
                return_code=0,
                stdout="",
                stderr="",
                actions_performed=["no_actions_resolved"],
                work_dir=work_dir,
                guidance=guidance,
                flag_format_regex=flag_format_regex,
            )

        actions_performed: List[str] = []
        stdout_acc: List[str] = []
        stderr_acc: List[str] = []
        final_return_code: Optional[int] = None
        timed_out = False
        error_msg: Optional[str] = None

        for idx, raw_action in enumerate(actions_to_run, start=1):
            # 1. Policy validation
            try:
                action = ActionPolicy.validate_action(raw_action, input_dir, work_dir)
            except (ExecutionPolicyError, PermissionError, ValueError) as e:
                console.print(f"[bold red]❌ Execution Policy rejected action {idx} ({raw_action.kind}): {e}[/bold red]")
                error_msg = f"Policy rejection: {e}"
                final_return_code = -1
                actions_performed.append(f"rejected:{raw_action.kind}:{e}")
                break

            # 2. Execute single action through backend callback
            try:
                res = single_action_executor(action, challenge_context)
                ret_code = res.get("return_code", 0)
                cmd_repr = res.get("action_repr", f"{action.kind}")
                actions_performed.append(cmd_repr)

                stdout_piece = res.get("stdout", "")
                stderr_piece = res.get("stderr", "")
                if stdout_piece:
                    stdout_acc.append(stdout_piece)
                if stderr_piece:
                    stderr_acc.append(stderr_piece)

                final_return_code = ret_code
                if res.get("timed_out"):
                    timed_out = True
                    stderr_acc.append(f"Action {idx} timed out after {action.timeout}s")
                    break

                if ret_code != 0:
                    console.print(f"[yellow]⚠️ Action {idx} failed with exit code {ret_code}. Halting plan execution.[/yellow]")
                    break

            except subprocess.TimeoutExpired:
                timed_out = True
                final_return_code = -9
                actions_performed.append(f"{action.kind}:timeout")
                stderr_acc.append(f"Action {idx} timed out after {action.timeout}s")
                break
            except Exception as e:
                final_return_code = -1
                error_msg = str(e)
                actions_performed.append(f"{action.kind}:error:{e}")
                stderr_acc.append(str(e))
                break

        full_stdout = "\n".join(stdout_acc)
        full_stderr = "\n".join(stderr_acc)

        return ExecutionResultEvaluator.build_result(
            experiment_id=experiment_id,
            return_code=final_return_code,
            stdout=full_stdout,
            stderr=full_stderr,
            actions_performed=actions_performed,
            work_dir=work_dir,
            guidance=guidance,
            flag_format_regex=flag_format_regex,
            timed_out=timed_out,
            error_message=error_msg,
        )
