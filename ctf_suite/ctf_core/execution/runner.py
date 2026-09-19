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
        guidance: AdvisorGuidance,
        work_dir: Path,
        default_timeout: int = 60,
    ) -> List[ExecutionAction]:
        """
        Extracts execution plan from guidance or falls back to standard solver files.
        Notice: guidance.next_actions is human-readable prose and is NEVER executed.
        """
        actions_to_run: List[ExecutionAction] = []
        if getattr(guidance, "execution_plan", None):
            actions_to_run.extend(guidance.execution_plan)
        else:
            solve_sage = work_dir / "solve.sage"
            solve_script = work_dir / "solve.py"
            if solve_sage.is_file():
                actions_to_run.append(ExecutionAction(
                    kind="run_sage_file",
                    argv=["sage", "solve.sage"],
                    path="solve.sage",
                    timeout=default_timeout,
                ))
            elif solve_script.is_file():
                actions_to_run.append(ExecutionAction(
                    kind="run_solver",
                    argv=["python3", "solve.py"],
                    path="solve.py",
                    timeout=default_timeout,
                ))
            else:
                actions_to_run.append(ExecutionAction(
                    kind="list_files",
                    argv=["ls", "-la"],
                    timeout=10,
                ))
        return actions_to_run

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
