from pathlib import Path
from typing import Any, Dict, List, Optional, Set
import re
import os

from ..models import ExecutionAction
from .artifacts import ArtifactResolver, ArtifactResolutionError


class ExecutionPolicyError(Exception):
    """Raised when an ExecutionAction violates the execution security policy."""
    pass


SAFE_ENV_KEYS = ["PATH", "HOME", "LANG", "LC_ALL", "PYTHONPATH"]

ALLOWED_ANALYSIS_TOOLS: Set[str] = {
    "file",
    "strings",
    "readelf",
    "objdump",
    "checksec",
    "nm",
    "ltrace",
    "strace",
    "ropper",
    "seccomp-tools",
}

SUPPORTED_ACTION_KINDS: Set[str] = {
    "run_solver",
    "run_python_file",
    "run_sage_file",
    "run_binary",
    "read_file",
    "list_files",
    "analysis_tool",
}

FORBIDDEN_SHELL_CHARS = {";", "&", "|", "`", "$", "\n", "\r"}

MIN_ACTION_TIMEOUT = 1
MAX_ACTION_TIMEOUT = 300
DEFAULT_ACTION_TIMEOUT = 60


class ActionPolicy:
    """
    Canonical execution policy shared by all safe backends
    (RestrictedLocalExecutor, ContainerExecutor).

    Enforces:
    1. Supported action kind validation.
    2. Analysis tool allowlist validation.
    3. Strict path containment (input/ro and work/rw).
    4. Per-action timeout bounds.
    5. No shell metacharacters in arguments.
    6. Environment variable secret stripping.
    """

    @classmethod
    def validate_action(
        cls,
        action: ExecutionAction,
        input_dir: Path,
        work_dir: Path,
    ) -> ExecutionAction:
        """
        Validates an ExecutionAction against security policy rules.
        Returns a sanitized/normalized ExecutionAction or raises ExecutionPolicyError.
        """
        # 1. Action kind validation
        kind = getattr(action, "kind", None)
        if not kind or kind not in SUPPORTED_ACTION_KINDS:
            raise ExecutionPolicyError(f"Unsupported action kind: '{kind}'. Allowed: {sorted(SUPPORTED_ACTION_KINDS)}")

        # 2. Timeout bounds enforcement
        timeout = getattr(action, "timeout", None) or DEFAULT_ACTION_TIMEOUT
        if not isinstance(timeout, (int, float)) or timeout < MIN_ACTION_TIMEOUT:
            timeout = MIN_ACTION_TIMEOUT
        elif timeout > MAX_ACTION_TIMEOUT:
            timeout = MAX_ACTION_TIMEOUT
        action.timeout = int(timeout)

        # 3. Shell metacharacter check in all arguments
        if action.argv:
            for arg in action.argv:
                for bad_char in FORBIDDEN_SHELL_CHARS:
                    if bad_char in arg:
                        raise ExecutionPolicyError(
                            f"Dangerous shell metacharacter '{bad_char}' detected in argument: {arg}"
                        )

        # 4. Specific kind rules & tool allowlist
        if kind == "analysis_tool":
            tool_name = action.tool or (action.argv[0] if action.argv else None)
            if not tool_name:
                raise ExecutionPolicyError("analysis_tool action must specify a tool name")
            if tool_name not in ALLOWED_ANALYSIS_TOOLS:
                raise ExecutionPolicyError(
                    f"Analysis tool '{tool_name}' is not in allowed registry: {sorted(ALLOWED_ANALYSIS_TOOLS)}"
                )

            # Validate tool arguments and operands
            raw_args = action.argv[1:] if (action.argv and action.argv[0] == tool_name) else (action.argv or [])
            cls._validate_tool_operands(raw_args, input_dir, work_dir)

        elif kind in ["run_solver", "run_python_file"]:
            target = action.path or "solve.py"
            cls._validate_target_path(target, input_dir, work_dir, allowed_in_input=False)

        elif kind == "run_sage_file":
            target = action.path or "solve.sage"
            cls._validate_target_path(target, input_dir, work_dir, allowed_in_input=False)

        elif kind == "run_binary":
            target = action.path or (action.argv[0] if action.argv else None)
            if not target:
                raise ExecutionPolicyError("run_binary action must specify a target binary path or argv[0]")
            cls._validate_target_path(target, input_dir, work_dir, allowed_in_input=True)

        elif kind == "read_file":
            target = action.path or (action.argv[0] if action.argv else None)
            if not target:
                raise ExecutionPolicyError("read_file action must specify a target file path or argv[0]")
            cls._validate_target_path(target, input_dir, work_dir, allowed_in_input=True)

        elif kind == "list_files":
            # list_files is inherently contained
            pass

        return action

    @classmethod
    def _validate_target_path(
        cls,
        spec: str,
        input_dir: Path,
        work_dir: Path,
        allowed_in_input: bool = True,
    ) -> Path:
        """
        Ensures target path resolves safely inside input/ or work/.
        """
        try:
            resolved = ArtifactResolver.resolve_local(spec, input_dir, work_dir, require_exists=False)
        except (ArtifactResolutionError, PermissionError) as e:
            raise ExecutionPolicyError(f"Path containment violation for target '{spec}': {e}") from e

        resolved_input = input_dir.resolve()
        resolved_work = work_dir.resolve()

        if resolved.is_relative_to(resolved_work):
            return resolved

        if allowed_in_input and resolved.is_relative_to(resolved_input):
            return resolved

        raise ExecutionPolicyError(
            f"Target path '{spec}' resolves to '{resolved}', which is not permitted. "
            f"(allowed_in_input={allowed_in_input}, work_dir={resolved_work})"
        )

    @classmethod
    def _validate_tool_operands(
        cls,
        argv: List[str],
        input_dir: Path,
        work_dir: Path,
    ):
        """
        Inspects all argument tokens passed to an analysis tool.
        Rejects external filesystem paths (e.g. /etc/passwd, ../../secret, /home/user/file).
        """
        resolved_input = input_dir.resolve()
        resolved_work = work_dir.resolve()

        for arg in argv:
            # Check for --flag=value options
            val = arg
            if arg.startswith("-") and "=" in arg:
                _, val = arg.split("=", 1)
            elif arg.startswith("-"):
                # Pure option flag (e.g. -a, -b, -n, --all, -d) - safe
                continue

            val_str = str(val).strip()
            if not val_str:
                continue

            # Check if value represents an artifact reference
            if val_str.startswith("input:") or val_str.startswith("work:"):
                try:
                    resolved = ArtifactResolver.resolve_local(val_str, input_dir, work_dir, require_exists=False)
                except (ArtifactResolutionError, PermissionError) as e:
                    raise ExecutionPolicyError(f"Tool argument violates artifact containment: {val_str} ({e})") from e
                if not (resolved.is_relative_to(resolved_input) or resolved.is_relative_to(resolved_work)):
                    raise ExecutionPolicyError(f"Tool argument resolves outside challenge boundaries: {val_str}")
                continue

            # If the argument looks like an absolute path, home path, or relative path with traversal
            if (
                val_str.startswith("/")
                or val_str.startswith("~")
                or val_str.startswith("../")
                or "/../" in val_str
                or val_str.endswith("/..")
                or val_str == ".."
            ):
                p = Path(val_str).expanduser()
                try:
                    resolved = p.resolve()
                except Exception as e:
                    raise ExecutionPolicyError(f"Invalid path argument in tool: {val_str}") from e

                if not (resolved.is_relative_to(resolved_input) or resolved.is_relative_to(resolved_work)):
                    raise ExecutionPolicyError(
                        f"External path operand blocked by execution policy: '{val_str}' resolves to '{resolved}'"
                    )

    @classmethod
    def sanitize_environment(
        cls,
        extra_vars: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, str]:
        """
        Produces a sanitized environment dictionary containing only safe system keys
        and challenge variables stripped of all host secrets and credentials.
        """
        env = {k: os.environ[k] for k in SAFE_ENV_KEYS if k in os.environ}
        if "PATH" not in env:
            env["PATH"] = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

        if extra_vars and isinstance(extra_vars, dict):
            for k, v in extra_vars.items():
                k_upper = str(k).upper()
                if any(bad in k_upper for bad in ["TOKEN", "COOKIE", "SECRET", "AUTH", "PASS", "KEY", "SESSION"]):
                    continue
                env[str(k)] = str(v)

        return env
