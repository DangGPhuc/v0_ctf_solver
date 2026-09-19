import shutil
from typing import Optional
from .adapter import ExecutorAdapter
from .evaluator import ExecutionResultEvaluator
from .restricted_executor import RestrictedLocalExecutor
from .container_executor import ContainerExecutor
from .unsafe_executor import UnsafeLocalExecutor

def get_executor(
    mode: str = "auto",
    flag_format_regex: str = r"FLAG\{[^\n\r\}]+\}",
    allow_local_fallback: bool = False,
    allow_network: bool = False,
    network_profile: str = "none",
) -> ExecutorAdapter:
    """
    Executor factory with an honest security model:
    - 'auto': ContainerExecutor (isolated container). If container engine is unavailable,
              execution FAILS by default to prevent silently executing untrusted CTF code
              on the host system, unless allow_local_fallback=True is explicitly passed.
    - 'container': Strict ContainerExecutor (Docker / Podman, no fallback).
    - 'restricted-local': RestrictedLocalExecutor (shell=False, strictly resolved work_dir paths,
                          tool allowlist, safe env, but NOT a full sandbox against Python bytecode).
    - 'unsafe-local': UnsafeLocalExecutor (direct unconstrained host execution; dangerous).
    """
    mode = mode.lower().strip()
    if mode in ["unsafe", "unsafe-local"]:
        return UnsafeLocalExecutor(flag_format_regex=flag_format_regex)
    elif mode == "container":
        return ContainerExecutor(
            flag_format_regex=flag_format_regex,
            allow_network=allow_network,
            network_profile=network_profile,
            allow_local_fallback=False,
        )
    elif mode in ["restricted", "restricted-local"]:
        return RestrictedLocalExecutor(flag_format_regex=flag_format_regex)
    else:  # auto
        return ContainerExecutor(
            flag_format_regex=flag_format_regex,
            allow_network=allow_network,
            network_profile=network_profile,
            allow_local_fallback=allow_local_fallback,
        )

from .policy import ActionPolicy, ExecutionPolicyError, ALLOWED_ANALYSIS_TOOLS
from .runner import ExecutionRunner
from .artifacts import ArtifactResolver, ArtifactResolutionError

__all__ = [
    "ExecutorAdapter",
    "ExecutionResultEvaluator",
    "RestrictedLocalExecutor",
    "ContainerExecutor",
    "UnsafeLocalExecutor",
    "get_executor",
    "ActionPolicy",
    "ExecutionPolicyError",
    "ExecutionRunner",
    "ArtifactResolver",
    "ArtifactResolutionError",
    "ALLOWED_ANALYSIS_TOOLS",
]
