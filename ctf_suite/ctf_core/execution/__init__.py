import shutil
from typing import Optional
from .adapter import ExecutorAdapter
from .restricted_executor import RestrictedLocalExecutor
from .container_executor import ContainerExecutor
from .unsafe_executor import UnsafeLocalExecutor

def get_executor(
    mode: str = "auto",
    flag_format_regex: str = r"FLAG\{[^\n\r\}]+\}"
) -> ExecutorAdapter:
    """
    Executor factory:
    - 'auto': ContainerExecutor if docker/podman is available, else RestrictedLocalExecutor.
    - 'container': ContainerExecutor.
    - 'restricted': RestrictedLocalExecutor (shell=False, sanitized env).
    - 'unsafe-local': UnsafeLocalExecutor (shell=True, explicit warning).
    """
    mode = mode.lower().strip()
    if mode == "unsafe-local":
        return UnsafeLocalExecutor(flag_format_regex=flag_format_regex)
    elif mode == "container":
        return ContainerExecutor(flag_format_regex=flag_format_regex)
    elif mode in ["restricted", "restricted-local"]:
        return RestrictedLocalExecutor(flag_format_regex=flag_format_regex)
    else:  # auto
        if shutil.which("docker") or shutil.which("podman"):
            return ContainerExecutor(flag_format_regex=flag_format_regex)
        return RestrictedLocalExecutor(flag_format_regex=flag_format_regex)

__all__ = [
    "ExecutorAdapter",
    "RestrictedLocalExecutor",
    "ContainerExecutor",
    "UnsafeLocalExecutor",
    "get_executor",
]
