import os
from pathlib import Path
from typing import List, Optional, Tuple


class ArtifactResolutionError(Exception):
    """Raised when an artifact cannot be resolved safely."""
    pass


class ArtifactResolver:
    """
    Translates logical resource specifiers ('input:<file>', 'work:<file>')
    into safe, verified physical paths on the host or inside a container.

    Guarantees:
    1. Rejects path traversal (e.g. 'input:../../etc/passwd').
    2. Enforces read-only boundary for input/ and read-write boundary for work/.
    3. Prevents leakage of host absolute paths into the container.
    """

    @staticmethod
    def resolve_local(
        logical_spec: str,
        input_dir: Path,
        work_dir: Path,
        require_exists: bool = False,
    ) -> Path:
        """
        Resolves a logical specifier to a verified local Path.
        """
        if not logical_spec:
            raise ArtifactResolutionError("Artifact specification cannot be empty")

        spec = str(logical_spec).strip()
        input_dir = input_dir.resolve()
        work_dir = work_dir.resolve()

        if spec.startswith("input:"):
            rel_name = spec[len("input:"):].strip().lstrip("/\\")
            target = (input_dir / rel_name).resolve()
            if not target.is_relative_to(input_dir):
                raise ArtifactResolutionError(f"Path traversal blocked: '{spec}' resolves outside input directory")
            if require_exists and not target.exists():
                raise FileNotFoundError(f"Input artifact not found: {spec} -> {target}")
            return target

        if spec.startswith("work:"):
            rel_name = spec[len("work:"):].strip().lstrip("/\\")
            target = (work_dir / rel_name).resolve()
            if not target.is_relative_to(work_dir):
                raise ArtifactResolutionError(f"Path traversal blocked: '{spec}' resolves outside work directory")
            if require_exists and not target.exists():
                raise FileNotFoundError(f"Work artifact not found: {spec} -> {target}")
            return target

        # Unprefixed path: first check work_dir, then input_dir
        p = Path(spec)
        if p.is_absolute():
            resolved = p.resolve()
            if resolved.is_relative_to(work_dir) or resolved.is_relative_to(input_dir):
                return resolved
            raise ArtifactResolutionError(f"Path traversal blocked: absolute path '{spec}' outside challenge boundaries is forbidden")


        work_target = (work_dir / p).resolve()
        if work_target.is_relative_to(work_dir) and work_target.exists():
            return work_target

        input_target = (input_dir / p).resolve()
        if input_target.is_relative_to(input_dir) and input_target.exists():
            return input_target

        # Default fallback to work_dir if doesn't exist yet
        if not work_target.is_relative_to(work_dir):
            raise ArtifactResolutionError(f"Path traversal blocked for relative path: {spec}")
        if require_exists:
            raise FileNotFoundError(f"Artifact not found in work or input: {spec}")
        return work_target

    @staticmethod
    def resolve_container(
        logical_spec: str,
        input_dir: Optional[Path] = None,
        work_dir: Optional[Path] = None,
    ) -> str:
        """
        Resolves a logical specifier to an in-container absolute path (/input/... or /work/...).
        """
        spec = str(logical_spec).strip()
        if spec.startswith("input:"):
            rel_name = spec[len("input:"):].strip().lstrip("/\\")
            if ".." in rel_name:
                raise ArtifactResolutionError(f"Path traversal in container spec blocked: {spec}")
            return f"/input/{rel_name}"

        if spec.startswith("work:"):
            rel_name = spec[len("work:"):].strip().lstrip("/\\")
            if ".." in rel_name:
                raise ArtifactResolutionError(f"Path traversal in container spec blocked: {spec}")
            return f"/work/{rel_name}"

        # If unprefixed: check existence in local input/work to decide container prefix
        clean_rel = spec.lstrip("/\\")
        if ".." in clean_rel:
            raise ArtifactResolutionError(f"Path traversal blocked: {spec}")

        if input_dir and (input_dir.resolve() / clean_rel).exists():
            return f"/input/{clean_rel}"

        # Default in-container working directory is /work
        return f"/work/{clean_rel}"

    @classmethod
    def translate_argv(
        cls,
        argv: List[str],
        input_dir: Path,
        work_dir: Path,
        in_container: bool = False,
    ) -> List[str]:
        """
        Rewrites argument tokens containing logical specs ('input:...', 'work:...')
        to their actual resolved target representations.
        """
        translated: List[str] = []
        for arg in argv:
            if "input:" in arg or "work:" in arg:
                # Handle argument flags like --file=input:vuln or standalone input:vuln
                if "=" in arg:
                    prefix, spec = arg.split("=", 1)
                    if spec.startswith("input:") or spec.startswith("work:"):
                        resolved = (
                            cls.resolve_container(spec, input_dir, work_dir)
                            if in_container
                            else str(cls.resolve_local(spec, input_dir, work_dir))
                        )
                        translated.append(f"{prefix}={resolved}")
                        continue
                if arg.startswith("input:") or arg.startswith("work:"):
                    resolved = (
                        cls.resolve_container(arg, input_dir, work_dir)
                        if in_container
                        else str(cls.resolve_local(arg, input_dir, work_dir))
                    )
                    translated.append(resolved)
                    continue
            translated.append(arg)
        return translated
