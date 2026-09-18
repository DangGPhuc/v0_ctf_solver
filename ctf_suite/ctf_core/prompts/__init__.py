"""
Prompt Master Engine for CTF Suite (inspired by nidhinjs/prompt-master).
Provides 9-dimensional Intent Extraction, State Capsule distillation,
Anti-Pattern Linting, and High-Fidelity Prompt Contracts (Template H & Template E).
"""

from .spec import PromptSpec
from .state_capsule import StateCapsule
from .linter import PromptLinter, LintViolation
from .templates import CTFTemplates
from .compiler import PromptCompiler

__all__ = [
    "PromptSpec",
    "StateCapsule",
    "PromptLinter",
    "LintViolation",
    "CTFTemplates",
    "PromptCompiler",
]
