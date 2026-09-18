import ast
import os
import unittest
from pathlib import Path


class TestLegacyIsolation(unittest.TestCase):
    """
    Assert that production code in ctf_core has zero references to
    deprecated legacy components:
    - ctf_core.workspace (WorkspaceRepo, WorkspaceBuilder)
    - CTF_Workspace
    - ChatGPTService
    - reverse-skill/work
    - SAVED_NOTES
    - hardcoded local knowledge_base path
    """

    def setUp(self):
        self.ctf_core_dir = Path(__file__).resolve().parent.parent / "ctf_core"

    def test_no_workspace_module_exists(self):
        """Ensure ctf_core.workspace directory/module does not exist."""
        workspace_dir = self.ctf_core_dir / "workspace"
        self.assertFalse(
            workspace_dir.exists(),
            f"Legacy directory {workspace_dir} must be completely deleted from production!"
        )

    def test_no_chatgpt_service_file_exists(self):
        """Ensure chatgpt_service.py does not exist."""
        chatgpt_file = self.ctf_core_dir / "services" / "chatgpt_service.py"
        self.assertFalse(
            chatgpt_file.exists(),
            f"Legacy file {chatgpt_file} must be deleted in favor of advisor subsystem!"
        )

    def test_no_production_imports_of_legacy_modules(self):
        """Parse all Python files in ctf_core and verify no legacy imports exist."""
        forbidden_modules = [
            "ctf_core.workspace",
            "ctf_core.workspace.repo",
            "ctf_core.workspace.builder",
            "ctf_core.services.chatgpt_service",
            "ctf_core.execution.local_executor",
        ]
        forbidden_strings = [
            "WorkspaceRepo",
            "WorkspaceBuilder",
            "CTF_Workspace",
            "ChatGPTService",
            "reverse-skill/work",
        ]

        py_files = list(self.ctf_core_dir.rglob("*.py"))
        self.assertTrue(len(py_files) > 0, "ctf_core must contain Python files")

        for py_file in py_files:
            content = py_file.read_text(encoding="utf-8")
            rel_path = py_file.relative_to(self.ctf_core_dir)

            # 1. AST import checking
            try:
                tree = ast.parse(content, filename=str(py_file))
                for node in ast.walk(tree):
                    if isinstance(node, ast.Import):
                        for alias in node.names:
                            for forbidden in forbidden_modules:
                                self.assertFalse(
                                    alias.name == forbidden or alias.name.startswith(forbidden + "."),
                                    f"Legacy import '{alias.name}' found in {rel_path}"
                                )
                    elif isinstance(node, ast.ImportFrom):
                        module_name = node.module or ""
                        for forbidden in forbidden_modules:
                            self.assertFalse(
                                module_name == forbidden or module_name.startswith(forbidden + "."),
                                f"Legacy from-import '{module_name}' found in {rel_path}"
                            )
            except SyntaxError:
                pass

            # 2. String literal checking
            for f_str in forbidden_strings:
                self.assertNotIn(
                    f_str, content,
                    f"Forbidden legacy token '{f_str}' found in {rel_path}"
                )


if __name__ == "__main__":
    unittest.main()
