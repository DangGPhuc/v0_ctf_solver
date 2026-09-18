import os
import shutil
import tempfile
import unittest
from pathlib import Path

from ctf_core.prompts.spec import PromptSpec
from ctf_core.prompts.state_capsule import StateCapsule
from ctf_core.prompts.linter import PromptLinter, LintViolation
from ctf_core.prompts.templates import CTFTemplates
from ctf_core.prompts.compiler import PromptCompiler
from ctf_core.services.advisor_service import AdvisorService
from ctf_core.runtime.manager import RuntimeManager
from ctf_core.models import Challenge


class TestPromptMasterEngine(unittest.TestCase):
    def setUp(self):
        self.test_dir = Path(tempfile.mkdtemp())
        self.capsule = StateCapsule(
            challenge_id="rev101",
            challenge_name="Simple_Rev",
            category="Rev",
            confirmed_facts=["Binary is ELF 64-bit stripped", "XOR loop at 0x401122"],
            active_hypothesis="Key is 1-byte XOR",
            rejected_hypotheses=[{"name": "H_Brute", "reason": "Sample space 2^64 too large"}],
            recent_progress=[
                {"id": "EXP-01", "status": "CONFIRMED", "actions": "GDB break 0x401122", "observed": "al = 0x5a"}
            ],
            unresolved_questions=["Where is the salt stored?"],
            retrieved_hints=[{"source": "Card_srev", "hint": "Check string table references"}],
        )

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_state_capsule_rendering(self):
        md = self.capsule.to_markdown()
        self.assertIn("STATE CAPSULE: Simple_Rev", md)
        self.assertIn("Binary is ELF 64-bit stripped", md)
        self.assertIn("TUYỆT ĐỐI KHÔNG LẶP LẠI", md)
        self.assertIn("H_Brute", md)
        self.assertIn("KHÔNG PHẢI FACT", md)

    def test_prompt_spec_and_templates(self):
        spec = PromptSpec(
            task_objective="Analyze main function",
            state_capsule=self.capsule,
            task_type="triage",
            target_agent="advisor",
            target_backend="chatgpt",
        )
        self.assertEqual(spec.target_agent, "advisor")
        rendered_advisor = CTFTemplates.render_advisor_contract(spec)
        self.assertIn("STRATEGIC ADVISOR DIRECTIVE", rendered_advisor)
        self.assertIn("Auditable Output Contract", rendered_advisor)

        spec.target_agent = "executor"
        rendered_executor = CTFTemplates.render_executor_contract(spec)
        self.assertIn("EXECUTOR TASK CONTRACT", rendered_executor)
        self.assertIn("AGENTIC STOP CONDITIONS", rendered_executor)
        self.assertIn("MANDATORY RETURN FORMAT", rendered_executor)

    def test_prompt_linter_detection_and_repair(self):
        # Tạo spec thiếu stop_conditions, scope, v.v.
        broken_spec = PromptSpec(
            task_objective="Do whatever you want",
            state_capsule=self.capsule,
            allowed_scope=[],
            forbidden_scope=[],
            stop_conditions=[],
            evidence_contract=[],
            success_criteria=[],
        )

        violations = PromptLinter.lint(broken_spec)
        rule_ids = [v.rule_id for v in violations]
        self.assertIn("NO_STOP_CONDITIONS", rule_ids)
        self.assertIn("NO_ALLOWED_SCOPE", rule_ids)
        self.assertIn("NO_FORBIDDEN_SCOPE", rule_ids)
        self.assertIn("NO_SUCCESS_CRITERIA", rule_ids)
        self.assertIn("NO_EVIDENCE_CONTRACT", rule_ids)

        repaired_spec, rep_violations = PromptLinter.lint_and_repair(broken_spec)
        self.assertTrue(len(repaired_spec.stop_conditions) > 0)
        self.assertTrue(len(repaired_spec.allowed_scope) > 0)
        self.assertTrue(len(repaired_spec.forbidden_scope) > 0)
        self.assertTrue(len(repaired_spec.evidence_contract) > 0)

    def test_linter_detects_targeting_rejected_hypothesis(self):
        # Mục tiêu thử lại giả thuyết đã bị rejected
        bad_spec = PromptSpec(
            task_objective="Let us test H_Brute again with same parameters",
            state_capsule=self.capsule,
        )
        violations = PromptLinter.lint(bad_spec)
        rule_ids = [v.rule_id for v in violations]
        self.assertIn("TARGETING_REJECTED_HYPOTHESIS", rule_ids)

    def test_compiler_end_to_end_advisor_service(self):
        # Tạo challenge workspace
        chall = Challenge(
            id=202,
            name="Crypto_Vault",
            category="Crypto",
            points=200,
            description="Crack the RSA vault",
            connection_info="nc 10.10.10.10 5000",
        )
        rm = RuntimeManager(base_dir=self.test_dir / ".runtime")
        rm.materialize_challenge("default_event", chall)
        service = AdvisorService(workspace_dir=self.test_dir, runtime_manager=rm, event_id="default_event")
        service.init_challenge_advisor(202)

        capsule = service.get_state_capsule(202)
        self.assertEqual(capsule.challenge_id, "202")
        self.assertEqual(capsule.category, "Crypto")

        repaired_spec, violations = service.lint_challenge_prompt(202, target_agent="advisor")
        self.assertIsNotNone(repaired_spec)

        prompt_text, viols = service.show_compiled_prompt(202, target_agent="advisor")
        self.assertIn("STRATEGIC ADVISOR DIRECTIVE", prompt_text)
        self.assertIn("Template E: Auditable Reasoning", prompt_text)

        exec_text, _ = service.show_compiled_prompt(202, target_agent="executor")
        self.assertIn("EXECUTOR TASK CONTRACT", exec_text)
        self.assertIn("Template H: ReAct + Stop Conditions", exec_text)


if __name__ == "__main__":
    unittest.main()
