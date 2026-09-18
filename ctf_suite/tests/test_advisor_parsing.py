import pytest
from ctf_core.services.advisor_service import AdvisorService
from ctf_core.models import AdvisorGuidance, ExecutionAction


def test_parse_advisor_response_valid_structured_json():
    text = """
Here is my analysis of the challenge:

```json
{
  "assessment": "Vulnerability is a stack overflow in vuln() function",
  "hypotheses": [
    {
      "id": "H1",
      "statement": "Offset to RIP is 72 bytes",
      "confidence": 0.85,
      "rationale": "Buffer is 64 bytes and RBP is 8 bytes"
    }
  ],
  "execution_plan": [
    {
      "kind": "analysis_tool",
      "tool": "checksec",
      "argv": ["--file", "input:vuln"],
      "timeout": 15
    },
    {
      "kind": "run_solver",
      "path": "solve.py",
      "argv": ["python3", "solve.py"],
      "timeout": 30
    }
  ],
  "requested_evidence": ["checksec mitigation status", "flag output"],
  "stop_conditions": ["flag pattern captured in stdout"]
}
```

Good luck with the execution!
"""
    guidance = AdvisorService.parse_advisor_response(text)
    assert guidance.is_structured is True
    assert guidance.validation_error is None
    assert guidance.assessment == "Vulnerability is a stack overflow in vuln() function"
    assert len(guidance.hypotheses) == 1
    assert guidance.hypotheses[0].id == "H1"
    assert len(guidance.execution_plan) == 2
    assert guidance.execution_plan[0].kind == "analysis_tool"
    assert guidance.execution_plan[0].tool == "checksec"
    assert guidance.execution_plan[1].kind == "run_solver"


def test_parse_advisor_response_invalid_json():
    text = """
```json
{
  "assessment": "Broken JSON syntax",
  "execution_plan": [ INVALID SYNTAX HERE
}
```
"""
    guidance = AdvisorService.parse_advisor_response(text)
    assert guidance.is_structured is False
    assert guidance.validation_error is not None
    assert "JSON" in guidance.validation_error
    assert len(guidance.execution_plan) == 0


def test_parse_advisor_response_prose_does_not_fabricate_execution_plan():
    text = """
# Assessment
We need to reverse the logic of check_password().

## Hypotheses
H1: Password is XOR encoded with static key.

## Next Actions
1. Run gdb on the binary and break at check_password
2. Send test payload AAAA

## Evidence
Observe return value in RAX.
"""
    guidance = AdvisorService.parse_advisor_response(text)
    assert guidance.is_structured is False
    assert guidance.validation_error is None
    assert len(guidance.hypotheses) == 1
    assert guidance.hypotheses[0].id == "H1"
    # Execution plan MUST remain empty: prose is NEVER executed as shell!
    assert len(guidance.execution_plan) == 0
    # Next actions can hold human-readable steps
    assert len(guidance.next_actions) > 0
