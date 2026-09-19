import json
import re
from typing import List, Optional

from ..models import Action, AdvisorGuidance, Hypothesis


class GuidanceParser:
    """
    Parses and validates advisor markdown/text output into structured AdvisorGuidance.
    Enforces the critical security invariant:
      - Only structured JSON execution plans are parsed into ExecutionAction objects.
      - Human-readable prose or text actions are NEVER converted into executable shell commands.
    """

    @classmethod
    def parse(cls, text: str) -> AdvisorGuidance:
        if not text:
            return AdvisorGuidance(raw_text="")

        # 1. Try to extract JSON codeblock (Mandatory Structured Execution Plan)
        json_match = re.search(r"```(?:json)?\s*(\{[\s\S]*?\})\s*```", text)
        if json_match:
            try:
                data = json.loads(json_match.group(1))
                if isinstance(data, dict):
                    data["raw_text"] = text

                    # Handle single 'experiment' dict
                    if "experiment" in data and isinstance(data["experiment"], dict) and "experiments" not in data:
                        data["experiments"] = [data["experiment"]]

                    # Support flat experiment specification
                    if "experiments" not in data and ("intent" in data or "expected_evidence" in data):
                        exp_id = data.get("experiment_id", "EXP-001")
                        hypo_id = data.get("hypothesis_id", "H1")
                        intent = data.get("intent", data.get("assessment", "Experiment action"))
                        expected_ev = data.get("expected_evidence", data.get("requested_evidence", []))
                        if isinstance(expected_ev, str):
                            expected_ev = [expected_ev]
                        contra_ev = data.get("contradicting_evidence", [])
                        if isinstance(contra_ev, str):
                            contra_ev = [contra_ev]
                        data["experiments"] = [{
                            "experiment_id": exp_id,
                            "hypothesis_id": hypo_id,
                            "intent": intent,
                            "execution_plan": data.get("execution_plan", []),
                            "expected_evidence": expected_ev,
                            "contradicting_evidence": contra_ev,
                        }]

                    # Cross-propagate execution_plan between root and experiments
                    if data.get("experiments"):
                        first_exp = data["experiments"][0]
                        if not data.get("execution_plan") and isinstance(first_exp, dict):
                            if first_exp.get("execution_plan"):
                                data["execution_plan"] = first_exp["execution_plan"]
                            elif first_exp.get("action"):
                                data["execution_plan"] = [first_exp["action"]]
                        elif data.get("execution_plan") and isinstance(first_exp, dict) and not first_exp.get("execution_plan") and not first_exp.get("action"):
                            first_exp["execution_plan"] = data["execution_plan"]

                    guidance = AdvisorGuidance.model_validate(data)
                    guidance.is_structured = True
                    return guidance
            except Exception as e:
                return AdvisorGuidance(
                    raw_text=text,
                    validation_error=f"Malformed or invalid structured JSON payload: {e}",
                    is_structured=False,
                )

        # 2. Heuristic parsing for human-readable display only.
        # CRITICAL INVARIANT: execution_plan remains empty. Prose next_actions is NEVER execution authority.
        assessment = ""
        ass_m = re.search(r"(?i)(?:assessment|root cause|phân tích)[:\s]+([^\n]+)", text)
        if ass_m:
            assessment = ass_m.group(1).strip()
        else:
            first_lines = [l.strip() for l in text.splitlines() if l.strip() and not l.startswith("#")]
            assessment = first_lines[0] if first_lines else "Initial assessment"

        hypotheses: List[Hypothesis] = []
        hypo_matches = re.findall(r"(?i)(?:H\d+|Hypothesis\s*\d+)[:\s]+([^\n]+)", text)
        for idx, h_text in enumerate(hypo_matches, 1):
            hypotheses.append(Hypothesis(id=f"H{idx}", statement=h_text.strip()))
        if not hypotheses:
            hypotheses.append(Hypothesis(id="H1", statement="Inspect binary and test exploit payload"))

        next_actions: List[Action] = []
        actions_matches = re.findall(r"(?i)(?:Action\s*\d*|Step\s*\d*|\d+\.)[:\s]+([^\n]+)", text)
        for act_text in actions_matches:
            act_s = act_text.strip()
            if len(act_s) > 5 and not any(kw in act_s.lower() for kw in ["hypothesis", "assessment"]):
                next_actions.append(Action(type="command", command_or_task=act_s))

        requested_evidence: List[str] = []
        ev_m = re.findall(r"(?i)(?:evidence|proof)[:\s]+([^\n]+)", text)
        for ev in ev_m:
            requested_evidence.append(ev.strip())

        stop_conditions: List[str] = []
        stop_m = re.findall(r"(?i)(?:stop condition|dừng khi)[:\s]+([^\n]+)", text)
        for sc in stop_m:
            stop_conditions.append(sc.strip())

        return AdvisorGuidance(
            assessment=assessment,
            hypotheses=hypotheses,
            execution_plan=[],
            next_actions=next_actions,
            requested_evidence=requested_evidence,
            stop_conditions=stop_conditions,
            raw_text=text,
            is_structured=False,
        )
