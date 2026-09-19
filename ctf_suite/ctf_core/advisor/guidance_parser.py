import json
import re
from typing import List, Optional

from ..models import (
    Action,
    AdvisorGuidance,
    ExecutionAction,
    Experiment,
    ExperimentCandidate,
    ExperimentProposal,
    Hypothesis,
)


class GuidanceParser:
    """
    Parses and validates advisor markdown/text output into structured AdvisorGuidance.
    Enforces the critical security invariant:
      - Only structured JSON execution plans are parsed into ExecutionAction objects.
      - Human-readable prose or text actions are NEVER converted into executable shell commands.
      - The system (not the Advisor) owns experiment IDs and outcomes.
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

                    candidates: List[ExperimentCandidate] = []

                    # A. Structured 'experiment_candidates' list (Section 4 & 5)
                    if "experiment_candidates" in data and isinstance(data["experiment_candidates"], list):
                        for raw_c in data["experiment_candidates"][:3]:  # bounded max 2-3
                            if isinstance(raw_c, dict):
                                c_dict = dict(raw_c)
                                c_dict.pop("experiment_id", None)
                                c_dict.pop("id", None)
                                c_dict.pop("outcome", None)
                                c_dict.pop("actual_evidence", None)
                                candidates.append(ExperimentCandidate.model_validate(c_dict))

                    # B. Structured single 'experiment' object (Section 4 & 6)
                    elif "experiment" in data and isinstance(data["experiment"], dict):
                        exp_raw = dict(data["experiment"])
                        # Advisor does NOT own experiment_id or outcome
                        exp_raw.pop("experiment_id", None)
                        exp_raw.pop("id", None)
                        exp_raw.pop("outcome", None)
                        exp_raw.pop("actual_evidence", None)

                        # Parse execution plan if present inside experiment
                        if not exp_raw.get("execution_plan") and data.get("execution_plan"):
                            exp_raw["execution_plan"] = data["execution_plan"]

                        expected = exp_raw.get("expected_evidence", [])
                        if isinstance(expected, str):
                            expected = [expected] if expected else []
                        exp_raw["expected_evidence"] = expected

                        contra = exp_raw.get("contradicting_evidence", [])
                        if isinstance(contra, str):
                            contra = [contra] if contra else []
                        exp_raw["contradicting_evidence"] = contra

                        candidates.append(ExperimentCandidate.model_validate(exp_raw))

                    # C. Legacy 'experiments' list
                    elif "experiments" in data and isinstance(data["experiments"], list) and data["experiments"]:
                        first_exp = dict(data["experiments"][0])
                        first_exp.pop("experiment_id", None)
                        first_exp.pop("id", None)
                        first_exp.pop("outcome", None)
                        first_exp.pop("actual_evidence", None)
                        candidates.append(ExperimentCandidate.model_validate(first_exp))

                    # D. Backward compatibility: legacy execution_plan without experiment block
                    elif data.get("execution_plan"):
                        # Target first declared hypothesis if available
                        hypo_id = "H1"
                        if data.get("hypotheses") and isinstance(data["hypotheses"], list) and data["hypotheses"]:
                            first_h = data["hypotheses"][0]
                            if isinstance(first_h, dict) and first_h.get("id"):
                                hypo_id = str(first_h["id"])
                        elif data.get("hypothesis_id"):
                            hypo_id = str(data["hypothesis_id"])

                        expected = data.get("expected_evidence", data.get("requested_evidence", []))
                        if isinstance(expected, str):
                            expected = [expected] if expected else []

                        contra = data.get("contradicting_evidence", [])
                        if isinstance(contra, str):
                            contra = [contra] if contra else []

                        candidates.append(ExperimentCandidate(
                            hypothesis_id=hypo_id,
                            intent=data.get("intent", data.get("assessment", "Execute solver action")),
                            execution_plan=[ExecutionAction.model_validate(a) for a in data["execution_plan"]],
                            expected_evidence=expected,
                            contradicting_evidence=contra,
                        ))

                    if candidates:
                        data["experiment_candidates"] = [c.model_dump() for c in candidates]
                        first_cand = candidates[0]
                        proposal = ExperimentProposal(
                            hypothesis_id=first_cand.hypothesis_id,
                            intent=first_cand.intent,
                            execution_plan=first_cand.execution_plan,
                            expected_evidence=first_cand.expected_evidence,
                            contradicting_evidence=first_cand.contradicting_evidence,
                        )
                        data["experiment"] = proposal.model_dump()
                        if not data.get("execution_plan") and proposal.execution_plan:
                            data["execution_plan"] = [a.model_dump() for a in proposal.execution_plan]
                        if not data.get("experiments"):
                            data["experiments"] = [{
                                "experiment_id": "candidate",
                                "hypothesis_id": proposal.hypothesis_id,
                                "intent": proposal.intent,
                                "execution_plan": [a.model_dump() for a in proposal.execution_plan],
                                "expected_evidence": proposal.expected_evidence,
                                "contradicting_evidence": proposal.contradicting_evidence,
                            }]

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
