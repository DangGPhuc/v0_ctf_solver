"""
CTF Solver Experiments Module: Explicit Evidence-Driven Reasoning Loop.
"""

from ..models import (
    ExecutionAction,
    ExecutionResult,
    Experiment,
    ExperimentCandidate,
    ExperimentEvaluation,
    ExperimentProposal,
    Hypothesis,
    HypothesisRecord,
)
from .evidence_evaluator import EvidenceEvaluator
from .hypothesis_manager import HypothesisManager, UnknownHypothesisError
from .ledger import ExperimentLedger, UnknownExperimentError
from .planner import CandidateEvaluation, ExperimentPlanner, SelectionResult
from .progress import SolverProgress, SolverProgressTracker, normalize_evidence_key
from .signatures import are_experiments_equivalent, compute_experiment_signature

__all__ = [
    "Hypothesis",
    "HypothesisRecord",
    "Experiment",
    "ExperimentProposal",
    "ExperimentCandidate",
    "ExperimentEvaluation",
    "ExecutionAction",
    "ExecutionResult",
    "HypothesisManager",
    "UnknownHypothesisError",
    "ExperimentLedger",
    "UnknownExperimentError",
    "EvidenceEvaluator",
    "ExperimentPlanner",
    "SelectionResult",
    "CandidateEvaluation",
    "SolverProgress",
    "SolverProgressTracker",
    "normalize_evidence_key",
    "compute_experiment_signature",
    "are_experiments_equivalent",
]
