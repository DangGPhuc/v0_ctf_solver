"""
Meta-Layer Subsystem for CTF Suite (inspired by Dream-RSI).
Manages Discovery Trees (DAG), Exploration Policies, Offline Replay Simulation,
and Declarative Knowledge Compilation.
"""

from .tree import DiscoveryTree, DiscoveryNode
from .policy import ExplorationPolicy
from .event_recorder import EventRecorder
from .simulator import ReplaySimulator, ReplayResult
from .scorer import PolicyScorer
from .knowledge_compiler import KnowledgeCompiler, KnowledgeRetriever

__all__ = [
    "DiscoveryTree",
    "DiscoveryNode",
    "ExplorationPolicy",
    "EventRecorder",
    "ReplaySimulator",
    "ReplayResult",
    "PolicyScorer",
    "KnowledgeCompiler",
    "KnowledgeRetriever",
]
