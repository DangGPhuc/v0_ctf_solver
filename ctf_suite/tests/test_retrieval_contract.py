import pytest
from pathlib import Path
from unittest.mock import MagicMock

from ctf_core.services.advisor_service import AdvisorService
from ctf_core.knowledge.models import KnowledgeDocument, KnowledgeHit, RetrievedKnowledgeContext
from ctf_core.prompts.compiler import PromptCompiler
from ctf_core.prompts.state_capsule import StateCapsule


def test_retrieved_knowledge_context_from_doc():
    doc = KnowledgeDocument(
        id="pwn.rop.ret2libc",
        title="Ret2Libc Attack Pattern",
        category="pwn",
        summary="Standard ret2libc exploit using puts to leak libc base",
        technique_steps=[
            "Leak libc base using puts(puts@got)",
            "Compute system address and /bin/sh string",
            "Return to system('/bin/sh')",
        ],
    )
    ctx = RetrievedKnowledgeContext.from_doc(doc, confidence=0.92)
    assert ctx.id == "pwn.rop.ret2libc"
    assert ctx.title == "Ret2Libc Attack Pattern"
    assert len(ctx.technique_steps) == 3
    assert ctx.confidence == 0.92


def test_build_state_capsule_with_retrieved_context(tmp_path):
    doc = KnowledgeDocument(
        id="pwn.rop.ret2libc",
        title="Ret2Libc Attack Pattern",
        category="pwn",
        technique_steps=[
            "Leak libc base using puts(puts@got)",
            "Return to system('/bin/sh')",
        ],
    )
    cards = [RetrievedKnowledgeContext.from_doc(doc, confidence=0.85)]
    state = {
        "active_hypothesis_id": "H1",
        "active_hypothesis_statement": "Buffer overflow reaches saved RIP",
    }
    capsule = PromptCompiler.build_state_capsule(
        chall_dir=tmp_path,
        state=state,
        retrieved_cards=cards,
    )
    assert capsule.active_hypothesis_id == "H1"
    assert capsule.active_hypothesis_statement == "Buffer overflow reaches saved RIP"
    assert len(capsule.retrieved_hints) == 2
    assert "Leak libc base" in capsule.retrieved_hints[0]["hint"]
    md = capsule.to_markdown()
    assert "[H1] Buffer overflow reaches saved RIP" in md
    assert "Leak libc base" in md


def test_compile_context_hypotheses_resolution_and_error_taxonomy(tmp_path):
    mock_provider = MagicMock()
    mock_doc = KnowledgeDocument(
        id="web.sqli.blind",
        title="Blind SQL Injection",
        category="web",
        technique_steps=["Inject boolean condition into parameter"],
    )
    mock_provider.search.return_value = [
        KnowledgeHit(id="web.sqli.blind", score=0.8, matched_on=["sqli"], path="web/sqli.md")
    ]
    mock_provider.fetch.return_value = mock_doc

    from ctf_core.runtime.manager import RuntimeManager
    rt = RuntimeManager(runtime_root=tmp_path / ".runtime")
    advisor = AdvisorService(
        workspace_dir=tmp_path,
        runtime_manager=rt,
        event_id="test_event",
        knowledge_provider=mock_provider,
    )

    # Set up runtime challenge directory
    chall_dir = tmp_path / ".runtime" / "test_event" / "challenges" / "101"
    chall_dir.mkdir(parents=True)
    advisor_dir = chall_dir / ".advisor"

    advisor_dir.mkdir(parents=True)
    state_file = advisor_dir / "state.json"
    state_data = {
        "challenge_id": "101",
        "name": "SuperSQLi",
        "category": "web",
        "active_hypothesis": "H2",
        "hypotheses": [
            {"id": "H1", "statement": "Check for SSTI in template"},
            {"id": "H2", "statement": "Check for blind SQLi in id param"},
        ],
    }
    import json
    state_file.write_text(json.dumps(state_data), encoding="utf-8")

    # Call compile_context
    ctx = advisor.compile_context("101")
    assert ctx["retrieval_status"] == "SUCCESS"
    assert len(ctx["retrieved_cards"]) == 1
    assert ctx["retrieved_cards"][0].id == "web.sqli.blind"
    assert ctx["state_capsule"].active_hypothesis_id == "H2"

    # Test error taxonomy on network failure
    mock_provider.search.side_effect = ConnectionError("Remote connection timed out")
    ctx_err = advisor.compile_context("101")
    assert ctx_err["retrieval_status"] == "REMOTE_UNAVAILABLE"
    assert len(ctx_err["retrieved_cards"]) == 0
