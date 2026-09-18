from datetime import datetime
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field

class KnowledgeQuery(BaseModel):
    category: Optional[str] = None
    tags: List[str] = Field(default_factory=list)
    keywords: List[str] = Field(default_factory=list)
    file_types: List[str] = Field(default_factory=list)
    protections: List[str] = Field(default_factory=list)
    current_hypothesis: Optional[str] = None

class KnowledgeHit(BaseModel):
    id: str
    score: float
    matched_on: List[str] = Field(default_factory=list)
    path: str
    kind: str = "technique"
    status: str = "active"
    blob_sha: str = ""
    title: str = ""
    summary: str = ""

class KnowledgeDocument(BaseModel):
    id: str
    title: str
    category: str
    tags: List[str] = Field(default_factory=list)
    status: str = "active"
    summary: str = ""
    signals: List[str] = Field(default_factory=list)
    technique_steps: List[str] = Field(default_factory=list)
    verification: List[str] = Field(default_factory=list)
    failure_modes: List[str] = Field(default_factory=list)
    tool_hints: List[str] = Field(default_factory=list)
    content_raw: str = ""
    blob_sha: str = ""

    @property
    def content(self) -> str:
        return self.content_raw


class RetrievedKnowledgeContext(BaseModel):
    id: str
    title: str
    category: str
    summary: str = ""
    technique_steps: List[str] = Field(default_factory=list)
    source: str = "v0_ctf_knowledge"
    confidence: float = 1.0

    @classmethod
    def from_doc(cls, doc: KnowledgeDocument, confidence: float = 1.0) -> "RetrievedKnowledgeContext":
        return cls(
            id=doc.id,
            title=doc.title,
            category=doc.category,
            summary=doc.summary,
            technique_steps=list(doc.technique_steps),
            source=doc.id,
            confidence=confidence,
        )

