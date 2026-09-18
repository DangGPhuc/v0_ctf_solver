from datetime import datetime
from typing import Any, Dict, List, Literal, Optional
from pydantic import BaseModel, Field

SubmitVerdict = Literal[
    "correct",
    "incorrect",
    "already_solved",
    "ratelimited",
    "auth_failed",
    "error",
]

class ContainerInfo(BaseModel):
    status: str = "stopped"  # running, stopped, expired, error
    entry: Optional[str] = None  # e.g. "chall.ctf.com:31337" or "http://chall.ctf.com:8080"
    host: Optional[str] = None
    port: Optional[int] = None
    remaining_seconds: Optional[int] = None
    message: Optional[str] = None
    raw: Dict[str, Any] = Field(default_factory=dict)

class SubmitResult(BaseModel):
    verdict: SubmitVerdict
    message: str
    challenge_id: Any
    challenge_name: Optional[str] = None
    flag: str
    points: Optional[int] = None
    timestamp: str = Field(default_factory=lambda: datetime.now().isoformat())

class Challenge(BaseModel):
    id: Any
    name: str
    category: str = "Misc"
    points: int = 0
    description: str = ""
    author: Optional[str] = None
    tags: List[str] = Field(default_factory=list)
    hints: List[Dict[str, Any]] = Field(default_factory=list)
    files: List[Dict[str, str]] = Field(default_factory=list)  # [{"name": "chall.zip", "url": "..."}]
    connection_info: Optional[str] = None
    solved_by_me: bool = False
    solves_count: Optional[int] = None
    is_dynamic_container: bool = False
    instance_info: Optional[ContainerInfo] = None
    raw_data: Dict[str, Any] = Field(default_factory=dict)

class CTFInfo(BaseModel):
    title: str = "CTF Competition"
    description: str = ""
    platform: str = "generic"
    url: str = ""
    user_name: Optional[str] = None
    team_name: Optional[str] = None
    flag_format: Optional[str] = None
    challenges: List[Challenge] = Field(default_factory=list)
