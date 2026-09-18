from pathlib import Path
from typing import Optional, Dict, Any
from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

class CTFSettings(BaseSettings):
    platform_url: Optional[str] = Field(default=None, validation_alias="PLATFORM_URL")
    session_cookie: Optional[str] = Field(default=None, validation_alias="SESSION_COOKIE")
    api_token: Optional[str] = Field(default=None, validation_alias="API_TOKEN")
    refresh_token: Optional[str] = Field(default=None, validation_alias="REFRESH_TOKEN")
    token_expires_at: Optional[float] = Field(default=None, validation_alias="TOKEN_EXPIRES_AT")
    flag_format: Optional[str] = Field(default=r"^FLAG\{.+\}$", validation_alias="FLAG_FORMAT")
    timeout: int = Field(default=30, validation_alias="TIMEOUT")
    workspace_dir: Optional[str] = Field(default=None, validation_alias="WORKSPACE_DIR")

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore"
    )

def find_env_file(start_dir: Optional[Path] = None) -> Optional[Path]:
    """
    Tìm kiếm tệp .env bằng cách duyệt ngược từ start_dir lên các thư mục cha.
    """
    curr = (start_dir or Path.cwd()).resolve()
    for directory in [curr, *curr.parents]:
        env_candidate = directory / ".env"
        if env_candidate.is_file():
            return env_candidate
    return None

def load_config(start_dir: Optional[Path] = None, explicit_env: Optional[Path] = None) -> CTFSettings:
    """
    Nạp cấu hình từ tệp .env được chỉ định hoặc tìm tự động từ start_dir.
    """
    target_env = explicit_env
    if not target_env:
        target_env = find_env_file(start_dir)
    
    if target_env and target_env.is_file():
        return CTFSettings(_env_file=str(target_env))
    return CTFSettings()

import os

def save_env_file(target_file: Path, values: Dict[str, Any]) -> Path:
    """
    Ghi hoặc cập nhật các biến cấu hình vào tệp .env kèm phân quyền bảo mật 0600.
    """
    target_file = Path(target_file).resolve()
    target_file.parent.mkdir(parents=True, exist_ok=True)
    existing: Dict[str, str] = {}
    
    if target_file.is_file():
        for line in target_file.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, v = line.split("=", 1)
            existing[k.strip()] = v.strip().strip("'\"")
            
    for k, v in values.items():
        if v is not None:
            existing[k] = str(v)
            
    lines = [
        "# Anti-IDE CTF Lifecycle Environment",
        "# Tự động sinh để phục vụ Anti-IDE requests & solver scripts",
        ""
    ]
    for k, v in sorted(existing.items()):
        lines.append(f'{k}="{v}"')
    lines.append("")
    
    target_file.write_text("\n".join(lines), encoding="utf-8")
    try:
        os.chmod(target_file, 0o600)
    except Exception:
        pass
    return target_file
