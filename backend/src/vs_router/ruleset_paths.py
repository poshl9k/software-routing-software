"""Stable on-disk locations for rule-set sources owned by the agent."""
from pathlib import Path

SOURCES_DIR = Path("/var/lib/vs-router/sources")


def active_rule_set_path(name: str, kind: str = "rule_set") -> Path:
    """Path of the atomically activated rule-set file used by sing-box."""
    return SOURCES_DIR / "active" / f"{name}.{kind}"
