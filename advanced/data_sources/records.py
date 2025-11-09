"""Common data models for structured hack ingestion."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List


@dataclass
class HackRecord:
    """Normalized representation of an external hack or exploit record."""

    uid: str
    title: str
    description: str
    discovered_at: datetime
    severity: str
    source: str
    references: List[str] = field(default_factory=list)
    artifacts: Dict[str, Any] = field(default_factory=dict)

    def to_learning_payload(self) -> Dict[str, Any]:
        """Convert the record into the structure expected by :class:`AutoLearner`."""

        snippet = self.artifacts.get("code_snippet")
        if not snippet and self.artifacts.get("files"):
            # Extract the first patch or raw fragment if available.
            for file_info in self.artifacts["files"]:
                patch = file_info.get("patch")
                if patch:
                    snippet = patch
                    break
                fragment = file_info.get("raw_preview")
                if fragment:
                    snippet = fragment
                    break

        affected_contracts = []
        for file_info in self.artifacts.get("files", []):
            filename = file_info.get("filename")
            if filename:
                affected_contracts.append(filename)

        payload = {
            "id": self.uid,
            "date": self.discovered_at.isoformat(),
            "title": self.title,
            "description": self.description,
            "impact": self.severity,
            "affected_contracts": affected_contracts,
            "exploit_code_snippet": snippet or "",
            "source": self.source,
            "references": self.references,
            "artifacts": self.artifacts,
        }
        return payload


def parse_github_datetime(value: str) -> datetime:
    """Parse an ISO 8601 timestamp returned by the GitHub API."""

    try:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError:
        # Fallback: attempt to parse without trailing Z
        return datetime.fromisoformat(value)
