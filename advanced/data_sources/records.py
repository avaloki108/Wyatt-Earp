"""
Data source records module for handling GitHub data.
"""

from datetime import datetime
from typing import Dict, Any, List, Optional


class GitHubRecord:
    """Represents a GitHub data record."""

    def __init__(self, data: Dict[str, Any]):
        self.data = data
        self.created_at = parse_github_datetime(data.get("created_at", ""))
        self.updated_at = parse_github_datetime(data.get("updated_at", ""))

    def __repr__(self):
        return (
            f"GitHubRecord(created_at={self.created_at}, updated_at={self.updated_at})"
        )


class RecordCollection:
    """Collection of GitHub records."""

    def __init__(self):
        self.records: List[GitHubRecord] = []

    def add(self, record: GitHubRecord):
        """Add a record to the collection."""
        self.records.append(record)

    def count(self) -> int:
        """Get the count of records."""
        return len(self.records)


def fetch_github_data(endpoint: str) -> List[Dict[str, Any]]:
    """
    Fetch data from GitHub API endpoint.

    Args:
        endpoint: API endpoint to fetch from

    Returns:
        List of data dictionaries
    """
    # Placeholder implementation
    return []


def parse_github_datetime(dt_string: Optional[str]) -> datetime:
    """
    Parse a GitHub datetime string into a datetime object.

    Args:
        dt_string: GitHub datetime string in ISO 8601 format, or None

    Returns:
        Parsed datetime object

    Raises:
        ValueError: If dt_string is None, empty, or invalid format
    """
    # Validate input - check for None or empty string
    if dt_string is None or dt_string == "":
        raise ValueError("Missing GitHub datetime string")

    try:
        # Try to parse the datetime string
        return datetime.fromisoformat(dt_string.replace("Z", "+00:00"))
    except (ValueError, AttributeError) as e:
        # Raise clear error with original input and underlying error
        raise ValueError(
            f"Failed to parse GitHub datetime string '{dt_string}': {str(e)}"
        ) from e


def process_records(data: List[Dict[str, Any]]) -> RecordCollection:
    """
    Process raw GitHub data into a record collection.

    Args:
        data: List of raw GitHub data dictionaries

    Returns:
        RecordCollection containing processed records
    """
    collection = RecordCollection()
    for item in data:
        record = GitHubRecord(item)
        collection.add(record)
    return collection
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
