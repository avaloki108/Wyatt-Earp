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
