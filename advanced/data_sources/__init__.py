"""Data sources module for GitHub data handling."""

from .records import (
    GitHubRecord,
    RecordCollection,
    parse_github_datetime,
    fetch_github_data,
    process_records,
)

__all__ = [
    'GitHubRecord',
    'RecordCollection',
    'parse_github_datetime',
    'fetch_github_data',
    'process_records',
]
