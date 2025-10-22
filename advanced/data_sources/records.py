"""
Data source records and utilities for GitHub data processing.
"""
from datetime import datetime
from typing import Dict, List, Any, Optional


class GitHubRecord:
    """Represents a record from GitHub API."""
    
    def __init__(self, data: Dict[str, Any]):
        self.data = data
        self.created_at = parse_github_datetime(data.get('created_at'))
        self.updated_at = parse_github_datetime(data.get('updated_at'))
    
    def __repr__(self):
        return f"GitHubRecord(created={self.created_at}, updated={self.updated_at})"


class IssueRecord(GitHubRecord):
    """Represents a GitHub issue record."""
    
    def __init__(self, data: Dict[str, Any]):
        super().__init__(data)
        self.title = data.get('title', '')
        self.state = data.get('state', 'unknown')
        self.closed_at = parse_github_datetime(data.get('closed_at'))


class PullRequestRecord(GitHubRecord):
    """Represents a GitHub pull request record."""
    
    def __init__(self, data: Dict[str, Any]):
        super().__init__(data)
        self.title = data.get('title', '')
        self.merged = data.get('merged', False)
        self.merged_at = parse_github_datetime(data.get('merged_at'))


class CommitRecord(GitHubRecord):
    """Represents a GitHub commit record."""
    
    def __init__(self, data: Dict[str, Any]):
        super().__init__(data)
        self.sha = data.get('sha', '')
        self.message = data.get('commit', {}).get('message', '')
        self.author_date = parse_github_datetime(
            data.get('commit', {}).get('author', {}).get('date')
        )


class RepositoryRecord:
    """Represents a GitHub repository record."""
    
    def __init__(self, data: Dict[str, Any]):
        self.data = data
        self.name = data.get('name', '')
        self.created_at = parse_github_datetime(data.get('created_at'))
        self.updated_at = parse_github_datetime(data.get('updated_at'))
        self.pushed_at = parse_github_datetime(data.get('pushed_at'))


def parse_github_datetime(dt_str: Optional[str]) -> datetime:
    """Parse GitHub API datetime string to datetime object.
    
    Args:
        dt_str: GitHub datetime string (ISO 8601 format), or None
    
    Returns:
        Parsed datetime object
    
    Raises:
        ValueError: If dt_str is None, empty, or cannot be parsed
    """
    # Validate input is not None or empty
    if dt_str is None or dt_str == '':
        raise ValueError("Missing GitHub datetime string")
    
    try:
        # Remove 'Z' suffix and parse
        clean_str = dt_str.rstrip('Z')
        return datetime.fromisoformat(clean_str)
    except Exception as e:
        # Raise clear error with original input and underlying error
        raise ValueError(
            f"Failed to parse GitHub datetime string '{dt_str}': {str(e)}"
        ) from e


def fetch_repository_records(repo_data: List[Dict[str, Any]]) -> List[RepositoryRecord]:
    """Convert list of repository data to RepositoryRecord objects."""
    return [RepositoryRecord(data) for data in repo_data]


def fetch_issue_records(issue_data: List[Dict[str, Any]]) -> List[IssueRecord]:
    """Convert list of issue data to IssueRecord objects."""
    return [IssueRecord(data) for data in issue_data]


def fetch_pr_records(pr_data: List[Dict[str, Any]]) -> List[PullRequestRecord]:
    """Convert list of PR data to PullRequestRecord objects."""
    return [PullRequestRecord(data) for data in pr_data]


def fetch_commit_records(commit_data: List[Dict[str, Any]]) -> List[CommitRecord]:
    """Convert list of commit data to CommitRecord objects."""
    return [CommitRecord(data) for data in commit_data]
