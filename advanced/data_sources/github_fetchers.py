"""
GitHub data fetchers for vulnerability and exploit information.
"""
import logging
import requests
from datetime import datetime
from typing import List, Dict, Optional, Any
from dataclasses import dataclass

logger = logging.getLogger(__name__)


@dataclass
class HackRecord:
    """Record of a security hack or vulnerability."""
    sha: str
    title: str
    description: str
    date: datetime
    url: str
    severity: str = "unknown"
    
    def __repr__(self):
        return f"HackRecord(sha={self.sha[:8]}, title={self.title}, date={self.date})"


def parse_github_datetime(date_str: str) -> datetime:
    """Parse GitHub's datetime format.
    
    Args:
        date_str: DateTime string from GitHub API
        
    Returns:
        Parsed datetime object
        
    Raises:
        ValueError: If date_str is None or invalid format
    """
    if date_str is None:
        raise ValueError("Date string cannot be None")
    
    # GitHub uses ISO 8601 format
    try:
        return datetime.fromisoformat(date_str.replace('Z', '+00:00'))
    except (ValueError, AttributeError) as e:
        raise ValueError(f"Invalid date format: {date_str}") from e


class GitHubHackFetcher:
    """Fetches hack and vulnerability data from GitHub repositories."""
    
    def __init__(self, github_token: Optional[str] = None):
        """Initialize the fetcher.
        
        Args:
            github_token: Optional GitHub personal access token for API access
        """
        self.github_token = github_token
        self.base_url = "https://api.github.com"
        self.headers = {}
        if github_token:
            self.headers['Authorization'] = f'token {github_token}'
    
    def fetch_repository_commits(self, owner: str, repo: str, 
                                 path: Optional[str] = None,
                                 max_commits: int = 100) -> List[Dict[str, Any]]:
        """Fetch commits from a GitHub repository.
        
        Args:
            owner: Repository owner
            repo: Repository name
            path: Optional file path to filter commits
            max_commits: Maximum number of commits to fetch
            
        Returns:
            List of commit data dictionaries
        """
        url = f"{self.base_url}/repos/{owner}/{repo}/commits"
        params = {'per_page': min(max_commits, 100)}
        if path:
            params['path'] = path
        
        try:
            response = requests.get(url, headers=self.headers, params=params)
            response.raise_for_status()
            return response.json()
        except requests.RequestException as e:
            logger.error(f"Failed to fetch commits from {owner}/{repo}: {e}")
            return []
    
    def fetch_commit_details(self, owner: str, repo: str, sha: str) -> Optional[Dict[str, Any]]:
        """Fetch detailed information about a specific commit.
        
        Args:
            owner: Repository owner
            repo: Repository name
            sha: Commit SHA
            
        Returns:
            Commit details dictionary or None if fetch fails
        """
        url = f"{self.base_url}/repos/{owner}/{repo}/commits/{sha}"
        
        try:
            response = requests.get(url, headers=self.headers)
            response.raise_for_status()
            return response.json()
        except requests.RequestException as e:
            logger.error(f"Failed to fetch commit {sha} from {owner}/{repo}: {e}")
            return None
    
    def search_vulnerability_commits(self, query: str, max_results: int = 50) -> List[Dict[str, Any]]:
        """Search for commits related to vulnerabilities.
        
        Args:
            query: Search query (e.g., 'vulnerability', 'exploit', 'CVE')
            max_results: Maximum number of results to return
            
        Returns:
            List of commit search results
        """
        url = f"{self.base_url}/search/commits"
        params = {
            'q': query,
            'per_page': min(max_results, 100),
            'sort': 'committer-date',
            'order': 'desc'
        }
        # Note: Commit search requires special Accept header
        headers = self.headers.copy()
        headers['Accept'] = 'application/vnd.github.cloak-preview+json'
        
        try:
            response = requests.get(url, headers=headers, params=params)
            response.raise_for_status()
            return response.json().get('items', [])
        except requests.RequestException as e:
            logger.error(f"Failed to search commits with query '{query}': {e}")
            return []
    
    def parse_commits_to_hack_records(self, owner: str, repo: str, 
                                      commits: List[Dict[str, Any]]) -> List[HackRecord]:
        """Parse GitHub commits into HackRecord objects.
        
        Args:
            owner: Repository owner
            repo: Repository name
            commits: List of commit data from GitHub API
            
        Returns:
            List of HackRecord objects
        """
        hack_records = []
        
        for commit_data in commits:
            try:
                # Get commit SHA
                sha = commit_data.get('sha', '')
                if not sha:
                    logger.warning("Commit missing SHA, skipping")
                    continue
                
                # Fetch detailed commit information if needed
                if 'commit' not in commit_data or not isinstance(commit_data['commit'], dict):
                    details = self.fetch_commit_details(owner, repo, sha)
                    if not details:
                        logger.warning(f"Could not fetch details for commit {sha}")
                        continue
                else:
                    details = commit_data
                
                # Extract commit message and metadata
                commit_info = details.get('commit', {})
                message = commit_info.get('message', 'No message')
                
                # Try to get commit date, first from author, then from committer
                commit_date = commit_info.get('author', {}).get('date')
                if commit_date is None:
                    commit_date = commit_info.get('committer', {}).get('date')
                
                # Skip this commit if both dates are missing
                if commit_date is None:
                    logger.warning(f"Skipping commit {sha}: both author and committer dates are missing")
                    continue
                
                parsed_date = parse_github_datetime(commit_date)
                
                # Create HackRecord
                record = HackRecord(
                    sha=sha,
                    title=message.split('\n')[0][:100],  # First line, truncated
                    description=message,
                    date=parsed_date,
                    url=details.get('html_url', f'https://github.com/{owner}/{repo}/commit/{sha}')
                )
                
                hack_records.append(record)
                
            except Exception as e:
                logger.error(f"Error parsing commit {commit_data.get('sha', 'unknown')}: {e}")
                continue
        
        return hack_records
    
    def fetch_hack_records_from_repo(self, owner: str, repo: str, 
                                     search_terms: Optional[List[str]] = None,
                                     max_records: int = 50) -> List[HackRecord]:
        """Fetch and parse hack records from a repository.
        
        Args:
            owner: Repository owner
            repo: Repository name
            search_terms: Optional list of terms to search for (e.g., ['vulnerability', 'exploit'])
            max_records: Maximum number of records to fetch
            
        Returns:
            List of HackRecord objects
        """
        all_commits = []
        
        if search_terms:
            # Search for commits matching specific terms
            for term in search_terms:
                query = f'repo:{owner}/{repo} {term}'
                commits = self.search_vulnerability_commits(query, max_records // len(search_terms))
                all_commits.extend(commits)
        else:
            # Fetch recent commits from the repository
            commits = self.fetch_repository_commits(owner, repo, max_commits=max_records)
            all_commits.extend(commits)
        
        # Remove duplicates based on SHA
        seen_shas = set()
        unique_commits = []
        for commit in all_commits:
            sha = commit.get('sha', '')
            if sha and sha not in seen_shas:
                seen_shas.add(sha)
                unique_commits.append(commit)
        
        # Parse commits to HackRecord objects
        return self.parse_commits_to_hack_records(owner, repo, unique_commits[:max_records])


def main():
    """Example usage of GitHubHackFetcher."""
    # Initialize fetcher (optionally with GitHub token from environment)
    import os
    token = os.environ.get('GITHUB_TOKEN')
    fetcher = GitHubHackFetcher(github_token=token)
    
    # Example: Fetch vulnerability-related commits
    records = fetcher.fetch_hack_records_from_repo(
        owner='example-org',
        repo='example-repo',
        search_terms=['vulnerability', 'security', 'CVE'],
        max_records=20
    )
    
    logger.info(f"Fetched {len(records)} hack records")
    for record in records[:5]:
        logger.info(f"  {record}")


if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO)
    main()
