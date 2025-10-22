"""
Unit tests for GitHub data fetchers
Tests handling of missing commit dates and proper fallback logic
"""

import pytest
import sys
from pathlib import Path
from datetime import datetime
from unittest.mock import Mock, patch

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from advanced.data_sources.github_fetchers import (
    GitHubHackFetcher,
    HackRecord,
    parse_github_datetime,
)


class TestParseGitHubDateTime:
    """Test the parse_github_datetime function"""
    
    def test_parse_valid_datetime(self):
        """Test parsing a valid GitHub datetime string"""
        date_str = "2023-10-22T12:34:56Z"
        result = parse_github_datetime(date_str)
        assert isinstance(result, datetime)
        assert result.year == 2023
        assert result.month == 10
        assert result.day == 22
    
    def test_parse_none_raises_error(self):
        """Test that passing None raises ValueError"""
        with pytest.raises(ValueError, match="Date string cannot be None"):
            parse_github_datetime(None)
    
    def test_parse_invalid_format_raises_error(self):
        """Test that invalid format raises ValueError"""
        with pytest.raises(ValueError, match="Invalid date format"):
            parse_github_datetime("invalid-date")


class TestGitHubHackFetcher:
    """Test the GitHubHackFetcher class"""
    
    @pytest.fixture
    def fetcher(self):
        """Create a GitHubHackFetcher instance for testing"""
        return GitHubHackFetcher(github_token="test_token")
    
    def test_initialization(self, fetcher):
        """Test fetcher initialization"""
        assert fetcher.github_token == "test_token"
        assert 'Authorization' in fetcher.headers
    
    def test_initialization_without_token(self):
        """Test fetcher initialization without token"""
        fetcher = GitHubHackFetcher()
        assert fetcher.github_token is None
        assert 'Authorization' not in fetcher.headers


class TestParseCommitsToHackRecords:
    """Test the parse_commits_to_hack_records method"""
    
    @pytest.fixture
    def fetcher(self):
        """Create a GitHubHackFetcher instance for testing"""
        return GitHubHackFetcher()
    
    def test_parse_commit_with_author_date(self, fetcher):
        """Test parsing a commit with author date"""
        commits = [{
            'sha': 'abc123',
            'commit': {
                'message': 'Fix vulnerability',
                'author': {
                    'date': '2023-10-22T12:34:56Z'
                },
                'committer': {
                    'date': '2023-10-22T13:00:00Z'
                }
            },
            'html_url': 'https://github.com/test/repo/commit/abc123'
        }]
        
        records = fetcher.parse_commits_to_hack_records('test', 'repo', commits)
        assert len(records) == 1
        assert records[0].sha == 'abc123'
        assert records[0].title == 'Fix vulnerability'
        assert isinstance(records[0].date, datetime)
    
    def test_parse_commit_with_missing_author_date(self, fetcher):
        """Test parsing a commit where author date is None but committer date exists"""
        commits = [{
            'sha': 'def456',
            'commit': {
                'message': 'Security patch',
                'author': {
                    'date': None  # Missing author date
                },
                'committer': {
                    'date': '2023-10-22T14:00:00Z'
                }
            },
            'html_url': 'https://github.com/test/repo/commit/def456'
        }]
        
        records = fetcher.parse_commits_to_hack_records('test', 'repo', commits)
        assert len(records) == 1
        assert records[0].sha == 'def456'
        assert isinstance(records[0].date, datetime)
    
    def test_parse_commit_with_both_dates_missing(self, fetcher, caplog):
        """Test parsing a commit where both author and committer dates are None"""
        commits = [{
            'sha': 'ghi789',
            'commit': {
                'message': 'Update code',
                'author': {
                    'date': None
                },
                'committer': {
                    'date': None
                }
            },
            'html_url': 'https://github.com/test/repo/commit/ghi789'
        }]
        
        records = fetcher.parse_commits_to_hack_records('test', 'repo', commits)
        # Should skip this commit and return empty list
        assert len(records) == 0
        # Should log a warning with the SHA
        assert 'ghi789' in caplog.text
        assert 'missing' in caplog.text.lower() or 'skip' in caplog.text.lower()
    
    def test_parse_commit_with_missing_author_object(self, fetcher):
        """Test parsing a commit where author object is missing but committer exists"""
        commits = [{
            'sha': 'jkl012',
            'commit': {
                'message': 'Fix bug',
                'committer': {
                    'date': '2023-10-23T10:00:00Z'
                }
            },
            'html_url': 'https://github.com/test/repo/commit/jkl012'
        }]
        
        records = fetcher.parse_commits_to_hack_records('test', 'repo', commits)
        assert len(records) == 1
        assert records[0].sha == 'jkl012'
    
    def test_parse_multiple_commits_with_mixed_dates(self, fetcher):
        """Test parsing multiple commits with various date scenarios"""
        commits = [
            {
                'sha': 'commit1',
                'commit': {
                    'message': 'Good commit',
                    'author': {'date': '2023-10-22T12:00:00Z'},
                    'committer': {'date': '2023-10-22T12:30:00Z'}
                },
                'html_url': 'https://github.com/test/repo/commit/commit1'
            },
            {
                'sha': 'commit2',
                'commit': {
                    'message': 'Bad commit',
                    'author': {'date': None},
                    'committer': {'date': None}
                },
                'html_url': 'https://github.com/test/repo/commit/commit2'
            },
            {
                'sha': 'commit3',
                'commit': {
                    'message': 'Fallback commit',
                    'author': {'date': None},
                    'committer': {'date': '2023-10-22T15:00:00Z'}
                },
                'html_url': 'https://github.com/test/repo/commit/commit3'
            }
        ]
        
        records = fetcher.parse_commits_to_hack_records('test', 'repo', commits)
        # Should parse commit1 and commit3, skip commit2
        assert len(records) == 2
        assert records[0].sha == 'commit1'
        assert records[1].sha == 'commit3'
    
    def test_parse_commit_without_sha(self, fetcher):
        """Test that commits without SHA are skipped"""
        commits = [{
            'commit': {
                'message': 'No SHA commit',
                'author': {'date': '2023-10-22T12:00:00Z'}
            }
        }]
        
        records = fetcher.parse_commits_to_hack_records('test', 'repo', commits)
        assert len(records) == 0


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
