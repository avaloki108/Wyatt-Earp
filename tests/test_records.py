"""
Tests for data_sources.records module
"""

import sys
from pathlib import Path
from datetime import datetime
import pytest

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from advanced.data_sources.records import (
    parse_github_datetime,
    GitHubRecord,
    IssueRecord,
    PullRequestRecord,
    CommitRecord,
    RepositoryRecord,
)


class TestParseGitHubDatetime:
    """Test parse_github_datetime function"""
    
    def test_parse_valid_datetime_with_z_suffix(self):
        """Test parsing valid datetime string with Z suffix"""
        dt_str = "2023-10-15T14:30:00Z"
        result = parse_github_datetime(dt_str)
        
        assert isinstance(result, datetime)
        assert result.year == 2023
        assert result.month == 10
        assert result.day == 15
        assert result.hour == 14
        assert result.minute == 30
        assert result.second == 0
    
    def test_parse_valid_datetime_without_z_suffix(self):
        """Test parsing valid datetime string without Z suffix"""
        dt_str = "2023-10-15T14:30:00"
        result = parse_github_datetime(dt_str)
        
        assert isinstance(result, datetime)
        assert result.year == 2023
        assert result.month == 10
        assert result.day == 15
    
    def test_parse_valid_datetime_with_microseconds(self):
        """Test parsing datetime with microseconds"""
        dt_str = "2023-10-15T14:30:00.123456Z"
        result = parse_github_datetime(dt_str)
        
        assert isinstance(result, datetime)
        assert result.microsecond == 123456
    
    def test_raises_error_on_none_input(self):
        """Test that None input raises ValueError with clear message"""
        with pytest.raises(ValueError) as exc_info:
            parse_github_datetime(None)
        
        assert "Missing GitHub datetime string" in str(exc_info.value)
    
    def test_raises_error_on_empty_string_input(self):
        """Test that empty string input raises ValueError with clear message"""
        with pytest.raises(ValueError) as exc_info:
            parse_github_datetime("")
        
        assert "Missing GitHub datetime string" in str(exc_info.value)
    
    def test_raises_error_on_invalid_format(self):
        """Test that invalid format raises ValueError with original input"""
        invalid_dt_str = "not-a-datetime"
        
        with pytest.raises(ValueError) as exc_info:
            parse_github_datetime(invalid_dt_str)
        
        # Check that the error message includes the original input
        error_msg = str(exc_info.value)
        assert "Failed to parse GitHub datetime string" in error_msg
        assert invalid_dt_str in error_msg
    
    def test_raises_error_on_malformed_iso_format(self):
        """Test that malformed ISO format raises ValueError with details"""
        malformed_dt_str = "2023-13-45T25:99:99Z"  # Invalid month, day, hour, etc.
        
        with pytest.raises(ValueError) as exc_info:
            parse_github_datetime(malformed_dt_str)
        
        error_msg = str(exc_info.value)
        assert "Failed to parse GitHub datetime string" in error_msg
        assert malformed_dt_str in error_msg
    
    def test_raises_error_includes_underlying_exception(self):
        """Test that error includes underlying exception message"""
        invalid_dt_str = "invalid-format"
        
        with pytest.raises(ValueError) as exc_info:
            parse_github_datetime(invalid_dt_str)
        
        # The error should include details from the underlying exception
        error_msg = str(exc_info.value)
        assert "Failed to parse GitHub datetime string" in error_msg
        assert invalid_dt_str in error_msg
        # Should have some info about what went wrong
        assert len(error_msg) > len(invalid_dt_str) + 30


class TestGitHubRecord:
    """Test GitHubRecord class"""
    
    def test_github_record_with_valid_dates(self):
        """Test creating GitHubRecord with valid datetime strings"""
        data = {
            'created_at': '2023-10-15T14:30:00Z',
            'updated_at': '2023-10-16T10:00:00Z'
        }
        
        record = GitHubRecord(data)
        
        assert isinstance(record.created_at, datetime)
        assert isinstance(record.updated_at, datetime)
        assert record.created_at.year == 2023
        assert record.updated_at.day == 16
    
    def test_github_record_with_none_dates_raises_error(self):
        """Test that GitHubRecord raises error when dates are None"""
        data = {
            'created_at': None,
            'updated_at': '2023-10-16T10:00:00Z'
        }
        
        with pytest.raises(ValueError) as exc_info:
            GitHubRecord(data)
        
        assert "Missing GitHub datetime string" in str(exc_info.value)


class TestIssueRecord:
    """Test IssueRecord class"""
    
    def test_issue_record_with_valid_data(self):
        """Test creating IssueRecord with valid data"""
        data = {
            'title': 'Test Issue',
            'state': 'open',
            'created_at': '2023-10-15T14:30:00Z',
            'updated_at': '2023-10-16T10:00:00Z',
            'closed_at': '2023-10-17T12:00:00Z'
        }
        
        record = IssueRecord(data)
        
        assert record.title == 'Test Issue'
        assert record.state == 'open'
        assert isinstance(record.closed_at, datetime)
        assert record.closed_at.day == 17


class TestPullRequestRecord:
    """Test PullRequestRecord class"""
    
    def test_pr_record_with_merged_data(self):
        """Test creating PullRequestRecord with merged PR data"""
        data = {
            'title': 'Test PR',
            'merged': True,
            'created_at': '2023-10-15T14:30:00Z',
            'updated_at': '2023-10-16T10:00:00Z',
            'merged_at': '2023-10-17T15:30:00Z'
        }
        
        record = PullRequestRecord(data)
        
        assert record.title == 'Test PR'
        assert record.merged is True
        assert isinstance(record.merged_at, datetime)
        assert record.merged_at.hour == 15


class TestCommitRecord:
    """Test CommitRecord class"""
    
    def test_commit_record_with_valid_data(self):
        """Test creating CommitRecord with valid data"""
        data = {
            'sha': 'abc123def456',
            'created_at': '2023-10-15T14:30:00Z',
            'updated_at': '2023-10-16T10:00:00Z',
            'commit': {
                'message': 'Fix bug',
                'author': {
                    'date': '2023-10-15T14:30:00Z'
                }
            }
        }
        
        record = CommitRecord(data)
        
        assert record.sha == 'abc123def456'
        assert record.message == 'Fix bug'
        assert isinstance(record.author_date, datetime)


class TestRepositoryRecord:
    """Test RepositoryRecord class"""
    
    def test_repository_record_with_valid_data(self):
        """Test creating RepositoryRecord with valid data"""
        data = {
            'name': 'test-repo',
            'created_at': '2023-10-15T14:30:00Z',
            'updated_at': '2023-10-16T10:00:00Z',
            'pushed_at': '2023-10-17T08:00:00Z'
        }
        
        record = RepositoryRecord(data)
        
        assert record.name == 'test-repo'
        assert isinstance(record.created_at, datetime)
        assert isinstance(record.updated_at, datetime)
        assert isinstance(record.pushed_at, datetime)
        assert record.pushed_at.hour == 8
