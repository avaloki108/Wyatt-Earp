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
    RecordCollection,
)


class TestParseGitHubDatetime:
    """Test parse_github_datetime function"""

    def test_valid_iso_datetime_with_z(self):
        """Test parsing valid ISO datetime with Z timezone"""
        dt_string = "2023-10-15T14:30:00Z"
        result = parse_github_datetime(dt_string)
        assert isinstance(result, datetime)
        assert result.year == 2023
        assert result.month == 10
        assert result.day == 15
        assert result.hour == 14
        assert result.minute == 30
        assert result.second == 0

    def test_valid_iso_datetime_with_offset(self):
        """Test parsing valid ISO datetime with timezone offset"""
        dt_string = "2023-10-15T14:30:00+00:00"
        result = parse_github_datetime(dt_string)
        assert isinstance(result, datetime)
        assert result.year == 2023
        assert result.month == 10
        assert result.day == 15

    def test_valid_iso_datetime_with_microseconds(self):
        """Test parsing valid ISO datetime with microseconds"""
        dt_string = "2023-10-15T14:30:00.123456Z"
        result = parse_github_datetime(dt_string)
        assert isinstance(result, datetime)
        assert result.microsecond == 123456

    def test_none_input_raises_valueerror(self):
        """Test that None input raises ValueError with correct message"""
        with pytest.raises(ValueError) as exc_info:
            parse_github_datetime(None)
        assert "Missing GitHub datetime string" in str(exc_info.value)

    def test_empty_string_raises_valueerror(self):
        """Test that empty string raises ValueError with correct message"""
        with pytest.raises(ValueError) as exc_info:
            parse_github_datetime("")
        assert "Missing GitHub datetime string" in str(exc_info.value)

    def test_invalid_format_raises_valueerror_with_input(self):
        """Test that invalid format raises ValueError including the input"""
        invalid_string = "not-a-datetime"
        with pytest.raises(ValueError) as exc_info:
            parse_github_datetime(invalid_string)
        error_msg = str(exc_info.value)
        assert "Failed to parse GitHub datetime string" in error_msg
        assert invalid_string in error_msg

    def test_invalid_format_includes_underlying_error(self):
        """Test that error message includes underlying error information"""
        invalid_string = "2023-13-45"  # Invalid month and day
        with pytest.raises(ValueError) as exc_info:
            parse_github_datetime(invalid_string)
        error_msg = str(exc_info.value)
        assert "Failed to parse GitHub datetime string" in error_msg
        assert invalid_string in error_msg
        # Should include some indication of the underlying error

    def test_malformed_iso_string(self):
        """Test with malformed ISO string"""
        malformed_string = "not-a-date-at-all"  # Completely invalid format
        with pytest.raises(ValueError) as exc_info:
            parse_github_datetime(malformed_string)
        error_msg = str(exc_info.value)
        assert "Failed to parse GitHub datetime string" in error_msg
        assert malformed_string in error_msg

    def test_partial_datetime_string(self):
        """Test with partial datetime string"""
        partial_string = "2023-10"
        with pytest.raises(ValueError) as exc_info:
            parse_github_datetime(partial_string)
        error_msg = str(exc_info.value)
        assert "Failed to parse GitHub datetime string" in error_msg
        assert partial_string in error_msg

    def test_whitespace_only_string_raises_valueerror(self):
        """Test that whitespace-only string is not treated as empty"""
        # Whitespace is not empty string, so it should fail parsing
        with pytest.raises(ValueError) as exc_info:
            parse_github_datetime("   ")
        error_msg = str(exc_info.value)
        assert "Failed to parse GitHub datetime string" in error_msg


class TestGitHubRecord:
    """Test GitHubRecord class"""

    def test_create_record_with_valid_datetimes(self):
        """Test creating a record with valid datetime strings"""
        data = {
            "created_at": "2023-10-15T14:30:00Z",
            "updated_at": "2023-10-16T10:00:00Z",
        }
        record = GitHubRecord(data)
        assert isinstance(record.created_at, datetime)
        assert isinstance(record.updated_at, datetime)

    def test_create_record_with_missing_datetimes_raises(self):
        """Test that creating record with missing datetimes raises ValueError"""
        data = {}
        with pytest.raises(ValueError) as exc_info:
            GitHubRecord(data)
        assert "Missing GitHub datetime string" in str(exc_info.value)

    def test_record_repr(self):
        """Test record string representation"""
        data = {
            "created_at": "2023-10-15T14:30:00Z",
            "updated_at": "2023-10-16T10:00:00Z",
        }
        record = GitHubRecord(data)
        repr_str = repr(record)
        assert "GitHubRecord" in repr_str
        assert "created_at" in repr_str
        assert "updated_at" in repr_str


class TestRecordCollection:
    """Test RecordCollection class"""

    def test_empty_collection(self):
        """Test creating empty collection"""
        collection = RecordCollection()
        assert collection.count() == 0

    def test_add_record(self):
        """Test adding records to collection"""
        collection = RecordCollection()
        data = {
            "created_at": "2023-10-15T14:30:00Z",
            "updated_at": "2023-10-16T10:00:00Z",
        }
        record = GitHubRecord(data)
        collection.add(record)
        assert collection.count() == 1

    def test_add_multiple_records(self):
        """Test adding multiple records"""
        collection = RecordCollection()
        for i in range(5):
            data = {
                "created_at": f"2023-10-{15+i}T14:30:00Z",
                "updated_at": f"2023-10-{16+i}T10:00:00Z",
            }
            record = GitHubRecord(data)
            collection.add(record)
        assert collection.count() == 5
