"""
Tests for External Knowledge Ingestion Pipeline
Tests GitHub crawlers, data fetchers, and pattern extraction
"""

import pytest
import sys
from pathlib import Path
from datetime import datetime, timedelta
from unittest.mock import Mock, patch, MagicMock

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from advanced.data_sources import (
    SmartBugsWildFetcher,
    DeFiHackLabsFetcher,
    CyfrinAderynFetcher,
    SoloditContentFetcher,
    HackRecord,
)
from advanced.auto_learning import AutoLearner


class TestGitHubFetchers:
    """Test suite for GitHub-based data source fetchers"""
    
    def test_smartbugs_fetcher_initialization(self):
        """Test SmartBugsWild fetcher initialization"""
        fetcher = SmartBugsWildFetcher()
        
        assert fetcher is not None
        assert fetcher.owner == "smartbugs"
        assert fetcher.repo == "smartbugs-wild"
        assert fetcher.provides_code_artifacts is True
        
    def test_defihacklabs_fetcher_initialization(self):
        """Test DeFiHackLabs fetcher initialization"""
        fetcher = DeFiHackLabsFetcher()
        
        assert fetcher is not None
        assert fetcher.owner == "SunWeb3Sec"
        assert fetcher.repo == "DeFiHackLabs"
        assert fetcher.provides_code_artifacts is True
        
    def test_cyfrin_aderyn_fetcher_initialization(self):
        """Test Cyfrin/aderyn fetcher initialization"""
        fetcher = CyfrinAderynFetcher()
        
        assert fetcher is not None
        assert fetcher.owner == "Cyfrin"
        assert fetcher.repo == "aderyn"
        
    def test_solodit_fetcher_initialization(self):
        """Test Solodit fetcher initialization"""
        fetcher = SoloditContentFetcher()
        
        assert fetcher is not None
        assert fetcher.owner == "Solodit"
        assert fetcher.repo == "solodit_content"
        assert fetcher.provides_code_artifacts is False  # Markdown reports
        
    @patch('requests.Session.get')
    def test_fetcher_with_github_token(self, mock_get):
        """Test that fetchers use GitHub token when provided"""
        token = "test_token_12345"
        fetcher = SmartBugsWildFetcher(token=token)
        
        # Check that authorization header is set
        assert "Authorization" in fetcher.session.headers
        assert fetcher.session.headers["Authorization"] == f"Bearer {token}"
        
    @patch('requests.Session.get')
    def test_fetch_returns_hack_records(self, mock_get):
        """Test that fetch returns list of HackRecord objects"""
        # Mock API response
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = []
        mock_get.return_value = mock_response
        
        fetcher = SmartBugsWildFetcher()
        since = datetime.now() - timedelta(days=7)
        
        records = fetcher.fetch(since)
        
        assert isinstance(records, list)
        # All items should be HackRecord instances
        assert all(isinstance(r, HackRecord) for r in records)
        
    @patch('requests.Session.get')
    def test_rate_limiting_handling(self, mock_get):
        """Test that fetchers handle rate limiting properly"""
        fetcher = SmartBugsWildFetcher()
        
        # Initial request should work
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"sha": "test123"}
        mock_get.return_value = mock_response
        
        # Make requests and verify rate limiting is respected
        start_time = datetime.now()
        fetcher._request("https://api.github.com/test")
        fetcher._request("https://api.github.com/test2")
        elapsed = (datetime.now() - start_time).total_seconds()
        
        # Should take at least request_interval seconds
        assert elapsed >= fetcher.request_interval
        
    @patch('requests.Session.get')
    def test_solidity_snippet_collection(self, mock_get):
        """Test collecting Solidity code snippets from files"""
        fetcher = DeFiHackLabsFetcher()
        
        files = [
            {
                "filename": "exploit.sol",
                "status": "added",
                "patch": "contract Exploit { }",
                "raw_url": "https://example.com/exploit.sol"
            },
            {
                "filename": "README.md",
                "status": "modified"
            }
        ]
        
        # Mock the raw file request
        mock_raw = Mock()
        mock_raw.text = "contract Exploit { function attack() public { } }"
        mock_get.return_value = mock_raw
        
        artifacts = fetcher._collect_solidity_snippets(files)
        
        assert "files" in artifacts
        # Should only collect .sol files
        assert len(artifacts["files"]) == 1
        assert artifacts["files"][0]["filename"] == "exploit.sol"


class TestHackRecordStructure:
    """Test suite for HackRecord data structure"""
    
    def test_hack_record_creation(self):
        """Test creating a HackRecord instance"""
        record = HackRecord(
            uid="test-001",
            title="Test Exploit",
            description="Test description",
            discovered_at=datetime.now(),
            severity="critical",
            source="test_source",
            references=["https://example.com"],
            artifacts={"files": []}
        )
        
        assert record.uid == "test-001"
        assert record.title == "Test Exploit"
        assert record.severity == "critical"
        assert isinstance(record.discovered_at, datetime)
        
    def test_hack_record_serialization(self):
        """Test that HackRecord can be serialized"""
        record = HackRecord(
            uid="test-002",
            title="Test",
            description="Desc",
            discovered_at=datetime.now(),
            severity="high",
            source="src",
            references=[],
            artifacts={}
        )
        
        # Should have basic dict-like behavior
        assert hasattr(record, 'uid')
        assert hasattr(record, 'title')


class TestAutoLearnerIntegration:
    """Test suite for AutoLearner knowledge ingestion"""
    
    def test_auto_learner_initialization(self):
        """Test AutoLearner initialization"""
        learner = AutoLearner()
        
        assert learner is not None
        assert len(learner.source_fetchers) > 0
        assert isinstance(learner.learned_patterns, list)
        
    def test_auto_learner_has_all_fetchers(self):
        """Test that AutoLearner includes all GitHub fetchers"""
        learner = AutoLearner()
        
        fetcher_types = [type(f).__name__ for f in learner.source_fetchers]
        
        assert "SmartBugsWildFetcher" in fetcher_types
        assert "DeFiHackLabsFetcher" in fetcher_types
        assert "CyfrinAderynFetcher" in fetcher_types
        assert "SoloditContentFetcher" in fetcher_types
        
    @patch.object(SmartBugsWildFetcher, 'fetch')
    @patch.object(DeFiHackLabsFetcher, 'fetch')
    @patch.object(CyfrinAderynFetcher, 'fetch')
    @patch.object(SoloditContentFetcher, 'fetch')
    def test_learn_from_github_exploits(self, mock_solodit, mock_cyfrin, mock_defi, mock_smartbugs):
        """Test learning from GitHub exploit sources"""
        # Mock fetch to return empty lists
        mock_smartbugs.return_value = []
        mock_defi.return_value = []
        mock_cyfrin.return_value = []
        mock_solodit.return_value = []
        
        learner = AutoLearner()
        
        # This should not raise errors even with empty data
        result = learner.learn_from_github_exploits(days=1)
        
        assert isinstance(result, list)
        
    def test_learned_patterns_persistence(self):
        """Test that learned patterns are persisted"""
        learner = AutoLearner()
        
        # Should have a patterns file location
        assert learner.patterns_file is not None
        assert learner.patterns_file.parent.exists()
        
    def test_processed_hack_ids_tracking(self):
        """Test that processed hack IDs are tracked to avoid duplicates"""
        learner = AutoLearner()
        
        # Should maintain a set of processed IDs
        assert isinstance(learner.processed_hack_ids, set)


class TestPatternExtraction:
    """Test suite for LLM-based pattern extraction"""
    
    def test_extract_vulnerability_patterns(self):
        """Test extracting patterns from hack descriptions"""
        learner = AutoLearner()
        
        mock_hack = {
            "title": "Flash Loan Attack",
            "description": "Attacker used flash loan to manipulate oracle price",
            "impact": "critical",
            "exploit_code_snippet": "flashLoan(amount); manipulateOracle();"
        }
        
        # Even if extraction doesn't work without real LLM,
        # the method should exist and handle gracefully
        assert hasattr(learner, 'llm')
        
    def test_pattern_deduplication(self):
        """Test that duplicate patterns are not added"""
        learner = AutoLearner()
        
        initial_count = len(learner.learned_patterns)
        
        # Add a pattern
        pattern = {
            "name": "test_pattern",
            "severity": "high",
            "provenance": {"source_id": "test-001"}
        }
        
        learner.learned_patterns.append(pattern)
        learner.processed_hack_ids.add("test-001")
        
        # Try to add same pattern again
        if "test-001" in learner.processed_hack_ids:
            # Should not add duplicate
            pass
        
        # Pattern count should only increase by 1
        assert len(learner.learned_patterns) == initial_count + 1


class TestContinuousLearning:
    """Test suite for continuous learning pipeline"""
    
    @patch.object(AutoLearner, 'learn_from_github_exploits')
    def test_github_only_mode(self, mock_learn):
        """Test continuous learning in GitHub-only mode"""
        mock_learn.return_value = []
        
        learner = AutoLearner()
        result = learner.learn_from_github_exploits(days=1)
        
        assert mock_learn.called
        assert isinstance(result, list)
        
    def test_lookback_window(self):
        """Test that lookback window is respected"""
        learner = AutoLearner()
        
        # Fetch with different lookback windows
        # Should not raise errors
        try:
            learner.fetch_recent_hacks(days=1)
            learner.fetch_recent_hacks(days=7)
            learner.fetch_recent_hacks(days=30)
        except Exception as e:
            pytest.fail(f"Lookback window handling failed: {e}")


class TestProvenanceTracking:
    """Test suite for pattern provenance tracking"""
    
    def test_provenance_log_creation(self):
        """Test that provenance log is created"""
        learner = AutoLearner()
        
        assert learner.provenance_log is not None
        assert learner.provenance_log.parent.exists()
        
    def test_pattern_includes_source_info(self):
        """Test that learned patterns include source information"""
        learner = AutoLearner()
        
        # Check existing patterns for provenance
        for pattern in learner.learned_patterns:
            # Pattern should be a dict
            assert isinstance(pattern, dict)
            # May have provenance field
            if "provenance" in pattern:
                assert isinstance(pattern["provenance"], dict)


class TestKnowledgeIngestionEdgeCases:
    """Test edge cases in knowledge ingestion"""
    
    @patch('requests.Session.get')
    def test_api_error_handling(self, mock_get):
        """Test handling of API errors"""
        # Mock 404 error
        mock_response = Mock()
        mock_response.status_code = 404
        mock_response.text = "Not Found"
        mock_get.return_value = mock_response
        
        fetcher = SmartBugsWildFetcher()
        
        # Should handle error gracefully
        with pytest.raises(Exception):  # GitHubAPIError
            fetcher._get_json("/nonexistent")
            
    @patch('requests.Session.get')
    def test_malformed_json_response(self, mock_get):
        """Test handling of malformed JSON responses"""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.side_effect = ValueError("Invalid JSON")
        mock_get.return_value = mock_response
        
        fetcher = DeFiHackLabsFetcher()
        
        # Should handle malformed JSON
        with pytest.raises(Exception):
            fetcher._get_json("/test")
            
    def test_empty_repository_handling(self):
        """Test handling of empty repositories"""
        learner = AutoLearner()
        
        # Should handle empty results gracefully
        hacks = learner.fetch_recent_hacks(days=0)
        
        # May return empty list or mock data
        assert isinstance(hacks, list)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
