"""Data source clients for the auto-learning pipeline."""

from .records import HackRecord
from .github_fetchers import (
    GitHubSourceFetcher,
    SmartBugsWildFetcher,
    DeFiHackLabsFetcher,
    CyfrinAderynFetcher,
    SoloditContentFetcher,
)

__all__ = [
    "HackRecord",
    "GitHubSourceFetcher",
    "SmartBugsWildFetcher",
    "DeFiHackLabsFetcher",
    "CyfrinAderynFetcher",
    "SoloditContentFetcher",
]
