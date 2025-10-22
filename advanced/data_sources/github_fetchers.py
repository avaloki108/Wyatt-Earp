"""GitHub-based data source clients for exploit intelligence."""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Dict, Iterable, List, Optional

import requests

from .records import HackRecord, parse_github_datetime

LOGGER = logging.getLogger(__name__)


class GitHubAPIError(RuntimeError):
    """Raised when the GitHub API returns a non-successful response."""


@dataclass
class GitHubSourceFetcher:
    """Base class for GitHub-backed hack/exploit fetchers."""

    owner: str
    repo: str
    token: Optional[str] = None
    request_interval: float = 1.0
    session: Optional[requests.Session] = None

    def __post_init__(self) -> None:
        self.session = self.session or requests.Session()
        headers = {
            "Accept": "application/vnd.github+json",
            "User-Agent": "Wyatt-Earp-AutoLearner/1.0",
        }
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        self.session.headers.update(headers)
        self._last_request_ts = 0.0

    # -- HTTP helpers -----------------------------------------------------------------

    def _wait_for_rate_limit(self) -> None:
        delta = time.time() - self._last_request_ts
        if delta < self.request_interval:
            time.sleep(self.request_interval - delta)

    def _request(self, url: str, **kwargs) -> requests.Response:
        self._wait_for_rate_limit()
        timeout = kwargs.pop("timeout", 15)
        response = self.session.get(url, timeout=timeout, **kwargs)
        self._last_request_ts = time.time()

        if response.status_code == 403 and response.headers.get("X-RateLimit-Remaining") == "0":
            reset_at = response.headers.get("X-RateLimit-Reset")
            if reset_at:
                wait_for = max(int(reset_at) - int(time.time()), 1)
                LOGGER.warning(
                    "GitHub rate limit hit for %s/%s, sleeping for %s seconds",
                    self.owner,
                    self.repo,
                    wait_for,
                )
                time.sleep(min(wait_for, 60))
                return self._request(url, **kwargs)
        if response.status_code >= 400:
            raise GitHubAPIError(
                f"GitHub API error {response.status_code} for {url}: {response.text[:200]}"
            )
        return response

    def _get_json(self, path: str, params: Optional[Dict[str, str]] = None) -> Any:
        url = f"https://api.github.com/repos/{self.owner}/{self.repo}{path}"
        response = self._request(url, params=params)
        return response.json()

    def _paginate(self, path: str, params: Optional[Dict[str, str]] = None) -> List[Dict[str, str]]:
        results: List[Dict[str, str]] = []
        page = 1
        params = params.copy() if params else {}
        per_page = int(params.get("per_page", 30))

        while True:
            params["page"] = str(page)
            payload = self._get_json(path, params=params)
            if not payload:
                break
            results.extend(payload)
            if len(payload) < per_page:
                break
            page += 1
        return results

    # -- Public API -------------------------------------------------------------------

    def fetch(self, since: datetime) -> List[HackRecord]:
        """Fetch recent hack/exploit records since the given timestamp."""

        raise NotImplementedError

    # -- Utilities --------------------------------------------------------------------

    def _fetch_commit_details(self, sha: str) -> Dict[str, Any]:
        path = f"/commits/{sha}"
        return self._get_json(path)

    def _list_commits(self, since: datetime, path: Optional[str] = None, limit: int = 30) -> List[Dict[str, Any]]:
        params: Dict[str, str] = {
            "since": since.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "per_page": str(min(limit, 100)),
        }
        if path:
            params["path"] = path
        commits = self._paginate("/commits", params=params)
        if limit:
            commits = commits[:limit]
        return commits

    def _collect_solidity_snippets(self, files: Iterable[Dict[str, Any]], max_preview: int = 8000) -> Dict[str, Any]:
        """Collect Solidity file metadata and optionally fetch raw previews."""

        collected = []
        for file_info in files:
            filename = file_info.get("filename", "")
            if not filename.endswith(('.sol', '.vy', '.rs', '.py')):
                continue
            entry: Dict[str, Any] = {
                "filename": filename,
                "status": file_info.get("status"),
            }
            patch = file_info.get("patch")
            if patch:
                entry["patch"] = patch[:max_preview]
            raw_url = file_info.get("raw_url")
            if raw_url and filename.endswith(".sol"):
                try:
                    raw_resp = self._request(raw_url)
                    entry["raw_preview"] = raw_resp.text[:max_preview]
                except Exception as exc:  # noqa: BLE001
                    LOGGER.debug("Failed to fetch raw file %s: %s", raw_url, exc)
            collected.append(entry)
        return {"files": collected}


class SmartBugsWildFetcher(GitHubSourceFetcher):
    """Fetch exploit samples from the smartbugs/smartbugs-wild repository."""

    def __init__(self, token: Optional[str] = None) -> None:
        super().__init__(owner="smartbugs", repo="smartbugs-wild", token=token)

    def fetch(self, since: datetime) -> List[HackRecord]:
        commits = self._list_commits(since, path="contracts", limit=25)
        records: List[HackRecord] = []
        for commit in commits:
            sha = commit.get("sha")
            if not sha:
                continue
            try:
                details = self._fetch_commit_details(sha)
            except GitHubAPIError as exc:
                LOGGER.warning("Failed to fetch smartbugs commit %s: %s", sha, exc)
                continue

            files = details.get("files", [])
            artifact = self._collect_solidity_snippets(files)
            if not artifact.get("files"):
                continue

            message = details.get("commit", {}).get("message", "SmartBugs Wild update")
            title = message.splitlines()[0]
            commit_date = details.get("commit", {}).get("author", {}).get("date")
            if not commit_date:
                LOGGER.warning("Missing commit date for smartbugs commit %s", sha)
            record = HackRecord(
                uid=f"smartbugs-wild-{sha}",
                title=f"SmartBugs Wild dataset update: {title}",
                description=message,
                discovered_at=parse_github_datetime(commit_date),
                severity="medium",
                source="smartbugs/smartbugs-wild",
                references=[details.get("html_url", f"https://github.com/smartbugs/smartbugs-wild/commit/{sha}")],
                artifacts=artifact,
            )
            records.append(record)
        return records


class DeFiHackLabsFetcher(GitHubSourceFetcher):
    """Fetch new PoC exploits from SunWeb3Sec/DeFiHackLabs."""

    def __init__(self, token: Optional[str] = None) -> None:
        super().__init__(owner="SunWeb3Sec", repo="DeFiHackLabs", token=token)

    def fetch(self, since: datetime) -> List[HackRecord]:
        commits = self._list_commits(since, path="src", limit=25)
        records: List[HackRecord] = []
        for commit in commits:
            sha = commit.get("sha")
            if not sha:
                continue
            try:
                details = self._fetch_commit_details(sha)
            except GitHubAPIError as exc:
                LOGGER.warning("Failed to fetch DeFiHackLabs commit %s: %s", sha, exc)
                continue

            files = details.get("files", [])
            artifact = self._collect_solidity_snippets(files)
            if not artifact.get("files"):
                continue

            message = details.get("commit", {}).get("message", "DeFiHackLabs update")
            title = message.splitlines()[0]
            commit_date = details.get("commit", {}).get("author", {}).get("date", datetime.utcnow().isoformat())
            record = HackRecord(
                uid=f"defihacklabs-{sha}",
                title=f"DeFiHackLabs PoC update: {title}",
                description=message,
                discovered_at=parse_github_datetime(commit_date),
                severity="critical",
                source="SunWeb3Sec/DeFiHackLabs",
                references=[details.get("html_url", f"https://github.com/SunWeb3Sec/DeFiHackLabs/commit/{sha}")],
                artifacts=artifact,
            )
            records.append(record)
        return records


class CyfrinAderynFetcher(GitHubSourceFetcher):
    """Fetch rule updates from the Cyfrin/aderyn repository."""

    def __init__(self, token: Optional[str] = None) -> None:
        super().__init__(owner="Cyfrin", repo="aderyn", token=token)

    def fetch(self, since: datetime) -> List[HackRecord]:
        commits = self._list_commits(since, path="", limit=20)
        records: List[HackRecord] = []
        for commit in commits:
            sha = commit.get("sha")
            if not sha:
                continue
            try:
                details = self._fetch_commit_details(sha)
            except GitHubAPIError as exc:
                LOGGER.warning("Failed to fetch Cyfrin/aderyn commit %s: %s", sha, exc)
                continue

            files = details.get("files", [])
            artifact = self._collect_solidity_snippets(files)
            if not artifact.get("files"):
                continue

            message = details.get("commit", {}).get("message", "Aderyn update")
            title = message.splitlines()[0]
            commit_date = details.get("commit", {}).get("author", {}).get("date", datetime.utcnow().isoformat())
            record = HackRecord(
                uid=f"cyfrin-aderyn-{sha}",
                title=f"Cyfrin/aderyn rule update: {title}",
                description=message,
                discovered_at=parse_github_datetime(commit_date),
                severity="medium",
                source="Cyfrin/aderyn",
                references=[details.get("html_url", f"https://github.com/Cyfrin/aderyn/commit/{sha}")],
                artifacts=artifact,
            )
            records.append(record)
        return records


class SoloditContentFetcher(GitHubSourceFetcher):
    """Fetches new Solodit reports from the public solodit_content repository."""

    def __init__(self, token: Optional[str] = None) -> None:
        super().__init__(owner="Solodit", repo="solodit_content", token=token)

    def fetch(self, since: datetime) -> List[HackRecord]:
        commits = self._list_commits(since, path="reports", limit=25)
        records: List[HackRecord] = []
        for commit in commits:
            sha = commit.get("sha")
            if not sha:
                continue
            try:
                details = self._fetch_commit_details(sha)
            except GitHubAPIError as exc:
                LOGGER.warning("Failed to fetch Solodit commit %s: %s", sha, exc)
                continue

            files = details.get("files", [])
            report_files = [f for f in files if f.get("filename", "").endswith(".md")]
            if not report_files:
                continue

            report_artifacts = []
            for file_info in report_files:
                raw_url = file_info.get("raw_url")
                content_preview = ""
                if raw_url:
                    try:
                        raw_resp = self._request(raw_url)
                        content_preview = raw_resp.text[:4000]
                    except Exception as exc:  # noqa: BLE001
                        LOGGER.debug("Failed to fetch Solodit report %s: %s", raw_url, exc)
                report_artifacts.append(
                    {
                        "filename": file_info.get("filename"),
                        "raw_preview": content_preview,
                        "status": file_info.get("status"),
                        "patch": file_info.get("patch"),
                    }
                )

            if not report_artifacts:
                continue

            message = details.get("commit", {}).get("message", "Solodit report update")
            title = message.splitlines()[0]
            commit_date = details.get("commit", {}).get("author", {}).get("date", datetime.utcnow().isoformat())
            record = HackRecord(
                uid=f"solodit-{sha}",
                title=f"Solodit report update: {title}",
                description=message,
                discovered_at=parse_github_datetime(commit_date),
                severity="informational",
                source="Solodit/solodit_content",
                references=[details.get("html_url", f"https://github.com/Solodit/solodit_content/commit/{sha}")],
                artifacts={"files": report_artifacts},
            )
            records.append(record)
        return records
