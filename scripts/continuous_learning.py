"""Scheduled ingestion runner for the auto-learning system.

This script is designed to be invoked from cron (or any scheduler) to pull
fresh exploit intelligence, run the LLM extraction pipeline, and persist any
new patterns that were learned.
"""

from __future__ import annotations

import argparse
import logging
from pathlib import Path
from typing import List

from advanced.auto_learning import AutoLearner

LOGGER = logging.getLogger(__name__)


def _configure_logging(log_path: Path) -> None:
    log_path.parent.mkdir(parents=True, exist_ok=True)
    handlers: List[logging.Handler] = [
        logging.FileHandler(log_path, encoding="utf-8"),
        logging.StreamHandler(),
    ]
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        handlers=handlers,
    )


def main() -> int:
    parser = argparse.ArgumentParser(description="Continuous learning ingestion runner")
    parser.add_argument(
        "--days",
        type=int,
        default=1,
        help="Look-back window (in days) for fetching new incidents",
    )
    parser.add_argument(
        "--github-only",
        action="store_true",
        help="Only run the GitHub exploit ingestion stage",
    )
    args = parser.parse_args()

    log_path = Path("logs/continuous_learning.log")
    _configure_logging(log_path)

    LOGGER.info("Starting continuous learning ingestion (days=%s, github_only=%s)", args.days, args.github_only)
    learner = AutoLearner()
    if args.github_only:
        new_patterns = learner.learn_from_github_exploits(days=args.days)
    else:
        new_patterns = learner.learn_from_recent_hacks(days=args.days)

    pattern_names = ", ".join(pattern.get("name", "unknown") for pattern in new_patterns)
    LOGGER.info("Ingestion complete. %s new pattern(s) learned.", len(new_patterns))
    if new_patterns:
        LOGGER.info("New patterns: %s", pattern_names)
    else:
        LOGGER.info("No new patterns were identified in this run.")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
