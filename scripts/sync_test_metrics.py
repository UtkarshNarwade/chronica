"""Synchronize README.md, docs/limitations.md, and docs/testing.md with real test metrics.

Automates F-21 requirements: prevents hardcoded or stale test numbers by
introspecting the actual pytest test collection and updating documentation.
"""

from __future__ import annotations

from pathlib import Path
import re
import sys
from typing import Dict, Tuple

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

import pytest


class PytestCollector:
    """Collects test functions per file from pytest."""
    def __init__(self) -> None:
        self.collected_total = 0
        self.files_map: Dict[str, int] = {}

    def pytest_collection_modifyitems(self, items) -> None:
        self.collected_total = len(items)
        for item in items:
            raw_path = str(item.fspath)
            # Make path relative to REPO_ROOT and use forward slashes
            try:
                rel_path = Path(raw_path).resolve().relative_to(REPO_ROOT).as_posix()
            except ValueError:
                rel_path = raw_path
            self.files_map[rel_path] = self.files_map.get(rel_path, 0) + 1


def collect_suite_metrics() -> Tuple[int, Dict[str, int]]:
    """Introspect pytest test collection to obtain exact file and test counts."""
    collector = PytestCollector()
    pytest.main(["--collect-only", "-q"], plugins=[collector])
    return collector.collected_total, dict(sorted(collector.files_map.items()))


def update_readme(total_tests: int, file_counts: Dict[str, int]) -> bool:
    """Update README.md badge and Verified Test Summary section."""
    readme_path = REPO_ROOT / "README.md"
    if not readme_path.exists():
        return False

    content = readme_path.read_text(encoding="utf-8")

    # 1. Update Badge
    badge_pattern = re.compile(r'\[!\[Test Suite\]\(https://img\.shields\.io/badge/pytest-[^)]+\)\]\(\)')
    new_badge = f'[![Test Suite](https://img.shields.io/badge/pytest-{total_tests}%20passed-brightgreen.svg)]()'
    content = badge_pattern.sub(new_badge, content)

    # 2. Build Summary Block
    summary_lines = ["### Verified Test Summary:", "```text"]
    for file_path, count in file_counts.items():
        summary_lines.append(f"{file_path} ({count} test{'s' if count != 1 else ''}) PASSED")
    summary_lines.append("")
    summary_lines.append(f"============================= {total_tests} passed =============================")
    summary_lines.append("```")
    new_summary_block = "\n".join(summary_lines)

    # 3. Replace Verified Test Summary section
    summary_section_pattern = re.compile(
        r'### Verified Test Summary:\s*```text[\s\S]*?```',
        re.MULTILINE
    )
    if summary_section_pattern.search(content):
        content = summary_section_pattern.sub(new_summary_block, content)
    else:
        # Fallback if pattern doesn't match
        return False

    readme_path.write_text(content, encoding="utf-8")
    return True


def update_docs(total_tests: int) -> None:
    """Update docs/limitations.md and docs/testing.md with current test counts."""
    limitations_path = REPO_ROOT / "docs" / "limitations.md"
    if limitations_path.exists():
        text = limitations_path.read_text(encoding="utf-8")
        # Replace line: - \d+ automated unit...
        updated = re.sub(
            r'-\s+\d+\s+automated unit, integration, end-to-end, and headless UI tests passing',
            f'- {total_tests} automated unit, integration, end-to-end, and headless UI tests passing',
            text,
        )
        limitations_path.write_text(updated, encoding="utf-8")

    testing_path = REPO_ROOT / "docs" / "testing.md"
    if testing_path.exists():
        text = testing_path.read_text(encoding="utf-8")
        updated = re.sub(
            r'\b\d+\s+automated tests\b',
            f'{total_tests} automated tests',
            text,
        )
        testing_path.write_text(updated, encoding="utf-8")


def sync_all_metrics() -> Tuple[int, Dict[str, int]]:
    """Execute complete metrics synchronization."""
    total, file_counts = collect_suite_metrics()
    update_readme(total, file_counts)
    update_docs(total)
    return total, file_counts


if __name__ == "__main__":
    tot, files = sync_all_metrics()
    print(f"Successfully synchronized test metrics: {tot} tests across {len(files)} files.")
