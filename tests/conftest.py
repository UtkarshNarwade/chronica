"""Pytest configuration and global fixtures for Chronica test suite."""

from __future__ import annotations

from pathlib import Path
import sys

# Ensure repository root is on sys.path for test discovery and sub-process execution
REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

