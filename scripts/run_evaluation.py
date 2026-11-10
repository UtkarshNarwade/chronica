"""Automated benchmark evaluation across all three synthetic scenarios."""

from __future__ import annotations

from pathlib import Path
import sys

repo_root = Path(__file__).resolve().parent.parent
if str(repo_root) not in sys.path:
    sys.path.insert(0, str(repo_root))

from src.evaluation.runner import run_evaluation, run_benchmark

__all__ = ["run_evaluation", "run_benchmark"]

if __name__ == "__main__":
    run_benchmark()
