"""Integration test verifying that tampering with preserved evidence triggers integrity alerts."""

from pathlib import Path
import pytest

from src.diagnostics.gap_analysis import DiagnosticCategory
from src.evidence.verification import IntegrityStatus
from src.pipeline import ForensicPipeline
from src.storage.repository import InvestigationRepository


def test_tamper_detection_triggers_diagnostic_alert(tmp_path: Path):
    repo = InvestigationRepository(data_root=tmp_path)
    pipeline = ForensicPipeline(repository=repo)

    inv = repo.create_investigation("case_tamper", "Tamper Test Investigation")

    raw_log = b"Oct 12 10:00:00 host1 sshd[1]: Accepted publickey for alice from 10.0.0.1\n"
    preserved, _ = pipeline.ingest_evidence_bytes(inv.investigation_id, "auth.log", raw_log)

    # Initial verification: clean
    analysis_clean = pipeline.analyze_investigation(inv.investigation_id)
    assert analysis_clean["integrity_summary"].all_verified is True
    assert not any(
        d.category == DiagnosticCategory.H_EVIDENCE_INTEGRITY_ISSUE
        for d in analysis_clean["diagnostics"]
    )

    # Simulate unauthorized tampering on the preserved evidence file on disk
    stored_file = preserved.stored_path
    assert stored_file.is_file()
    
    # Overwrite with modified byte
    import os, stat
    os.chmod(stored_file, stat.S_IWRITE)
    stored_file.write_bytes(b"Oct 12 10:00:00 host1 sshd[1]: Accepted publickey for MALICIOUS_ACTOR\n")

    # Re-run pipeline analysis
    analysis_tampered = pipeline.analyze_investigation(inv.investigation_id)
    summary = analysis_tampered["integrity_summary"]

    assert summary.all_verified is False
    assert summary.mismatched_files == 1
    assert summary.results[0].status == IntegrityStatus.MISMATCH

    # Verify Diagnostic finding was raised
    h_diags = [
        d for d in analysis_tampered["diagnostics"]
        if d.category == DiagnosticCategory.H_EVIDENCE_INTEGRITY_ISSUE
    ]
    assert len(h_diags) == 1
    assert "SHA-256 integrity mismatch" in h_diags[0].explanation
