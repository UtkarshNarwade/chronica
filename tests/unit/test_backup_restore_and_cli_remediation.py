"""Tests reproducing and verifying F-19:
- CLI returns non-zero exit code when evidence integrity or audit chain fails.
- JSON backup includes clock skew estimates, integrity summary, audit chain, and evidence files.
- Full backup/restore round-trip preserves metadata, manifest, evidence hashes, skew, and ledger.
- Export operations record an audited ledger entry (INVESTIGATION_EXPORTED).
"""

import json
import pytest

from src.evidence.verification import verify_evidence_integrity
from src.pipeline import ForensicPipeline
from src.reporting.json_export import export_investigation_json, restore_investigation_from_json
from src.storage.repository import InvestigationRepository
from src.timeline.clock_skew import ClockSkewEstimate
import scripts.chronica_cli as cli_mod


def test_reproduce_cli_exits_nonzero_on_tamper_or_chain_failure(tmp_path, monkeypatch):
    """Reproduce F-19 defect 1: CLI must exit non-zero when integrity or audit chain is broken."""
    data_dir = tmp_path / "data"
    out_dir = tmp_path / "out"
    repo = InvestigationRepository(data_root=data_dir)
    pipeline = ForensicPipeline(repo)
    repo.create_investigation("case_cli_fail", "CLI Fail Test")

    # Ingest a real sample log
    log_line = b"2026-10-12T10:00:00Z web-01 sshd[1234]: Accepted publickey for admin from 192.168.1.1 port 22 ssh2\n"
    pipeline.ingest_evidence_bytes("case_cli_fail", "auth.log", log_line)

    # Tamper with the evidence file directly to break vault integrity
    ev_path = repo.get_evidence_file_path("case_cli_fail", repo.get_manifest("case_cli_fail").entries[0].evidence_id)
    assert ev_path is not None and ev_path.is_file()
    ev_path.chmod(0o666)
    ev_path.write_bytes(b"TAMPERED EVIDENCE BYTES")
    ev_path.chmod(0o444)

    # Create a dummy log to satisfy --ingest requirement
    dummy_log = tmp_path / "new_event.log"
    dummy_log.write_text("2026-10-12T10:05:00Z web-01 sshd[1234]: Failed password for invalid user hacker from 10.0.0.9 port 22 ssh2\n")

    # Run CLI main targeting this case
    test_args = [
        "chronica_cli.py",
        "--case-id", "case_cli_fail",
        "--ingest", str(dummy_log),
        "--data-dir", str(data_dir),
        "--output-dir", str(out_dir),
    ]
    monkeypatch.setattr("sys.argv", test_args)

    exit_code = cli_mod.main()
    # DEFECT: CLI currently returns 0 even on integrity compromise!
    assert exit_code != 0, f"Expected non-zero exit code on compromised integrity, got {exit_code}"


def test_reproduce_json_backup_includes_skew_integrity_and_roundtrips(tmp_path):
    """Reproduce F-19 defect 2: JSON export must include skew, integrity, and support full restore."""
    repo = InvestigationRepository(data_root=tmp_path / "data")
    pipeline = ForensicPipeline(repo)
    inv = repo.create_investigation("case_backup", "Backup Test")

    log_line = b"2026-10-12T10:00:00Z web-01 sshd[1234]: Accepted publickey for admin from 192.168.1.1 port 22 ssh2\n"
    pipeline.ingest_evidence_bytes("case_backup", "auth.log", log_line)

    # Calculate skew and integrity
    pipeline.analyze_investigation("case_backup")
    manifest = repo.get_manifest("case_backup")
    integ_summary = verify_evidence_integrity(repo.get_evidence_dir("case_backup"), manifest)

    # Export JSON backup with full data
    skew_est = {
        "db-01": ClockSkewEstimate(
            target_source="db-01",
            reference_source="web-01",
            anchor_count=5,
            estimated_offset_sec=180.0,
            spread_mad_sec=0.5,
            uncertainty_sec=2.0,
        )
    }

    manifest = repo.get_manifest("case_backup")
    events = repo.load_events("case_backup")
    diagnostics = []

    json_str = export_investigation_json(
        metadata=inv,
        manifest=manifest,
        events=events,
        diagnostics=diagnostics,
        skew_estimates=skew_est,
        integrity_summary=integ_summary,
        repo=repo,
    )

    backup_data = json.loads(json_str)
    assert "clock_skew_analysis" in backup_data
    assert "db-01" in backup_data["clock_skew_analysis"]
    assert backup_data["evidence_integrity"]["verified_all"] is True
    assert "audit_ledger" in backup_data
    assert len(backup_data["audit_ledger"]) > 0
    assert "evidence_files" in backup_data
    assert len(backup_data["evidence_files"]) == 1

    # Restore into a fresh repository
    from src.reporting.json_export import restore_investigation_from_json
    restore_repo = InvestigationRepository(data_root=tmp_path / "restore_data")
    restored_inv = restore_investigation_from_json(json_str, restore_repo)
    assert restored_inv.investigation_id == "case_backup"

    # Verify restored integrity and manifest
    integ_summary = restore_repo.verify_evidence_integrity("case_backup")
    assert integ_summary.all_verified is True

    # Verify restored audit chain
    chain_ok, chain_cnt, chain_err = restore_repo.get_audit_ledger("case_backup").verify_chain()
    assert chain_ok is True, f"Restored audit chain failed: {chain_err}"
    assert chain_cnt >= 2


def test_reproduce_export_writes_audit_ledger_entry(tmp_path, monkeypatch):
    """Reproduce F-19 defect 3: Generating case exports must append an audited ledger entry."""
    data_dir = tmp_path / "data"
    out_dir = tmp_path / "out"
    repo = InvestigationRepository(data_root=data_dir)
    repo.create_investigation("case_export_audit", "Export Audit Test")

    dummy_log = tmp_path / "sample.log"
    dummy_log.write_text("2026-10-12T10:00:00Z web-01 sshd[1234]: Accepted publickey for admin from 192.168.1.1 port 22 ssh2\n")

    test_args = [
        "chronica_cli.py",
        "--case-id", "case_export_audit",
        "--ingest", str(dummy_log),
        "--data-dir", str(data_dir),
        "--output-dir", str(out_dir),
    ]
    monkeypatch.setattr("sys.argv", test_args)
    cli_mod.main()

    ledger = repo.get_audit_ledger("case_export_audit")
    actions = [e.action for e in ledger.get_entries()]
    assert "INVESTIGATION_EXPORTED" in actions, f"Expected INVESTIGATION_EXPORTED in ledger actions, found: {actions}"


def test_adversarial_restore_detects_tampered_evidence_payload(tmp_path):
    """Adversarial check 1: Restore must fail loudly if evidence payload in JSON backup was tampered."""
    repo = InvestigationRepository(data_root=tmp_path / "data")
    pipeline = ForensicPipeline(repo)
    inv = repo.create_investigation("case_adv_tamper", "Adv Tamper Test")

    log_line = b"2026-10-12T10:00:00Z web-01 sshd[1234]: Accepted publickey for admin from 192.168.1.1 port 22 ssh2\n"
    pipeline.ingest_evidence_bytes("case_adv_tamper", "auth.log", log_line)
    manifest = repo.get_manifest("case_adv_tamper")
    events = repo.load_events("case_adv_tamper")

    json_str = export_investigation_json(
        metadata=inv,
        manifest=manifest,
        events=events,
        diagnostics=[],
        repo=repo,
    )

    # Tamper with the evidence data inside the JSON payload
    data = json.loads(json_str)
    assert len(data["evidence_files"]) > 0
    # Alter the base64 content so hash does not match
    data["evidence_files"][0]["data_base64"] = "QUFBQUFBQUE="  # b"AAAAAAAA"

    restore_repo = InvestigationRepository(data_root=tmp_path / "tamper_restore_data")
    with pytest.raises(ValueError, match="integrity check failed"):
        restore_investigation_from_json(data, restore_repo)


def test_adversarial_cli_exits_nonzero_on_broken_audit_chain(tmp_path, monkeypatch):
    """Adversarial check 2: CLI must return non-zero when audit chain is truncated/corrupted."""
    data_dir = tmp_path / "data"
    out_dir = tmp_path / "out"
    repo = InvestigationRepository(data_root=data_dir)
    pipeline = ForensicPipeline(repo)
    repo.create_investigation("case_chain_fail", "Chain Fail Test")

    log_line = b"2026-10-12T10:00:00Z web-01 sshd[1234]: Accepted publickey for admin from 192.168.1.1 port 22 ssh2\n"
    pipeline.ingest_evidence_bytes("case_chain_fail", "auth.log", log_line)

    # Corrupt the last line in the audit chain ledger file
    ledger = repo.get_audit_ledger("case_chain_fail")
    with open(ledger.ledger_path, "a", encoding="utf-8") as f:
        f.write('{"seq_id": 999, "action": "FORGED", "entry_hash": "0000"}\n')

    dummy_log = tmp_path / "dummy.log"
    dummy_log.write_text("2026-10-12T10:05:00Z web-01 kernel: test\n")

    test_args = [
        "chronica_cli.py",
        "--case-id", "case_chain_fail",
        "--ingest", str(dummy_log),
        "--data-dir", str(data_dir),
        "--output-dir", str(out_dir),
    ]
    monkeypatch.setattr("sys.argv", test_args)
    exit_code = cli_mod.main()

    assert exit_code != 0, f"Expected non-zero exit code when audit chain is broken, got {exit_code}"


def test_adversarial_restore_backup_without_evidence_files(tmp_path):
    """Adversarial check 3: JSON backup without evidence files restores metadata and empty manifest."""
    repo = InvestigationRepository(data_root=tmp_path / "data")
    inv = repo.create_investigation("case_no_ev", "No Evidence Case")
    manifest = repo.get_manifest("case_no_ev")

    json_str = export_investigation_json(
        metadata=inv,
        manifest=manifest,
        events=[],
        diagnostics=[],
        repo=repo,
        include_evidence_bytes=False,
    )

    data = json.loads(json_str)
    assert len(data["evidence_files"]) == 0

    restore_repo = InvestigationRepository(data_root=tmp_path / "restore_no_ev")
    restored = restore_investigation_from_json(data, restore_repo)
    assert restored.investigation_id == "case_no_ev"
    assert restored.title == "No Evidence Case"



