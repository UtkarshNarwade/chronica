"""Integration test for full investigation lifecycle: creation, ingestion, updates, and deletion."""

from pathlib import Path
import pytest

from src.pipeline import ForensicPipeline
from src.storage.repository import InvestigationRepository


def test_investigation_lifecycle_isolation(tmp_path: Path):
    repo = InvestigationRepository(data_root=tmp_path)
    pipeline = ForensicPipeline(repository=repo)

    # 1. Create two separate investigations
    inv1 = repo.create_investigation("case_001", "Investigation Alpha", description="Alpha case")
    inv2 = repo.create_investigation("case_002", "Investigation Beta", description="Beta case")

    assert len(repo.list_investigations()) == 2

    # 2. Ingest evidence into Case 1
    log1 = b"Oct 12 10:00:00 host1 sshd[1]: Accepted publickey for alice from 10.0.0.1 port 22\n"
    pipeline.ingest_evidence_bytes(inv1.investigation_id, "auth.log", log1)

    # 3. Ingest different evidence into Case 2
    log2 = b'{"timestamp": "2026-10-12T12:00:00Z", "event": "db_query", "user": "bob"}\n'
    pipeline.ingest_evidence_bytes(inv2.investigation_id, "app.jsonl", log2)

    # 4. Verify evidence and events are isolated
    events1 = repo.load_events(inv1.investigation_id)
    events2 = repo.load_events(inv2.investigation_id)

    assert len(events1) == 1
    assert events1[0].username == "alice"

    assert len(events2) == 1
    assert events2[0].username == "bob"

    # 5. Update notes on Case 1
    inv1.notes = "Case 1 reviewed: authenticated user is alice."
    repo.update_investigation(inv1)
    reloaded_inv1 = repo.get_investigation("case_001")
    assert "alice" in reloaded_inv1.notes

    # 6. Delete Case 1 and verify Case 2 remains unaffected
    repo.delete_investigation("case_001")

    assert repo.get_investigation("case_001") is None
    assert len(repo.load_events("case_001")) == 0
    assert not (tmp_path / "investigations" / "case_001").exists()

    # Case 2 must still exist intact!
    assert repo.get_investigation("case_002") is not None
    assert len(repo.load_events("case_002")) == 1
    assert (tmp_path / "investigations" / "case_002").exists()
