"""SQLite database schema and persistence for investigations, events, and evidence."""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

from src.timeline.schema import Event


class DatabaseManager:
    """Manages the SQLite database schema and parameterized queries."""

    def __init__(self, db_path: Union[str, Path]) -> None:
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_schema()

    def _get_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.db_path))
        conn.row_factory = sqlite3.Row
        return conn

    def _init_schema(self) -> None:
        """Create tables if they do not exist."""
        with self._get_connection() as conn:
            cur = conn.cursor()

            # Investigations
            cur.execute("""
                CREATE TABLE IF NOT EXISTS investigations (
                    investigation_id TEXT PRIMARY KEY,
                    title TEXT NOT NULL,
                    description TEXT,
                    notes TEXT,
                    created_at_utc TEXT NOT NULL,
                    last_updated_utc TEXT NOT NULL
                )
            """)

            # Evidence Files
            cur.execute("""
                CREATE TABLE IF NOT EXISTS evidence_files (
                    evidence_id TEXT PRIMARY KEY,
                    investigation_id TEXT NOT NULL,
                    original_filename TEXT NOT NULL,
                    stored_filename TEXT NOT NULL,
                    file_size_bytes INTEGER NOT NULL,
                    sha256_digest TEXT NOT NULL,
                    collection_time_utc TEXT NOT NULL,
                    detected_format TEXT,
                    selected_parser TEXT,
                    ingestion_status TEXT NOT NULL,
                    record_count INTEGER DEFAULT 0,
                    assigned_timezone TEXT,
                    notes TEXT,
                    FOREIGN KEY (investigation_id) REFERENCES investigations(investigation_id) ON DELETE CASCADE
                )
            """)

            # Events
            cur.execute("""
                CREATE TABLE IF NOT EXISTS events (
                    event_id TEXT PRIMARY KEY,
                    investigation_id TEXT NOT NULL,
                    evidence_id TEXT NOT NULL,
                    original_filename TEXT NOT NULL,
                    line_number INTEGER NOT NULL,
                    raw_text TEXT NOT NULL,
                    original_timestamp_str TEXT,
                    parsed_dt_iso TEXT,
                    normalized_utc_iso TEXT,
                    corrected_utc_iso TEXT,
                    normalization_status TEXT NOT NULL,
                    timezone_assumed TEXT,
                    year_inferred INTEGER NOT NULL DEFAULT 0,
                    estimated_clock_offset_sec REAL,
                    correction_uncertainty_sec REAL,
                    correction_status TEXT NOT NULL,
                    source_host TEXT,
                    source_app TEXT,
                    severity TEXT NOT NULL,
                    category TEXT NOT NULL,
                    username TEXT,
                    src_ip TEXT,
                    dst_ip TEXT,
                    description TEXT NOT NULL,
                    request_id TEXT,
                    session_id TEXT,
                    parsing_status TEXT NOT NULL,
                    warnings_json TEXT,
                    provenance_json TEXT,
                    extra_fields_json TEXT,
                    FOREIGN KEY (investigation_id) REFERENCES investigations(investigation_id) ON DELETE CASCADE
                )
            """)

            # Indexes for efficient search & timeline queries
            cur.execute("CREATE INDEX IF NOT EXISTS idx_events_inv ON events(investigation_id)")
            cur.execute("CREATE INDEX IF NOT EXISTS idx_events_norm_ts ON events(normalized_utc_iso)")
            cur.execute("CREATE INDEX IF NOT EXISTS idx_events_corr_ts ON events(corrected_utc_iso)")
            cur.execute("CREATE INDEX IF NOT EXISTS idx_events_req_id ON events(request_id)")
            cur.execute("CREATE INDEX IF NOT EXISTS idx_events_host ON events(source_host)")
            cur.execute("CREATE INDEX IF NOT EXISTS idx_events_user ON events(username)")
            cur.execute("CREATE INDEX IF NOT EXISTS idx_events_ip ON events(src_ip)")

            conn.commit()

    def save_events(self, investigation_id: str, events: List[Event]) -> None:
        """Insert or replace events in bulk."""
        if not events:
            return

        with self._get_connection() as conn:
            cur = conn.cursor()
            query = """
                INSERT OR REPLACE INTO events (
                    event_id, investigation_id, evidence_id, original_filename, line_number,
                    raw_text, original_timestamp_str, parsed_dt_iso, normalized_utc_iso,
                    corrected_utc_iso, normalization_status, timezone_assumed, year_inferred,
                    estimated_clock_offset_sec, correction_uncertainty_sec, correction_status,
                    source_host, source_app, severity, category, username, src_ip, dst_ip,
                    description, request_id, session_id, parsing_status, warnings_json,
                    provenance_json, extra_fields_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """
            rows = [
                (
                    e.event_id,
                    investigation_id,
                    e.evidence_id,
                    e.original_filename,
                    e.line_number,
                    e.raw_text,
                    e.original_timestamp_str,
                    e.parsed_dt_iso,
                    e.normalized_utc_iso,
                    e.corrected_utc_iso,
                    e.normalization_status,
                    e.timezone_assumed,
                    1 if e.year_inferred else 0,
                    e.estimated_clock_offset_sec,
                    e.correction_uncertainty_sec,
                    e.correction_status,
                    e.source_host,
                    e.source_app,
                    e.severity,
                    e.category,
                    e.username,
                    e.src_ip,
                    e.dst_ip,
                    e.description,
                    e.request_id,
                    e.session_id,
                    e.parsing_status,
                    json.dumps(e.data_quality_warnings),
                    json.dumps(e.provenance),
                    json.dumps(e.extra_fields),
                )
                for e in events
            ]
            cur.executemany(query, rows)
            conn.commit()

    def get_events(self, investigation_id: str) -> List[Event]:
        """Fetch all events belonging to an investigation."""
        with self._get_connection() as conn:
            cur = conn.cursor()
            cur.execute(
                "SELECT * FROM events WHERE investigation_id = ? ORDER BY normalized_utc_iso ASC",
                (investigation_id,),
            )
            rows = cur.fetchall()

            events: List[Event] = []
            for r in rows:
                ev = Event(
                    event_id=r["event_id"],
                    investigation_id=r["investigation_id"],
                    evidence_id=r["evidence_id"],
                    original_filename=r["original_filename"],
                    line_number=r["line_number"],
                    raw_text=r["raw_text"],
                    original_timestamp_str=r["original_timestamp_str"],
                    parsed_dt_iso=r["parsed_dt_iso"],
                    normalized_utc_iso=r["normalized_utc_iso"],
                    corrected_utc_iso=r["corrected_utc_iso"],
                    normalization_status=r["normalization_status"],
                    timezone_assumed=r["timezone_assumed"],
                    year_inferred=bool(r["year_inferred"]),
                    estimated_clock_offset_sec=r["estimated_clock_offset_sec"],
                    correction_uncertainty_sec=r["correction_uncertainty_sec"],
                    correction_status=r["correction_status"],
                    source_host=r["source_host"],
                    source_app=r["source_app"],
                    severity=r["severity"],
                    category=r["category"],
                    username=r["username"],
                    src_ip=r["src_ip"],
                    dst_ip=r["dst_ip"],
                    description=r["description"],
                    request_id=r["request_id"],
                    session_id=r["session_id"],
                    parsing_status=r["parsing_status"],
                    data_quality_warnings=json.loads(r["warnings_json"] or "[]"),
                    provenance=json.loads(r["provenance_json"] or "{}"),
                    extra_fields=json.loads(r["extra_fields_json"] or "{}"),
                )
                events.append(ev)
            return events

    def delete_investigation_events(self, investigation_id: str) -> None:
        """Delete all events associated with an investigation."""
        with self._get_connection() as conn:
            cur = conn.cursor()
            cur.execute("DELETE FROM events WHERE investigation_id = ?", (investigation_id,))
            conn.commit()
