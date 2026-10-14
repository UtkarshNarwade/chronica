"""Synthetic incident data generator for AIORI-3 PS-013.

Generates three reproducible, offline incident scenarios with diverse log formats,
calibrated clock skews, and documented ground-truth answer keys stored separately from evidence.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Dict, List, Tuple

from src.evaluation.ground_truth import GroundTruthEvent, ScenarioGroundTruth


class ScenarioGenerator:
    """Generates synthetic log files and ground-truth answer keys for Scenarios 1, 2, and 3."""

    def __init__(self, output_root: Path) -> None:
        self.output_root = output_root
        self.scenarios_dir = self.output_root / "scenarios"
        self.definitions_dir = self.output_root / "scenario_definitions"
        self.scenarios_dir.mkdir(parents=True, exist_ok=True)
        self.definitions_dir.mkdir(parents=True, exist_ok=True)

    def generate_all(self) -> Dict[str, Tuple[Path, Path]]:
        """Generate all three scenarios.
        
        Returns:
            Dict mapping scenario_id -> (evidence_folder_path, ground_truth_json_path)
        """
        s1 = self.generate_scenario_1()
        s2 = self.generate_scenario_2()
        s3 = self.generate_scenario_3()
        return {
            "scenario_1": s1,
            "scenario_2": s2,
            "scenario_3": s3,
        }

    def generate_scenario_1(self) -> Tuple[Path, Path]:
        """Scenario 1: Clean Baseline.
        
        A standard multi-tier login sequence:
        1. Web access log: User loads /login and submits POST /api/auth (Nginx access log)
        2. Syslog auth.log: SSH login verification and sudo escalation (Linux syslog)
        3. App JSONL: Backend session generation and audit record
        Timestamps are consistent, valid, and chronological.
        """
        scen_dir = self.scenarios_dir / "scenario_1_clean_baseline"
        scen_dir.mkdir(parents=True, exist_ok=True)

        # 1. Nginx access log (web_access.log)
        nginx_content = (
            '192.168.1.105 - - [12/Oct/2026:10:00:01 +0000] "GET /login HTTP/1.1" 200 1420 "-" "Mozilla/5.0" "req-sec1-001"\n'
            '192.168.1.105 - - [12/Oct/2026:10:00:05 +0000] "POST /api/v1/auth HTTP/1.1" 200 450 "https://corp.local/login" "Mozilla/5.0" "req-sec1-002"\n'
            '192.168.1.105 - alice [12/Oct/2026:10:00:15 +0000] "GET /dashboard HTTP/1.1" 200 5820 "https://corp.local/dashboard" "Mozilla/5.0" "req-sec1-003"\n'
            '192.168.1.105 - alice [12/Oct/2026:10:01:00 +0000] "POST /api/v1/reports/export HTTP/1.1" 200 12040 "https://corp.local/reports" "Mozilla/5.0" "req-sec1-004"\n'
        )
        (scen_dir / "web_access.log").write_text(nginx_content, encoding="utf-8")

        # 2. Linux syslog (auth.log)
        syslog_content = (
            "Oct 12 10:00:10 srv-app-01 sshd[4102]: Accepted publickey for alice from 192.168.1.105 port 52314 ssh2\n"
            "Oct 12 10:00:11 srv-app-01 sshd[4102]: pam_unix(sshd:session): session opened for user alice by (uid=0)\n"
            "Oct 12 10:00:30 srv-app-01 sudo[4180]:    alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/usr/bin/systemctl status nginx\n"
            "Oct 12 10:01:20 srv-app-01 sshd[4102]: pam_unix(sshd:session): session closed for user alice\n"
        )
        (scen_dir / "auth.log").write_text(syslog_content, encoding="utf-8")

        # 3. JSON Lines Application log (app_audit.jsonl)
        jsonl_lines = [
            json.dumps({
                "timestamp": "2026-10-12T10:00:06.120Z",
                "level": "INFO",
                "app": "auth-service",
                "host": "srv-app-01",
                "event": "user_login_success",
                "user": "alice",
                "src_ip": "192.168.1.105",
                "request_id": "req-sec1-002",
                "session_id": "sess-99120",
                "message": "User alice authenticated successfully via MFA token.",
            }),
            json.dumps({
                "timestamp": "2026-10-12T10:00:16.050Z",
                "level": "INFO",
                "app": "portal-api",
                "host": "srv-app-01",
                "event": "dashboard_view",
                "user": "alice",
                "src_ip": "192.168.1.105",
                "request_id": "req-sec1-003",
                "session_id": "sess-99120",
                "message": "User alice loaded main executive dashboard.",
            }),
            json.dumps({
                "timestamp": "2026-10-12T10:01:01.300Z",
                "level": "INFO",
                "app": "reporting-worker",
                "host": "srv-app-01",
                "event": "report_generated",
                "user": "alice",
                "src_ip": "192.168.1.105",
                "request_id": "req-sec1-004",
                "session_id": "sess-99120",
                "message": "Financial report export completed (480 records).",
            }),
        ]
        (scen_dir / "app_audit.jsonl").write_text("\n".join(jsonl_lines) + "\n", encoding="utf-8")

        # Ground Truth Answer Key
        gt_events = [
            GroundTruthEvent("gt_1_1", 1, "2026-10-12T10:00:01.000000Z", "web_access.log", "GET /login", "req-sec1-001"),
            GroundTruthEvent("gt_1_2", 2, "2026-10-12T10:00:05.000000Z", "web_access.log", "POST /api/v1/auth", "req-sec1-002"),
            GroundTruthEvent("gt_1_3", 3, "2026-10-12T10:00:06.120000Z", "srv-app-01", "user_login_success", "req-sec1-002"),
            GroundTruthEvent("gt_1_4", 4, "2026-10-12T10:00:10.000000Z", "srv-app-01", "Accepted publickey for alice"),
            GroundTruthEvent("gt_1_5", 5, "2026-10-12T10:00:11.000000Z", "srv-app-01", "session opened for user alice"),
            GroundTruthEvent("gt_1_6", 6, "2026-10-12T10:00:15.000000Z", "web_access.log", "GET /dashboard", "req-sec1-003"),
            GroundTruthEvent("gt_1_7", 7, "2026-10-12T10:00:16.050000Z", "srv-app-01", "dashboard_view", "req-sec1-003"),
            GroundTruthEvent("gt_1_8", 8, "2026-10-12T10:00:30.000000Z", "srv-app-01", "COMMAND=/usr/bin/systemctl"),
            GroundTruthEvent("gt_1_9", 9, "2026-10-12T10:01:00.000000Z", "web_access.log", "POST /api/v1/reports", "req-sec1-004"),
            GroundTruthEvent("gt_1_10", 10, "2026-10-12T10:01:01.300000Z", "srv-app-01", "report_generated", "req-sec1-004"),
            GroundTruthEvent("gt_1_11", 11, "2026-10-12T10:01:20.000000Z", "srv-app-01", "session closed for user alice"),
        ]

        gt = ScenarioGroundTruth(
            scenario_id="scenario_1",
            scenario_name="Scenario 1: Clean Baseline",
            description="Multi-tier clean baseline log collection demonstrating normal timeline reconstruction.",
            reference_source="web_access.log",
            known_clock_offsets_sec={"srv-app-01": 0.0},
            known_timezones={"web_access.log": "UTC", "srv-app-01": "UTC"},
            expected_events=gt_events,
            expected_diagnostics_count={"A_PARSE_FAILURE": 0, "H_EVIDENCE_INTEGRITY_ISSUE": 0},
        )
        gt_path = self.definitions_dir / "scenario_1_ground_truth.json"
        gt.save_to_file(gt_path)

        return scen_dir, gt_path

    def generate_scenario_2(self) -> Tuple[Path, Path]:
        """Scenario 2: Clock Skew and Time-Zone Mismatch.
        
        Host A: Web gateway (`edge-gateway.local`), Reference clock at true UTC.
        Host B: Database/App (`db-backend-02`), Clock runs +180.0 seconds FAST (3 minutes ahead),
                and logs in Eastern Daylight Time (`-0400` / `America/New_York`).
        
        Correlated anchors: `req-tx-201`, `req-tx-202`, `req-tx-203`, `req-tx-204`.
        Naive string sorting trap:
        Host B logs recorded at 06:03:00 EDT (-0400) correspond to 10:03:00 UTC.
        Because Host B's clock is 180s fast, an event triggered by Host A at 10:00:00 UTC
        is stamped by Host B as 10:03:00 UTC (+180s).
        Without clock-skew correction, Host B operations appear to take place 3 minutes
        after they finished or out of sequence with downstream logs!
        """
        scen_dir = self.scenarios_dir / "scenario_2_clock_skew"
        scen_dir.mkdir(parents=True, exist_ok=True)

        # Host A (Reference): Web access log (edge_gateway.log)
        # UTC timestamps: 10:00:00, 10:01:00, 10:02:00, 10:03:00
        gateway_lines = [
            '10.0.0.50 - bob [12/Oct/2026:10:00:00 +0000] "POST /api/transfer HTTP/1.1" 200 120 "-" "AppClient/1.0" "req-tx-201"',
            '10.0.0.50 - bob [12/Oct/2026:10:01:00 +0000] "GET /api/account/balance HTTP/1.1" 200 85 "-" "AppClient/1.0" "req-tx-202"',
            '10.0.0.50 - bob [12/Oct/2026:10:02:00 +0000] "POST /api/audit/confirm HTTP/1.1" 200 95 "-" "AppClient/1.0" "req-tx-203"',
            '10.0.0.50 - bob [12/Oct/2026:10:03:00 +0000] "POST /api/logout HTTP/1.1" 200 45 "-" "AppClient/1.0" "req-tx-204"',
        ]
        (scen_dir / "edge_gateway.log").write_text("\n".join(gateway_lines) + "\n", encoding="utf-8")

        # Host B: Database backend JSONL (db_backend.jsonl)
        # True UTC: 10:00:00, 10:01:00, 10:02:00, 10:03:00
        # Clock offset: +180s -> Local clock reads 10:03:00, 10:04:00, 10:05:00, 10:06:00
        # Timezone: EDT (-04:00) -> 06:03:00-04:00, 06:04:00-04:00, 06:05:00-04:00, 06:06:00-04:00
        db_lines = [
            json.dumps({
                "timestamp": "2026-10-12T06:03:00.000-04:00",  # UTC equivalent: 10:03:00 (+180s skew)
                "host": "db-backend-02",
                "app": "postgres-cluster",
                "level": "INFO",
                "event": "sql_commit",
                "user": "bob",
                "request_id": "req-tx-201",
                "session_id": "sess-bob-881",
                "message": "UPDATE accounts SET balance = balance - 500 WHERE user_id = 'bob';",
            }),
            json.dumps({
                "timestamp": "2026-10-12T06:04:00.000-04:00",  # UTC equivalent: 10:04:00 (+180s skew)
                "host": "db-backend-02",
                "app": "postgres-cluster",
                "level": "INFO",
                "event": "sql_query",
                "user": "bob",
                "request_id": "req-tx-202",
                "session_id": "sess-bob-881",
                "message": "SELECT balance FROM accounts WHERE user_id = 'bob';",
            }),
            json.dumps({
                "timestamp": "2026-10-12T06:05:00.000-04:00",  # UTC equivalent: 10:05:00 (+180s skew)
                "host": "db-backend-02",
                "app": "postgres-cluster",
                "level": "INFO",
                "event": "audit_logged",
                "user": "bob",
                "request_id": "req-tx-203",
                "session_id": "sess-bob-881",
                "message": "INSERT INTO audit_log (user, action) VALUES ('bob', 'confirm_tx');",
            }),
            json.dumps({
                "timestamp": "2026-10-12T06:06:00.000-04:00",  # UTC equivalent: 10:06:00 (+180s skew)
                "host": "db-backend-02",
                "app": "postgres-cluster",
                "level": "INFO",
                "event": "session_terminated",
                "user": "bob",
                "request_id": "req-tx-204",
                "session_id": "sess-bob-881",
                "message": "Session sess-bob-881 closed by client.",
            }),
        ]
        (scen_dir / "db_backend.jsonl").write_text("\n".join(db_lines) + "\n", encoding="utf-8")

        # Ground Truth Answer Key
        gt_events = [
            GroundTruthEvent("gt_2_1", 1, "2026-10-12T10:00:00.000000Z", "edge_gateway.log", "POST /api/transfer", "req-tx-201"),
            GroundTruthEvent("gt_2_2", 2, "2026-10-12T10:00:00.000000Z", "db-backend-02", "sql_commit", "req-tx-201"),
            GroundTruthEvent("gt_2_3", 3, "2026-10-12T10:01:00.000000Z", "edge_gateway.log", "GET /api/account/balance", "req-tx-202"),
            GroundTruthEvent("gt_2_4", 4, "2026-10-12T10:01:00.000000Z", "db-backend-02", "sql_query", "req-tx-202"),
            GroundTruthEvent("gt_2_5", 5, "2026-10-12T10:02:00.000000Z", "edge_gateway.log", "POST /api/audit/confirm", "req-tx-203"),
            GroundTruthEvent("gt_2_6", 6, "2026-10-12T10:02:00.000000Z", "db-backend-02", "audit_logged", "req-tx-203"),
            GroundTruthEvent("gt_2_7", 7, "2026-10-12T10:03:00.000000Z", "edge_gateway.log", "POST /api/logout", "req-tx-204"),
            GroundTruthEvent("gt_2_8", 8, "2026-10-12T10:03:00.000000Z", "db-backend-02", "session_terminated", "req-tx-204"),
        ]

        gt = ScenarioGroundTruth(
            scenario_id="scenario_2",
            scenario_name="Scenario 2: Clock Skew and Time-Zone Mismatch",
            description=(
                "Host db-backend-02 has +180.0s clock skew and uses America/New_York EDT offset (-0400). "
                "Cross-source anchors (req-tx-201..204) allow robust median offset estimation."
            ),
            reference_source="edge_gateway.log",
            known_clock_offsets_sec={"db-backend-02": 180.0},
            known_timezones={"edge_gateway.log": "UTC", "db-backend-02": "America/New_York"},
            expected_events=gt_events,
            expected_diagnostics_count={"G_UNRESOLVED_CLOCK_SKEW": 0},
        )
        gt_path = self.definitions_dir / "scenario_2_ground_truth.json"
        gt.save_to_file(gt_path)

        return scen_dir, gt_path

    def generate_scenario_3(self) -> Tuple[Path, Path]:
        """Scenario 3: Degraded and Incomplete Evidence.
        
        Contains controlled forensic imperfections:
        - Malformed record (corrupted JSON syntax on line 2 of app.jsonl)
        - Invalid timestamp (line 4 of app.jsonl with year 9999 or invalid month 13)
        - Truncated record (line 5 of syslog ends abruptly)
        - Missing fields (auth record with no username or IP)
        - Coverage gap (45-minute silence between 11:15 and 12:00)
        - Single isolated anchor on host-sensor-99 (leads to INCONCLUSIVE_INSUFFICIENT_ANCHORS)
        - Duplicate candidate record
        """
        scen_dir = self.scenarios_dir / "scenario_3_degraded_evidence"
        scen_dir.mkdir(parents=True, exist_ok=True)

        # 1. Syslog with truncation, missing fields, duplicate line, and 45-min gap
        syslog_lines = [
            "Oct 12 11:00:00 gateway-fw sudo[101]: admin : TTY=pts/0 ; PWD=/root ; USER=root ; COMMAND=/bin/dmesg",
            "Oct 12 11:05:00 gateway-fw sshd[105]: Accepted password for root from 192.168.1.200 port 41200 ssh2",
            # Duplicate candidate line
            "Oct 12 11:05:00 gateway-fw sshd[105]: Accepted password for root from 192.168.1.200 port 41200 ssh2",
            # Missing user/IP authentication event
            "Oct 12 11:10:00 gateway-fw sshd[110]: Authentication failure for unspecified connection",
            # Truncated line
            "Oct 12 11:15:00 gateway-fw kernel: [ 4812.102] CRITICAL_HARDWARE_FAULT_MEM_SEGVIOLATION_AT_0x",
            # 45-minute coverage gap (quiet period until 12:00:00)
            "Oct 12 12:00:00 gateway-fw systemd[1]: Reached target System Reboot.",
            "Oct 12 12:01:00 gateway-fw sshd[201]: Server listening on 0.0.0.0 port 22.",
        ]
        (scen_dir / "system_degraded.log").write_text("\n".join(syslog_lines) + "\n", encoding="utf-8")

        # 2. JSONL application log with syntax error, impossible date, and single isolated anchor
        app_lines = [
            json.dumps({
                "timestamp": "2026-10-12T11:00:01Z",
                "host": "host-sensor-99",
                "app": "sensor-agent",
                "level": "INFO",
                "request_id": "isolated-anchor-77",  # ONLY 1 anchor for host-sensor-99 -> Inconclusive!
                "message": "Telemetry heartbeat initialized.",
            }),
            # Syntax error (Malformed JSON)
            '{"timestamp": "2026-10-12T11:02:00Z", "host": "host-sensor-99", "level": "ERROR", "msg": CORRUPTED_NON_JSON_TOKEN',
            json.dumps({
                "timestamp": "2026-10-12T11:04:00Z",
                "host": "host-sensor-99",
                "app": "sensor-agent",
                "level": "INFO",
                "message": "Sensor threshold check passed.",
            }),
            # Impossible/Invalid date (Feb 31 or Month 13)
            '{"timestamp": "2026-13-45T99:99:99Z", "host": "host-sensor-99", "app": "sensor-agent", "level": "WARN", "message": "Clock glitch reported."}',
            json.dumps({
                "timestamp": "2026-10-12T12:01:30Z",
                "host": "host-sensor-99",
                "app": "sensor-agent",
                "level": "INFO",
                "message": "Resumed telemetry collection following system reboot.",
            }),
        ]
        (scen_dir / "sensor_degraded.jsonl").write_text("\n".join(app_lines) + "\n", encoding="utf-8")

        # Ground Truth Answer Key documenting intentional anomalies
        gt_events = [
            GroundTruthEvent("gt_3_1", 1, "2026-10-12T11:00:00.000000Z", "gateway-fw", "COMMAND=/bin/dmesg"),
            GroundTruthEvent("gt_3_2", 2, "2026-10-12T11:00:01.000000Z", "host-sensor-99", "Telemetry heartbeat", "isolated-anchor-77"),
            GroundTruthEvent("gt_3_3", 3, "", "host-sensor-99", "CORRUPTED_NON_JSON_TOKEN", is_anomaly=True, anomaly_type="MALFORMED"),
            GroundTruthEvent("gt_3_4", 4, "2026-10-12T11:04:00.000000Z", "host-sensor-99", "threshold check passed"),
            GroundTruthEvent("gt_3_5", 5, "2026-10-12T11:05:00.000000Z", "gateway-fw", "Accepted password for root"),
            GroundTruthEvent("gt_3_6", 6, "2026-10-12T11:05:00.000000Z", "gateway-fw", "Accepted password for root", is_anomaly=True, anomaly_type="DUPLICATE"),
            GroundTruthEvent("gt_3_7", 7, "2026-10-12T11:10:00.000000Z", "gateway-fw", "Authentication failure", is_anomaly=True, anomaly_type="MISSING_FIELD"),
            GroundTruthEvent("gt_3_8", 8, "", "host-sensor-99", "Clock glitch reported", is_anomaly=True, anomaly_type="INVALID_TS"),
            GroundTruthEvent("gt_3_9", 9, "2026-10-12T11:15:00.000000Z", "gateway-fw", "CRITICAL_HARDWARE_FAULT", is_anomaly=True, anomaly_type="TRUNCATED"),
            GroundTruthEvent("gt_3_10", 10, "2026-10-12T12:00:00.000000Z", "gateway-fw", "Reached target System Reboot"),
            GroundTruthEvent("gt_3_11", 11, "2026-10-12T12:01:00.000000Z", "gateway-fw", "Server listening on 0.0.0.0"),
            GroundTruthEvent("gt_3_12", 12, "2026-10-12T12:01:30.000000Z", "host-sensor-99", "Resumed telemetry collection"),
        ]

        gt = ScenarioGroundTruth(
            scenario_id="scenario_3",
            scenario_name="Scenario 3: Degraded or Incomplete Evidence",
            description=(
                "Stress-testing scenario with deliberate malformed records, invalid timestamp, "
                "missing identity fields, duplicate records, 45-minute coverage gap, and inconclusive clock skew."
            ),
            reference_source="system_degraded.log",
            known_clock_offsets_sec={"host-sensor-99": 0.0},
            known_timezones={"system_degraded.log": "UTC", "host-sensor-99": "UTC"},
            expected_events=gt_events,
            expected_coverage_gaps=[{
                "host": "gateway-fw",
                "start": "2026-10-12T11:15:00Z",
                "end": "2026-10-12T12:00:00Z",
                "duration_minutes": 45.0,
            }],
            expected_diagnostics_count={
                "A_PARSE_FAILURE": 1,
                "C_TIMESTAMP_FAILURE": 1,
                "E_MISSING_FIELD_WARNING": 1,
                "F_COVERAGE_GAP": 1,
                "G_UNRESOLVED_CLOCK_SKEW": 1,
                "I_DUPLICATE_CANDIDATE": 1,
            },
        )
        gt_path = self.definitions_dir / "scenario_3_ground_truth.json"
        gt.save_to_file(gt_path)

        return scen_dir, gt_path
