#!/usr/bin/env python3
"""Chronica Performance & Scalability Benchmark.

Measures heuristic analysis and timeline assembly across synthetic event volumes:
2k, 4k, 8k, 20k, and 100k events.

Target (F-04 acceptance criteria):
- Roughly linear scaling (avoid O(N^2) quadratic explosion)
- 100k events analyze in under 60 seconds on a standard workstation
"""

from __future__ import annotations

import sys
import time
from pathlib import Path
from typing import List

# Ensure repository root is on sys.path
REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from src.diagnostics.heuristics import ForensicHeuristicEngine
from src.timeline.schema import Event


def generate_synthetic_workload(count: int) -> List[Event]:
    """Generate a realistic forensic workload with mixed event severities and categories."""
    events: List[Event] = []
    base_epoch = 1791800000

    hosts = ["web-01", "db-01", "app-02", "auth-gw"]
    users = ["alice", "bob", "admin", "service_db", "deployer"]

    for i in range(count):
        host = hosts[i % len(hosts)]
        user = users[i % len(users)]
        sec = base_epoch + (i // 2)

        if i % 50 == 0:
            sev = "AUTH_SUCCESS"
            desc = f"Accepted publickey for {user} from 192.168.1.100 port 52341 ssh2"
            raw = f"Oct 12 10:00:00 {host} sshd[1234]: {desc}"
            extra = {}
        elif i % 50 == 1 and i > 0:
            sev = "HIGH"
            desc = f"sudo: {user} : TTY=pts/1 ; PWD=/home/{user} ; USER=root ; COMMAND=/bin/cat /etc/shadow"
            raw = f"Oct 12 10:00:01 {host} sudo[1235]: {desc}"
            extra = {}
        elif i % 100 == 10:
            sev = "INFO"
            desc = "GET /api/v1/database/export?dump=full HTTP/1.1 200"
            raw = f'192.168.1.100 - {user} [12/Oct/2026:10:00:10 +0000] "{desc}" 200 45000'
            extra = {"response_bytes": 45000}
        elif i % 25 == 5:
            sev = "AUTH_FAIL"
            desc = "Failed password for invalid user root from 10.0.0.99 port 41232 ssh2"
            raw = f"Oct 12 10:00:05 {host} sshd[1236]: {desc}"
            extra = {}
        else:
            sev = "INFO"
            desc = f"GET /static/bundle_{i % 500}.js HTTP/1.1 200"
            raw = f'192.168.1.50 - - [12/Oct/2026:10:00:00 +0000] "{desc}" 200 1234'
            extra = {"response_bytes": 1234}

        ev = Event.create(
            investigation_id="bench_inv",
            evidence_id="ev_bench",
            original_filename=f"{host}_system.log",
            line_number=i + 1,
            raw_text=raw,
            original_timestamp_str=f"epoch:{sec}",
            normalized_utc_iso=f"2026-10-12T10:{(i//3600)%24:02d}:{(i//60)%60:02d}.{i%1000:03d}000Z",
            corrected_utc_iso=f"2026-10-12T10:{(i//3600)%24:02d}:{(i//60)%60:02d}.{i%1000:03d}000Z",
            source_host=host,
            severity=sev,
            username=user if sev != "INFO" or "user" in desc else None,
            description=desc,
            extra_fields=extra,
        )
        events.append(ev)

    return events


def run_benchmark(tiers: List[int] = None) -> List[dict]:
    """Execute benchmark across event tiers and return performance metrics."""
    if tiers is None:
        tiers = [2000, 4000, 8000, 20000, 100000]

    engine = ForensicHeuristicEngine()
    results = []

    print("=" * 80)
    print("CHRONICA FORENSIC HEURISTIC ENGINE BENCHMARK (F-04)")
    print("=" * 80)

    for count in tiers:
        sys.stdout.write(f"Generating {count:,} synthetic events... ")
        sys.stdout.flush()
        t_gen_0 = time.perf_counter()
        events = generate_synthetic_workload(count)
        gen_time = time.perf_counter() - t_gen_0
        sys.stdout.write(f"done ({gen_time:.2f}s). Analyzing... ")
        sys.stdout.flush()

        t_ana_0 = time.perf_counter()
        leads = engine.analyze(events)
        ana_time = time.perf_counter() - t_ana_0
        eps = count / ana_time if ana_time > 0 else float("inf")

        sys.stdout.write(f"done in {ana_time:.3f}s ({eps:,.0f} events/sec, {len(leads)} leads)\n")

        results.append({
            "count": count,
            "analysis_sec": round(ana_time, 3),
            "events_per_sec": int(eps),
            "leads_count": len(leads),
            "under_target": bool(ana_time < 60.0 if count == 100000 else True),
        })

    print("-" * 80)
    print(f"{'Events':>10} | {'Analysis Time':>15} | {'Throughput':>18} | {'Leads':>8} | {'Status':>10}")
    print("-" * 80)
    for r in results:
        status = "PASS (<60s)" if r["under_target"] else "FAIL (>60s)"
        print(f"{r['count']:>10,d} | {r['analysis_sec']:>13.3f}s | {r['events_per_sec']:>14,d} ev/s | {r['leads_count']:>8d} | {status:>10}")
    print("=" * 80)

    return results


if __name__ == "__main__":
    run_benchmark()
