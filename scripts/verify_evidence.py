"""CLI utility to verify cryptographic SHA-256 evidence integrity."""

import argparse
from pathlib import Path
import sys

repo_root = Path(__file__).resolve().parent.parent
if str(repo_root) not in sys.path:
    sys.path.insert(0, str(repo_root))

from src.evidence.manifest import EvidenceManifest
from src.evidence.verification import verify_evidence_integrity


def main() -> None:
    parser = argparse.ArgumentParser(description="Verify Chronica digital evidence integrity.")
    parser.add_argument("--manifest", required=True, help="Path to manifest.json")
    parser.add_argument("--evidence-dir", required=True, help="Path to preserved evidence directory")
    args = parser.parse_args()

    manifest_path = Path(args.manifest)
    evidence_dir = Path(args.evidence_dir)

    if not manifest_path.is_file():
        print(f"Error: Manifest not found: {manifest_path}", file=sys.stderr)
        sys.exit(1)

    if not evidence_dir.is_dir():
        print(f"Error: Evidence dir not found: {evidence_dir}", file=sys.stderr)
        sys.exit(1)

    manifest = EvidenceManifest.load_from_file(manifest_path)
    summary = verify_evidence_integrity(evidence_dir, manifest)

    print(f"\n========================================================")
    print(f"Evidence Integrity Verification Audit: {manifest.investigation_id}")
    print(f"Audit Executed UTC: {summary.verification_time_utc}")
    print(f"========================================================")
    print(f"Total Files:      {summary.total_files}")
    print(f"Verified Intact:  {summary.verified_files}")
    print(f"Hash Mismatches:  {summary.mismatched_files}")
    print(f"Missing Files:    {summary.unavailable_files}")
    print(f"--------------------------------------------------------")

    for r in summary.results:
        symbol = "[OK]" if r.status == "VERIFIED" else "[FAIL]"
        print(f"{symbol} {r.original_filename} ({r.status.value})")
        print(f"     Recorded SHA-256:   {r.recorded_sha256}")
        print(f"     Calculated SHA-256: {r.calculated_sha256 or 'N/A'}")
        if r.status != "VERIFIED":
            print(f"     Details: {r.details}")

    print(f"--------------------------------------------------------")
    if summary.all_verified:
        print("[SUCCESS] All preserved evidence files verified bit-for-bit intact.\n")
        sys.exit(0)
    else:
        print("[WARNING] Integrity violations or missing evidence detected!\n")
        sys.exit(2)


if __name__ == "__main__":
    main()
