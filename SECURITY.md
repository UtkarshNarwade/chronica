# Security Policy & Threat Model

Chronica is an air-gapped, offline digital forensics incident investigation and timeline reconstruction tool. It is engineered to safely ingest untrusted log files collected from compromised systems and reconstruct defensible chronological event sequences without compromising the investigator's host.

---

## 1. Operational Threat Model & Trust Boundaries

### Execution Environment & Air-Gap Invariants
- **Localhost Binding:** Chronica binds strictly to `127.0.0.1` (`server.address = "127.0.0.1"` in `.streamlit/config.toml`). It never listens on public or external network interfaces by default.
- **Zero Remote Dependencies:** Chronica makes zero runtime network calls, contains no telemetry (`gatherUsageStats = false`), loads no CDN assets, and operates entirely air-gapped.
- **Detailed Error Redaction:** Debug stack traces are suppressed in the browser interface (`client.showErrorDetails = false`) to prevent internal path and memory disclosure.

### Assets Under Protection
1. **Pristine Physical Evidence:** Stored evidence files are marked read-only (`0444`) and protected against modification by non-destructive forensic operations.
2. **Custody Ledger Integrity:** Append-only cryptographic audit chain (`audit_chain.jsonl`) anchored in SQLite and external sidecars, verifying complete chain of custody.
3. **Analyst Workstation Safety:** Ingestion of hostile inputs (zip bombs, path traversal attacks, formula injections) is neutralized before system state is affected.

---

## 2. STRIDE Security Matrix & Controls

| STRIDE Category | Threat Description | Implemented Control |
|---|---|---|
| **Spoofing** | Attacker crafts forged log messages attributing activity to innocent identities. | Chronica treats log identities as unverified input claims, preserving raw text and labeling sources as recorded rather than ground truth. |
| **Tampering** | Modification of evidence files or truncation of audit logs post-collection. | SHA-256 manifest verification, dual-anchored audit chain head, and atomic staged ingestion rollback. |
| **Repudiation** | Denial that an event occurred or inability to prove provenance. | Every timeline event records `evidence_id`, `original_filename`, `line_number`, and pristine `raw_text`. State changes produce durable ledger entries. |
| **Information Disclosure** | Leakage of case evidence or network metadata via beaconing or telemetry. | Total air-gap enforcement; Markdown exports neutralize image beacon syntax (`![...](...)`) and raw HTML tags (`<img`, `<script>`). |
| **Denial of Service** | Archive bombs (zip/tar.gz) or ReDoS regexes crashing analyst workstation. | Streaming archive extraction with running byte cap and depth limits; regex searches bounded by time budgets. |
| **Elevation of Privilege** | Code execution via parser exploits, SQL injection, or CSV formula injection. | Strict parameterized SQLite queries, no `eval()`/`exec()`, single-quote escaping on formula trigger characters (`=`, `+`, `-`, `@`, `\t`, `\r`) in CSV export. |

---

## 3. Local Passphrase Gate for Destructive Actions

To protect against inadvertent or unauthenticated data loss in shared lab environments, Chronica provides a local passphrase gate:

- **Salted Key Derivation Function:** PBKDF2-HMAC-SHA256 with 100,000 iterations and 16-byte cryptographically secure random salt (`secrets.token_bytes(16)`).
- **Constant-Time Verification:** Verification against stored derivation hashes utilizes `hmac.compare_digest` to prevent timing side-channel attacks.
- **Protected Actions:**
  - `delete_investigation`: Deletion of case files and database records.
  - `restore_investigation`: Case restoration from external backup bundles.
  - `export_investigation`: Case data and evidence bundle extraction.

When configured via `PassphraseGate`, all protected actions require valid passphrase authorization. If unconfigured, the gate defaults to open for single-user triage.

---

## 4. Reporting Vulnerabilities

If you discover a security vulnerability or evidence integrity flaw in Chronica, please document the reproduction steps and submit a private security advisory or report via the repository issue tracker. Because Chronica is a forensics reference tool, forensic accuracy and parser safety defects are treated with the highest severity.
