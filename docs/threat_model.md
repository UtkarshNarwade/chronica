# Chronica Threat Model & Security Controls

**Security Assessment and Adversarial Analysis for AIORI-3 PS-013**

---

## 1. System Mission and Trust Boundaries

Chronica operates as an offline forensic triage application run on an analyst workstation. Its primary function is to ingest untrusted log files collected from compromised systems and produce reliable chronological incident timelines.

### Primary Assets to Protect
1. **Preserved Evidence Integrity:** Pristine log files must remain unmodified on disk once collected.
2. **Analysis Neutrality:** Output timeline must not be manipulated by maliciously crafted log records into concealing activity or framing legitimate users.
3. **Analyst Workstation Security:** Ingestion of malicious log files must not result in arbitrary code execution (RCE) on the investigator's host.

---

## 2. Threat Actor Profiles & Capabilities

| Threat Actor | Motivation | Assumed Capabilities |
|---|---|---|
| **Adversary with System Access** | Conceal lateral movement, forge audit logs, frame innocent users. | Can write arbitrary text to log files, manipulate system clocks, delete log records before collection. |
| **Insider / Disgruntled Employee** | Obfuscate tampering or log deletion. | Can insert fragmented or corrupted log lines, alter timezone environment variables. |
| **Untrusted File Input (Attacker)** | Exploit forensic parser vulnerability to compromise investigator machine. | Can submit files with path traversal filenames (`../../`), polyglot payloads, null bytes, or zip bombs. |

---

## 3. STRIDE Threat Analysis & Implemented Mitigations

### 3.1 Spoofing (Forged Logs & Attacker Identity)
- **Threat:** Attacker writes fake syslog lines attributing malicious activity to another user.
- **Forensic Boundary:** Chronica does not certify that the source log was genuine when generated; it only certifies that the log has not changed *since collection*.
- **Mitigation:** Chronica explicitly labels all usernames and IPs as "Recorded Attributes from Log" rather than authoritative ground truth. Reports include a formal disclaimer that findings reflect evidence as provided.

### 3.2 Tampering (Post-Collection Evidence Alteration)
- **Threat:** An insider or malware alters log records after evidence collection to remove incriminating lines.
- **Mitigation:**
  - Raw bytes are hashed with SHA-256 before parsing and written to read-only evidence files.
  - Manifest records cryptographic digests and composite hashes.
  - One-click and automated re-verification checks detect single-bit alterations (`IntegrityStatus.MISMATCH`).

### 3.3 Repudiation (Denial of Action)
- **Threat:** An investigator cannot prove which raw line generated a timeline finding.
- **Mitigation:** Full bidirectional provenance tracking. Every `Event` record retains `original_filename`, `line_number`, `evidence_id`, and exact `raw_text`.

### 3.4 Information Disclosure (Leakage of Sensitive Evidence)
- **Threat:** Evidence files leaked to external third parties or public endpoints.
- **Mitigation:**
  - 100% offline local processing: No cloud APIs, no external telemetry, no remote databases.
  - Parameterized local SQLite storage with strict file permissions.

### 3.5 Denial of Service (Crash or Resource Exhaustion)
- **Threat:** Gigabyte-sized log bomb or deeply recursive payload exhausts analyst RAM.
- **Mitigation:**
  - Configurable file-size enforcement (default: 100 MB max).
  - Chunked 64 KB streaming hashing without loading full files into memory.
  - Line-by-line streaming parser generators (`iter()`).

### 3.6 Elevation of Privilege (Parser Exploitation / RCE)
- **Threat:** Attacker injects shell escapes, SQL injection, or code execution into log lines.
- **Mitigation:**
  - **No `eval()` or `exec()`**: Log lines are parsed strictly via Python standard library regexes and `json.loads()`.
  - **Path Traversal Protection**: `EvidenceCollector.sanitize_filename()` strips all POSIX and Windows directory separators, replaces path traversal (`..`), and forces safe names.
  - **SQL Injection Prevention**: All SQLite database queries use parameterized placeholders (`?`).
  - **XSS Prevention in UI**: Streamlit native tables and code blocks escape raw HTML/JavaScript.

---

## 4. Residual Risks & Forensic Disclaimers

1. **Pre-Collection Alteration:** If an attacker cleared logs or modified NTP clocks prior to the investigator capturing the log files, SHA-256 integrity only guarantees preservation of the collected state, not the prior reality.
2. **Local Administrator Access:** A local root/admin user on the investigator workstation could modify both the evidence files and the manifest simultaneously. Digital signatures using hardware tokens (e.g. PKCS#11) are recommended for judicial proceedings.
