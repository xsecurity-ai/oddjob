# Code Analysis Capability — PR Spec

## Context

Every critical/high finding on the OPENAI engagement came from source review, not Ghost.
The current stack (nmap, masscan, portscan, amass, gobuster, vhost, katana, screenshot,
httpx, nuclei, replay, nslookup, reverse_ip) found infra findings and generated most of
the false positives. The actual crits — SQLi, evals RCE, open proxies, path traversal,
IDOR, tar-slip, torch.load RCE, the Artifactory cred leak — came from reading code.

This spec adds the capability to run SAST/SCA/secret-scanning tools against source repos
and import their findings into Oddjob automatically.

---

## Phase 1: Repo Asset + SARIF Ingestion (P0)

### 1a. `repo` target kind

Add `"repo"` to the existing `Target.kind` vocabulary alongside `host | mobile | cloud`.

A repo target is identified by its clone URL (lowercased, like every other host). It has
no IP, no liveness — treated like `mobile` for those purposes. The `host` field carries
the repo slug or URL, e.g. `github.com/openai/whisper` or the bare URL.

**Backend changes:**

- `backend/app/models.py:474-490` — add `"repo"` to the comment vocabulary. No migration
  needed (it's a free-text column with a default).
- `backend/app/schemas.py:392` — extend the `Literal["host", "mobile", "cloud"]` to
  `Literal["host", "mobile", "cloud", "repo"]`.
- `backend/app/schemas.py:454` — `_kind_implies` validator: for `repo`, clear
  `ip_address`/`ip_addresses`/`alive` (same as `mobile`). No `provider` required.
- `backend/app/routers/targets.py` — no changes needed; the page query and counts work
  identically (a repo can have vulns attached).

**Frontend changes:**

- `frontend/src/lib/api.ts:120` — add `'repo'` to the `kind` union.
- `frontend/src/lib/entities.ts:29-32` — add `{ value: 'repo', label: 'Repository' }`
  to the target-type options.
- `frontend/src/views/TargetsView.tsx` — the "IP Addresses" column already shows "N/A"
  for non-host kinds; no change needed. The status-icons column (scanned/web/critical)
  works unchanged: a repo with vulns shows the red dot.

**Why not a new model?** A `Target` row is the unit of "asset we care about in this
project." A repo is exactly that. Making it a separate model would mean every finding
endpoint, filter, search, and table needs a second join path. The kind discriminator
already exists and already handles two non-host asset types.

### 1b. SARIF importer

A new module `backend/app/importers/sarif.py` implementing the standard importer
interface:

```python
def looks_like(content: bytes) -> bool:
    """True if this is a SARIF 2.1.0 JSON document."""
    # Check for "version": "2.1.0" and "runs" array in first 512 bytes.

def parse(content: bytes, *, project_id: int) -> ParsedScan:
    """Parse SARIF into the IR."""
```

**Mapping SARIF → IR:**

| SARIF field | IR field | Notes |
|---|---|---|
| `runs[].tool.driver.rules[].id` | `ParsedVuln.external_id` | e.g. `python.lang.security.audit-eval-injection` |
| `runs[].tool.driver.name` | `ParsedVuln.scanner` | e.g. "Semgrep", "CodeQL" |
| `results[].ruleId` → rule's `defaultConfiguration.level` | `ParsedVuln.severity` | error→high, warning→medium, note→low; overridden by `properties.security-severity` if present |
| `results[].message.text` | `ParsedVuln.title` + `description` | |
| `results[].locations[0].physicalLocation.artifactLocation.uri` | `ParsedVuln.description` (file path) | SARIF has no file:line IR field; we encode it into description and the new `location` field below |
| `results[].locations[0].physicalLocation.region.startLine` | (see 1c) | |
| `results[].properties.security-severity` (CVSS score) | severity override | Map 9.0+→critical, 7.0+→high, 4.0+→medium, else low |
| `results[].fingerprints` or rule id + file + line | dedupe key | Used for upsert-on-external_id |

**SARIF → Target resolution:**

The SARIF importer needs to know which target (repo) the findings belong to. Two options:

1. **Explicit**: the import request includes `target_host` (the repo slug). The ghost
   task runner sets this from its own args. Preferred — unambiguous.
2. **Inferred**: parse the `originalUriBaseIds` or `artifactLocation.uriBaseId` to
   extract a git URL. Fragile; fallback only.

**Registration:**

- `backend/app/importers/__init__.py:65` — add `"sarif": ("SARIF 2.1 (semgrep, codeql, grype)", sarif.parse)` to REGISTRY.
- Add `sarif.looks_like` to `_DETECTORS`.
- SARIF is JSON and can be large (multi-repo org scans); add to `STREAMABLE` if we want
  chunked upload, or just raise `MAX_BYTES` for this format.

### 1c. Code-finding location fields on Vuln

Add two nullable columns to the `Vuln` model to carry source-location data that network
findings don't have:

```python
# Which file and line in which repo this finding is at. NULL for network findings.
file_path: Mapped[str | None] = mapped_column(String(1024))
line_number: Mapped[int | None] = mapped_column(Integer)
```

Migration: `alembic revision --autogenerate` — two nullable columns, no backfill.

The SARIF importer populates these. The frontend VulnModal shows them when present
("src/main.py:42"). Network importers leave them NULL.

**Why not just put it in description?** Because the targets table's status column and
any future "code findings" filter need to distinguish code findings from network ones,
and file:line is structured data that benefits from being queryable (e.g. "all findings
in this directory").

### 1d. Semgrep ghost task

**Backend:**

- `backend/app/routers/agents.py:258` — add to TASK_KINDS:
  ```python
  "semgrep": "sarif",       # outputs SARIF, imported as SARIF
  "trufflehog": "sarif",    # trufflehog --json → we wrap in SARIF or use its own JSON
  "osv": "sarif",           # osv-scanner --format=sarif
  ```
- `backend/app/roe.py:63` — add to IMPACT:
  ```python
  "semgrep": "read_only",   # reads source, writes nothing to the target
  "trufflehog": "read_only",
  "osv": "read_only",
  ```

**Ghost (Go):**

- `ghost/internal/tasks/tasks.go` — add runner:
  ```go
  func runSemgrep(ctx context.Context, t *Task) (*Result, error) {
      // args: {repo_url, branch?, semgrep_config?, sarif_path}
      // 1. git clone (shallow, --depth 1 unless full_history=true)
      // 2. semgrep scan --config <config> --json --sarif --output <path> <dir>
      // 3. Return the SARIF file content as the task output
  }
  ```
- Add `"semgrep": runSemgrep` to the `Runners` map.
- `ghost/internal/tools/tools.go` — add `"semgrep"` to `Known` (installable via pip/uv).
  Semgrep is a single binary (or uv tool), so installation is straightforward.

**Task args schema (JSON in AgentTask.args):**

```json
{
  "repo_url": "https://github.com/org/repo.git",
  "branch": "main",
  "config": "auto",           // or a specific rule set path / semgrep registry ID
  "depth": 1,                 // git clone depth; 0 = full history (for trufflehog)
  "full_history": false       // trufflehog: scan all commits, not just HEAD
}
```

**Trufflehog specifics:**

- `--only-verified` for live verification (reduces the ~35 benign secrets we cleared).
- `--fail` to exit non-zero on findings.
- Output: JSON lines → wrap into SARIF in the ghost before returning, OR add a
  separate `"trufflehog"` import format that parses its native JSON. The latter is
  simpler and avoids a lossy SARIF conversion for secrets. Decision: **native JSON
  importer** for trufflehog (like `nuclei` has its own), SARIF for semgrep/osv.

### 1e. Trufflehog native JSON importer

```python
# backend/app/importers/trufflehog.py
def looks_like(content: bytes) -> bool: ...
def parse(content: bytes, *, project_id: int) -> ParsedScan: ...
```

Trufflehog JSON output is an array of objects with `source`, `detector_name`,
`raw` (the secret), `verification_result`, `commit`, `file`, `line`. Maps to:

- `ParsedVuln` with severity from detector criticality, title = detector name.
- `ParsedCredential` for the actual secret value (goes into FindingSecret).
- `external_id` = `{detector_name}:{file}:{line}:{commit[:8]}` for dedupe.

---

## Phase 2: SCA + Deep Taint (P1)

### 2a. OSV-Scanner / Grype ghost task

```python
"osv": "sarif",   # osv-scanner --format=sarif
"grype": "sarif", # grype --output sarif
```

Same runner pattern as semgrep: clone repo (or scan a Docker image), run the tool,
return SARIF. The SARIF importer handles ingestion identically.

**Args:**
```json
{
  "repo_url": "...",
  "lockfiles_only": true,   // fast mode: just parse lock files, no full clone
  "image": null             // or a Docker image reference for container SCA
}
```

### 2b. CodeQL ghost task

Heavier: requires per-repo database build (5-30 min per repo). Same pattern but with
a longer timeout and the `--sarif` output flag.

```python
"codeql": "sarif",
```

**Args:**
```json
{
  "repo_url": "...",
  "languages": ["python", "javascript"],  // which QL packs to run
  "queries": "security-and-extended"     // or specific .qlref paths
}
```

CodeQL is a large install (~500 MB). Add to `Known` tools but NOT to `Baseline`.
The agent installs it on demand when its first codeql task arrives.

---

## Phase 3: Close the Noisy Gaps (P2)

### 3a. Retire.js + source-map recovery

Not a ghost task — this is a frontend/client-side analysis. Two options:

1. **Ghost task**: `retirejs` runner that takes a list of JS URLs (from httpx/katana
   results), downloads them, runs retire.js against the library DB, and reports
   known-vulnerable versions. Output: SARIF or native JSON.
2. **Backend analysis**: when a WebAddress is imported with a detected JS file URL,
   the backend queues a retire.js check.

Option 1 is simpler and keeps the pattern consistent. Add `"retirejs": "sarif"` to
TASK_KINDS.

### 3b. DNS takeover / subdomain takeover scanner

The images.openai.com takeover check was done manually. This maps to an existing
capability gap:

- New ghost task kind: `"takeover"` — takes a list of CNAME targets, checks each
  against known provider patterns (the backend already has `app/takeover.py` with the
  provider database). The ghost does the live HTTP check; the backend's takeover module
  provides the pattern matching.
- Output: native JSON (not SARIF — these are infra findings, not code findings).

### 3c. Cloud enumeration

`"cloud_enum"` task kind: given a cloud account/subscription scope, enumerate public
buckets, blobs, registries. This is more of an operator-driven task than an automated
scan. Lower priority; can be a `shell` task initially with structured output parsing.

---

## Phase 4: Structural Gaps

### 4a. Secret triage: "verified_benign" state

Current: `needs_investigating | true_positive | false_positive`.

The ~35 cleared secrets (Cloudflare Access tokens, MS FIDO challenges,
persisted-query hashes) are not false positives in the traditional sense — they're real
secrets that a human confirmed don't matter. Adding a fourth state:

```python
TRIAGE_STATES = ("needs_investigating", "true_positive", "false_positive", "verified_benign")
```

- `verified_benign` = "this is a real secret, but it's been assessed and confirmed
  non-sensitive (test token, public key, FIDO challenge, etc.)"
- Distinct from `false_positive` which means "the scanner was wrong, there's no
  secret here at all."
- Frontend: add to the triage dropdown in VulnModal, with a distinct colour
  (green-ish, between TP and FP).

**Migration:** No data migration needed — it's a new allowed value on an existing
free-text column. The validator in `routers/findings.py:839` needs the new value added.

### 4b. SARIF import endpoint (manual)

Beyond ghost tasks, operators will want to upload SARIF files directly (from local
semgrep runs, CI pipelines, etc.). This is already handled by the existing
`POST /api/scans/import` endpoint once the SARIF format is registered — no new
endpoint needed. The `GET /api/scans/formats` response auto-includes it.

### 4c. Frontend: code-finding display

- **VulnModal**: when `file_path` and `line_number` are present, show a "Location"
  row: `src/main.py:42` in monospace font with a copy button.
- **Targets table status column**: a repo target with vulns shows the red critical dot
  (already works via `total_criticals > 0`). Could add a distinct "code scanned" icon
  (e.g. a code-brackets icon) when the target has findings with non-null `file_path`.
- **Import view**: SARIF appears in the format picker automatically. Add a blurb:
  `"sarif": "SARIF 2.1 — semgrep, CodeQL, grype, osv-scanner output"`.

---

## Implementation Order

| Step | What | Effort | Unblocks |
|------|------|--------|----------|
| 1 | `repo` target kind (backend + frontend) | S | Everything else |
| 2 | `file_path` / `line_number` columns on Vuln + migration | S | SARIF importer |
| 3 | SARIF importer module + registration | M | Manual SARIF upload |
| 4 | Semgrep ghost task (Go runner + install) | M | Automated code scanning |
| 5 | Trufflehog JSON importer + ghost task | M | Org-wide secret scanning |
| 6 | `verified_benign` triage state | S | Secret triage workflow |
| 7 | Frontend: file:line in VulnModal + import blurb | S | Polish |
| 8 | OSV/Grype ghost task (reuses SARIF) | S | SCA |
| 9 | CodeQL ghost task | M | Deep taint |
| 10 | Retire.js / takeover / cloud_enum | L | P2 gaps |

Steps 1-4 are the critical path: "if Oddjob added one thing, it should be a semgrep
ghost task + SARIF import against a repo asset."

---

## Files Touched (Phase 1)

| File | Change |
|------|--------|
| `backend/app/models.py` | Vuln.file_path, Vuln.line_number columns; Target.kind comment |
| `backend/app/schemas.py` | kind Literal + validator; VulnOut new fields |
| `backend/app/importers/sarif.py` | NEW: SARIF parser |
| `backend/app/importers/trufflehog.py` | NEW: Trufflehog JSON parser |
| `backend/app/importers/__init__.py` | REGISTRY + _DETECTORS entries |
| `backend/app/routers/agents.py` | TASK_KINDS: semgrep, trufflehog, osv; KIND_TOOL |
| `backend/app/roe.py` | IMPACT entries |
| `backend/app/routers/findings.py` | TRIAGE_STATES validator (verified_benign) |
| `backend/alembic/versions/xxx_vuln_code_location.py` | NEW migration |
| `ghost/internal/tasks/tasks.go` | runSemgrep, runTrufflehog runners + Runners map |
| `ghost/internal/tools/tools.go` | semgrep, trufflehog in Known |
| `frontend/src/lib/api.ts` | kind union + Vuln fields |
| `frontend/src/lib/entities.ts` | repo option |
| `frontend/src/views/ImportView.tsx` | SARIF blurb |
| `frontend/src/components/VulnModal.tsx` | file:line display |
