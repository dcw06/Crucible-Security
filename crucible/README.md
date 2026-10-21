# Crucible

**Multi-Agent Testing Intelligence Platform**

> Three agents. One adversarial loop. Requirement-linked tests and adversarial review.

Crucible watches pull requests, generates tests with a writer/critic loop,
scans the changed source, executes approved tests in an attested sandbox, and
publishes the parsed JUnit outcomes to UiPath Test Manager through structured
test-case, test-set, execution, and test-log API calls.

Built for **UiPath AgentHack · Track 3: Test Cloud**.

🤖 Built with [Claude Code](https://claude.ai/code)

---

## Architecture

```
GitHub Webhook → durable leased job → Orchestrator
                                    ├─ Requirements Analyzer  (claude-haiku-4-5)
                                    ├─ Writer/Critic loop     (claude-sonnet-4-6 × 2)
                                    ├─ Security Agent         (semgrep + claude-sonnet-4-6)
                                    ├─ isolated test sandbox  (optional JUnit XML)
                                    └─ Test Cloud client      (create cases/set/run → logs → stats)
                                           ↓
                                    Confidence Score → PR Comment
                                           ↓ (if CRITICAL)
                                    Maestro Case
```

Application submissions use a parallel adapter path:

```text
Submission → target adapter → static inspection → optional remote browser sandbox
           → normalized JUnit + screenshots/traces + passive/a11y findings
           → conservative scan verdict
```

`WebAppAdapter` is the first common-adapter implementation. Browser execution
is disabled by default and occurs only in the separately deployed
`browser-worker/`. The dashboard requires explicit authorization, the target
must be present in `WEB_ALLOWED_HOSTS`, and destructive test plans are rejected.
Crucible accepts results only when the nonce, target, plan digest, JUnit digest,
evidence digest, isolation profile, and HMAC attestation all reconcile.

**Confidence formula:**
```
confidence = 0.3 × critic_score + 0.3 × security_score + 0.4 × sandbox_pass_rate
```
The 40% execution weight comes from the attested sandbox result. Test Cloud
publishes and independently confirms that result, but its availability cannot
hide known sandbox failures.

---

## Quick Start

### 1. Set up environment

```bash
cd ..
python3 -m venv .venv
./.venv/bin/python -m pip install -r requirements-dev.txt
cd crucible

cp .env.example .env
# Fill in ANTHROPIC_API_KEY, TC_BASE_URL, TC_TOKEN, TC_PROJECT_ID, GITHUB_*
```

### 2. Run Day 1 validation (required before anything else)

```bash
python validate_apis.py
```

All six checks must pass before using the live integrations:
1. Anthropic API key valid
2. Test Manager authentication works
3. Test-case creation schema is confirmed
4. Test-set and execution creation work
5. Test-log recording and execution statistics work
6. Semgrep installed and rulesets valid

### 3. Test TC client standalone (Day 2)

```bash
# Dry run (no TC API calls):
TC_DRY_RUN=true python tc_client.py

# Real run with an XML file:
python tc_client.py path/to/results.xml
```

### 4. Run unit tests

```bash
pytest tests/ -v
```

Includes:
- `tests/test_hmac.py` — 8 HMAC verification tests
- `tests/test_confidence.py` — 14 confidence formula tests (including demo math verification)

### 5. Start the full stack

```bash
# Local:
cd ..
make web

# Docker:
cd crucible
docker-compose up --build
```

`make web` binds to `127.0.0.1` and explicitly enables the development-only
scanner bypass. Direct and containerized production launches remain
fail-closed and require `SCANNER_ACCESS_TOKEN` to contain at least 32
characters.

Webhook server: http://localhost:8000
Dashboard:      http://localhost:8501
Health check:   http://localhost:8000/health

The dashboard opens on **Upload & scan**. Users can upload a ZIP application
or an individual source file (up to 200 MB). Crucible safely extracts the
package, rejects malformed Python/JSON before scanning, and runs the existing
Semgrep rulesets without executing uploaded code. Any CRITICAL result blocks
the upload. The **PR pipeline monitor** tab continues to display runs produced
by the existing GitHub webhook pipeline.

Desktop uploads accept packaged `.dmg`, `.pkg`, `.exe`, `.msi`, `.msix`,
AppImage, `.deb`, `.rpm`, and `.snap` artifacts for malware scanning and
conservative triage. Acceptance does not mean the package has passed a
platform distribution-safety check. macOS `.app` ZIPs receive non-executing
basic bundle metadata, entitlement, and deep code-signature inspection, but
remain `REVIEW_REQUIRED` without the additional attested macOS evidence listed
below.
Internal symlinks are lexically validated but never materialized, embedded
runtime archives remain opaque, and ClamAV covers every extracted regular file.
Artifacts return `REVIEW_REQUIRED` until a matching isolated platform worker
supplies complete attested inspection evidence. The workspace
`desktop-worker/` service implements the digest-, nonce-, policy-, platform-,
isolation-, and evidence-bound protocol plus structural inspectors for PE,
MSI, MSIX, DMG, PKG, Debian, RPM, Snap, and AppImage formats. Deploy it in a
separate Windows, macOS, or Linux execution profile with the native tools
documented there. A worker reports partial coverage when a required native tool
or provenance check is unavailable. Local native package records still include
bounded content-signature hints and extension/content mismatches; those hints
are not a substitute for attested structural inspection.

Worker startup also requires a short-lived Ed25519-signed launcher receipt.
The launcher private key is never available to the worker; the receipt binds
the sandbox identity, isolation controls, concrete resource limits, global job
deadline, unique worker instance, and one-time worker public key. Crucible
independently verifies the launcher receipt and the receipt-bound worker
signature. Each worker accepts one job and then exits.

When `ANTHROPIC_API_KEY` is configured, Claude also reviews the uploaded source
against the catalog in `security_controls.py`. Results distinguish evidenced
findings, evidenced passes, and controls that require manual review. Critical
findings from either Semgrep or Claude reject the upload. The same catalog is
included in the Writer's first test-generation iteration.

Language-specific profiles in `language_security_controls.py` add dangerous
APIs, common vulnerabilities, frameworks, and configuration checks for Python,
Java, JavaScript, TypeScript, C, C++, and C#. The scanner detects relevant
profiles from uploaded file extensions, while Semgrep uses cross-language
default, security-audit, OWASP, and secrets rulesets.

### Scanner verdicts

Upload scans are fail-closed and expose the status of every required stage:

- `PASSED` — all required scanners completed and no policy threshold was met
- `BLOCKED` — a high-confidence HIGH/CRITICAL issue or invalid app was found
- `REVIEW_REQUIRED` — analysis was partial or human evidence is required
- `SCAN_FAILED` — a required scanner did not produce a trustworthy result

Semgrep, Claude, syntax validation, dependency analysis, and malware analysis
return independent status and coverage metadata. Dependency manifests require
`osv-scanner`; malware analysis requires an operational `clamscan` installation
and signature database. Missing engines produce `SCAN_FAILED`, never a clean
result. Language validation is parser-only unless a safe local parser is
available; uploaded build scripts and tests are never executed on the host.

The deployment image pins Semgrep and OSV-Scanner and installs ClamAV, Node,
Java, and Clang tooling. Production mode disables the upload action until all
required scanner engines pass readiness checks. Set
`SECURITY_SCAN_MODE=development` only for UI work; missing engines still cannot
produce `PASSED`.

Every product control has a stable ID, verification owner, and exactly one
Claude assessment. Operational/manual controls cannot be passed by static
assertion, and dedicated malware/dependency controls are owned by their scanner
stages. Claude file coverage is recorded per file and chunk; omitted content,
model-declared incompleteness, or an incomplete control matrix prevents a
successful result.

The 200 MB value is a transport limit for ZIP applications and individual
source files, not an instruction to materialize every file in every scanner.
ZIP admission also bounds total entries (including directories), regular-file
count, path depth, UTF-8 name length, per-member expanded size, aggregate
expanded size, compression ratio, and extraction wall time. Regular files are
streamed once with CRC verification; archive links are validated but never
materialized.
Syntax parsing defaults
to 10 MB per file and model review to 5 MB per file. Files above a stage limit
are recorded as unvalidated or omitted, forcing `REVIEW_REQUIRED`. The
large-upload production profile permits one concurrent scan and a 400 MB hourly
byte quota by default.

Compose stores SQLite state in `crucible_state`, scanner scratch data in a
dedicated 1 GB tmpfs, and ClamAV signatures in `clamav_signatures`. The
`clamav-updater` service owns signature refresh; the dashboard mounts that
volume read-only. Uploaded source therefore cannot persist in the database
volume and disappears when the dashboard container is replaced.

### Trust boundaries

Model-generated tests are never executed inside the Crucible application
process or container. `TEST_EXECUTION_MODE=disabled` is the default. The only
supported execution mode is an independently operated HTTPS sandbox service
that must provide an ephemeral non-root environment, no application
credentials, disabled network access, read-only source, CPU/memory/PID/disk
limits, and hard process-tree termination. Crucible sends an immutable GitHub
commit archive with its SHA-256 digest. Results are accepted only when the
sandbox returns the same commit/digest, non-empty JUnit results, valid pytest
and infrastructure status, exact one-test-to-one-requirement results whose
totals match JUnit, the requested isolation profile, and an HMAC attestation
covering the JUnit SHA-256 digest, generated-test SHA-256 digest, and a fresh
client request nonce produced with
`TEST_SANDBOX_ATTESTATION_SECRET`.

Each test must map to exactly one requirement. Skipped tests are rejected
explicitly rather than being treated as passing evidence. The sandbox operator
must reject reuse of a request nonce for its configured retention period.

Numeric confidence cannot independently approve a merge. Critic approval,
attested sandbox execution, and requirement coverage derived from literal test
markers plus collected sandbox results are mandatory gate evidence.

Webhook verification is fail-closed. Production requires
`GITHUB_WEBHOOK_SECRET`; `ALLOW_UNSIGNED_WEBHOOKS=true` works only when
`APP_ENV` is explicitly non-production.

The upload UI requires `SCANNER_ACCESS_TOKEN` in production. Each authenticated
session is subject to a configurable scan rate, byte quota, and process-local
concurrency limit. Upload scanning intentionally refuses a `SCANNER_REPLICAS`
value other than 1 until shared quota storage is configured.

Webhook admission atomically deduplicates and persists a minimal job. Workers
lease jobs from PostgreSQL (or local SQLite), renew long-running leases, reclaim
expired leases after restart, and retain terminal failures. The health endpoint
reports counts by job status. PostgreSQL is required for multiple webhook
replicas or hosts.

Test Cloud authentication uses only the explicitly configured `TC_TOKEN`;
Crucible never reads browser cookie stores or workstation sessions.

Playwright is never run in the Streamlit or webhook containers. The optional
browser worker accepts a bounded declarative action vocabulary and restricts
navigation to an operator-configured host list. Production still requires
infrastructure-level egress filtering and an ephemeral worker container or VM
per job; browser route interception is defense in depth only.

### Web assessment engine

The deployed-web path separates deterministic evidence collection from model
review:

1. The static fetch returns sanitized `WebFetchResult` evidence: repeated
   non-secret headers, cookie names and attributes, redirects, resolved address,
   TLS coverage, and explicit truncation/address-pinning state.
2. Python passive policy checks run even when browser testing is disabled.
3. The browser worker performs a bounded rendered-DOM crawl (50 pages, depth 4,
   120 seconds), inventories pages, forms, APIs, WebSockets, scripts, manifests,
   and forbidden controls, and emits the application model as a hashed,
   attested evidence artifact.
4. Browser console/network/page-error buffers are test-local. Unhandled page
   exceptions and authorized first-party HTTP 5xx responses fail their journey.
5. Free-form requirements that cannot be mapped to the discovered model are
   returned as `REVIEW_REQUIRED`; Crucible does not invent selectors.

Set `WEB_EGRESS_PROXY_URL` for both Crucible and the browser worker. Set
`REQUIRE_WEB_EGRESS_GATEWAY=true` in production to fail closed when it is
missing. Only set `WEB_EGRESS_GATEWAY_ATTESTED=true` when the deployed gateway
actually resolves, validates, and pins public destination addresses and
preserves the original hostname for TLS verification.

Authenticated role matrices and active ZAP remain separate services by design.
They must not be enabled until a job-scoped secret resolver, disposable test
accounts/data, signed attestations, rate limits, emergency stop, and a
staging-only authorization policy are deployed. Their absence is coverage
state, never an implicit pass.

### 6. Configure GitHub webhook

In your repo → Settings → Webhooks → Add webhook:
- Payload URL: `https://your-server/webhook`
- Content type: `application/json`
- Secret: value of `GITHUB_WEBHOOK_SECRET` in your `.env`
- Events: Pull requests

---

## Development Flags

| Flag | Default | Effect |
|---|---|---|
| `TC_DRY_RUN=true` | `false` | Stubs `tc_pass_rate=0.25`, no TC API calls |
| `GITHUB_WEBHOOK_SECRET` unset | — | Production startup fails closed |
| `MAESTRO_BASE_URL` unset | — | Maestro escalation skipped silently |

---

## File Structure

```
crucible/
├── main.py              # FastAPI webhook server + durable leased worker
├── pipeline.py          # Full orchestrator — calls all agents
├── confidence.py        # Confidence formula + PR comment formatter
├── tc_client.py         # Test Cloud client (upload → trigger → poll)
├── dashboard.py         # Streamlit live dashboard
├── upload_scanner.py    # Fail-closed upload scanning pipeline
├── scan_models.py       # Typed scanner results and verdict policy
├── test_sandbox.py      # Attested remote execution client
├── scanner_access.py    # Upload authentication and admission control
├── security_controls.py # Product security-control catalog
├── language_security_controls.py # Language-specific security profiles
├── validate_apis.py     # Day 1 validation checklist (run first!)
├── agents/
│   ├── requirements_analyzer.py  # haiku — extracts req_ids from PR
│   ├── writer.py                 # sonnet — generates pytest file
│   ├── critic.py                 # sonnet — adversarial review
│   └── security.py               # sonnet + semgrep — security scan
├── state/
│   └── db.py            # SQLite shared state (FastAPI writes, Streamlit reads)
├── tests/
│   ├── test_hmac.py
│   ├── test_confidence.py
│   ├── test_security_boundaries.py
│   ├── test_pipeline_evidence_gates.py
│   ├── test_upload_scanner_fail_closed.py
│   └── test_state_db.py
├── docker-compose.yml
├── Dockerfile
├── requirements.txt
└── .env.example
```

---

## Confidence Score

| Component | Weight | Source |
|---|---|---|
| `critic_score` | 30% | `max(0.5, 1.1 − 0.1×iteration)` |
| `security_score` | 30% | Semgrep findings (WARNING cap at 4, CRITICAL=0.0) |
| `execution_pass_rate` | 40% | HMAC-attested sandbox execution result |

**Merge gates:**
- `≥ 0.85` → ✅ Auto-approve
- `0.65–0.84` → ⚠️ Review recommended
- `< 0.65` or CRITICAL → ❌ Blocked

The attested sandbox result is authoritative. Test Cloud can publish and
independently confirm that result, but its unavailability never causes known
sandbox failures to be ignored. Missing verified sandbox evidence prevents
automatic approval.

---

## Real API Gotcha

> ⚠️ GitHub's webhook payload includes `changed_files` as an **integer** (the count), not an array. Fetching the actual file list requires a separate call to `GET /repos/{owner}/{repo}/pulls/{number}/files`. Crucible handles this explicitly — see `main.py:_fetch_pr_files()`.

---

## License

MIT
