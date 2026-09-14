# Architecture

## System Overview

```
┌─────────────────────────────────────────────────────────────────────┐
│                           Compliance Engine                          │
└─────────────────────────────────────────────────────────────────────┘

   ┌──────────────────┐
   │  controls/*.yaml │  ◄── Declarative control definitions
   │  • soc2_cc.yaml  │      (framework, ID, severity, check_function)
   │  • nist_800_53   │
   └────────┬─────────┘
            │
            ▼
   ┌──────────────────┐
   │  engine/loader   │  ◄── Loads YAML, resolves check_function strings
   │  • load_controls │      into actual Python callables
   │  • resolve_all   │
   └────────┬─────────┘
            │
            ▼
   ┌──────────────────┐
   │  checks/*.py     │  ◄── Pure functions: (boto3.Session) → (Status, str, dict)
   │  • iam_checks    │      Read-only AWS API calls
   │  • s3_checks     │
   │  • cloudtrail    │
   │  • ec2_checks    │
   └────────┬─────────┘
            │
            ▼
   ┌──────────────────┐
   │  engine/runner   │  ◄── Parallel execution (ThreadPoolExecutor)
   │  • run()         │      Catches exceptions → ERROR status
   │  • summarize()   │      Calculates compliance %
   └────────┬─────────┘
            │
            ├───────────────────┬──────────────────┐
            ▼                   ▼                  ▼
   ┌─────────────────┐  ┌──────────────┐  ┌────────────────┐
   │ engine/evidence │  │ engine/report│  │ Trend Dashboard│
   │ • capture()     │  │ • render_html│  │ • plot.html    │
   │ • SHA-256 hash  │  │ • write_     │  │ (compliance %  │
   │ • manifest.json │  │   snapshot   │  │  over time)    │
   └─────────────────┘  └──────────────┘  └────────────────┘
            │                   │
            ▼                   ▼
        evidence/           reports/
        (gitignored)        (gitignored)


┌─────────────────────────────────────────────────────────────────────┐
│                      AI-Assisted Layer (Optional)                    │
└─────────────────────────────────────────────────────────────────────┘

   Control without check_function?
            │
            ▼
   ┌──────────────────┐
   │ engine/ai_mapper │  ◄── Anthropic Claude API
   │ • draft_check_   │      Drafts candidate boto3 check function OR
   │   function()     │      maps to existing check
   │ • suggest_       │
   │   mapping()      │
   └──────────────────┘
            │
            ▼
      [Human review required]
            │
            ▼
      checks/*.py (manual commit)
```

## Data Flow

1. **Load**: `loader.load_controls()` reads YAML → list of `ControlDefinition` objects
2. **Resolve**: `loader.resolve_all()` turns `"checks.iam_checks.check_root_mfa"` strings into actual Python functions
3. **Execute**: `ComplianceRunner.run()` executes every (control, check_function) pair in parallel via `ThreadPoolExecutor`
4. **Collect**: Each check returns `(Status, message, evidence_dict)` → wrapped in `CheckResult`
5. **Evidence**: `EvidenceCollector.capture_all()` hashes each evidence dict (SHA-256), writes to disk/S3, produces manifest
6. **Report**: `render_html_report()` + `write_trend_snapshot()` produce browsable HTML and JSON for trending
7. **Trend**: `dashboard/plot.html` globs the JSON snapshots and renders compliance score over time

## Key Design Decisions

### Pure Functions for Checks
Every check is a pure function with no hidden state:
```python
def check_xyz(session: boto3.Session) -> tuple[Status, str, dict]:
    client = session.client("...")
    # boto3 calls here
    return (Status.PASS, "message", {"evidence": "data"})
```

This makes checks:
- **Testable** in isolation with `moto` (mocked AWS)
- **Composable** — no implicit dependencies between checks
- **Parallelizable** — ThreadPoolExecutor can run them concurrently

### Controls as Data, Not Code
Adding a new control = adding 6 lines of YAML + writing one function. The runner, evidence collector, and report generator never need to change. This is the compliance-as-code equivalent of "open-closed principle" — open for extension (new controls), closed for modification (engine internals).

### Evidence Integrity
Every check's `evidence` dict is:
1. Timestamped (ISO 8601 UTC)
2. Hashed (SHA-256 of canonical JSON)
3. Stored immutably (local or S3, write-once)
4. Indexed in a manifest

This mirrors how platforms like Vanta/Drata work — the point isn't just "we passed," it's "here's the cryptographic proof of what we observed at this timestamp."

### Read-Only by Default
The engine never modifies AWS resources. It's a read-only auditing tool. This makes it safe to run against production accounts (with appropriate IAM read-only role), and the worst-case failure mode is "the check errors out," not "the check deleted your S3 bucket."

### Parallel Execution
20+ boto3 API calls serially = 20+ seconds. With `ThreadPoolExecutor(max_workers=8)`, the same scan finishes in 3-4 seconds — I/O-bound API calls are perfect for thread-based parallelism, and boto3 clients are thread-safe when created per-thread or from a shared session.

## Extension Points

### Adding a New Control
1. Write the check function in `checks/<service>_checks.py`
2. Add a test in `tests/test_<service>_checks.py` using `moto`
3. Add the YAML entry in `controls/<framework>.yaml`
4. Run the scan — the engine auto-discovers and executes it

### Adding a New Framework
1. Create `controls/<framework>.yaml` with `framework: <name>` and a list of controls
2. Reference existing check functions or write new ones
3. Run: `python main.py scan --frameworks <name>`

### AI-Assisted Drafting (Optional)
```bash
python main.py draft-check AC-17 \
  --framework nist800-53 \
  --title "Remote access" \
  --description "The information system..." \
  --service ec2
```

Returns AI-drafted candidate function → review → commit to `checks/` if valid.

## Testing Strategy

- **Unit tests** for every check function (moto-mocked AWS)
- **Integration tests** for loader + runner (load real YAML, resolve real functions, run against mocked AWS)
- **Evidence integrity test** (hash is deterministic, manifest is valid JSON)
- **No live AWS calls in tests** — entire suite runs in CI without credentials

## Security Considerations

- **Least-privilege IAM**: Engine needs only read-only permissions (e.g., `SecurityAudit` managed policy)
- **No secrets in evidence**: Evidence dicts contain resource config (security group rules, IAM policy names), not sensitive values (passwords, private keys)
- **Sandboxed testing**: All tests use `moto` — no risk of accidentally hitting a real account
- **AI-generated code review**: The AI mapper produces code for human review, never auto-executes it
