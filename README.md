# Continuous Compliance-as-Code Engine

[![Tests](https://img.shields.io/badge/tests-pytest%20%2B%20moto-brightgreen)](#running-tests)
[![Frameworks](https://img.shields.io/badge/frameworks-SOC%202%20%7C%20NIST%20800--53-blue)](#framework-mapping)
[![AWS](https://img.shields.io/badge/AWS-IAM%20%7C%20S3%20%7C%20CloudTrail%20%7C%20EC2-orange)](#supported-checks)
[![License](https://img.shields.io/badge/license-MIT-green)](#license)

A continuous compliance monitoring engine for AWS that evaluates live infrastructure against **SOC 2 Trust Service Criteria** and **NIST 800-53** controls. Features automated evidence collection, cryptographic integrity hashing, trend reporting, and optional AI-assisted control mapping.

Built to demonstrate modern **GRC Engineering**: treating compliance controls as executable, version-controlled code rather than static spreadsheets and manual screenshots.

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           Continuous Compliance Engine                       │
└─────────────────────────────────────────────────────────────────────────────┘

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
             ├──────────────────────┬──────────────────────┐
             ▼                      ▼                      ▼
    ┌─────────────────┐    ┌──────────────┐      ┌────────────────┐
    │ engine/evidence │    │ engine/report│      │ Trend Dashboard│
    │ • capture()     │    │ • render_html│      │ • plot.html    │
    │ • SHA-256 hash  │    │ • write_     │      │ (compliance %  │
    │ • manifest.json │    │   snapshot   │      │  over time)    │
    └─────────────────┘    └──────────────┘      └────────────────┘
             │                      │
             ▼                      ▼
         evidence/              reports/
     (immutable snapshots)  (HTML + JSON trends)


┌─────────────────────────────────────────────────────────────────────────────┐
│                       AI-Assisted Layer (Optional)                          │
└─────────────────────────────────────────────────────────────────────────────┘

    Unmapped control description
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
       [Human Review Required]
             │
             ▼
       checks/*.py (manual commit)
```

---

## Key Features

### 1. Declarative Control-as-Code
Controls are defined purely in YAML — separating the *what* (compliance requirement) from the *how* (boto3 check implementation).

```yaml
- id: CC6.1-01
  title: "Root account has no active access keys"
  description: >
    The root user must not have active programmatic access keys.
  severity: critical
  service: iam
  check_function: checks.iam_checks.check_root_access_keys
  remediation: >
    Sign in as root, go to My Security Credentials, and deactivate/delete
    any active access keys. Use an IAM role for all automation.
```

### 2. Pure, Isolated Check Functions
Every check is a pure function:
```python
def check_s3_bucket_encryption(session: boto3.Session) -> tuple[Status, str, dict]:
    # returns (Status.PASS/FAIL/ERROR, "human-readable message", evidence_dict)
```
- **No hidden state** — testable in isolation with `moto`
- **Safe by default** — strictly read-only, never modifies AWS resources
- **Parallelizable** — run concurrently via `ThreadPoolExecutor`

### 3. Automated Evidence Collection (Vanta/Drata-style)
For every control evaluated, the engine captures a **timestamped, SHA-256-hashed snapshot** of the raw resource state.

- Evidence is written locally or pushed to an immutable S3 bucket
- A run manifest binds every control to its evidence hash — giving auditors cryptographic proof of what was observed at scan time
- Matches the evidence pipeline architecture of commercial GRC platforms

### 4. Trend Tracking & Reporting
- **HTML Compliance Report**: Clean, stakeholder-ready summary with severity-coded findings and specific remediation steps
- **JSON Trend Snapshots**: Append-only run history for tracking compliance posture over time
- **Visual Dashboard**: Lightweight Chart.js dashboard showing score progression

### 5. AI-Assisted Control Mapping (Optional)
Answers the GRC workflow challenge: *"How do we quickly onboard new compliance requirements?"*
- Drafts candidate boto3 check functions from plain-text control descriptions
- Suggests mappings to existing checks across different frameworks
- **Human-in-the-loop**: Generated code is displayed for review, never auto-executed

---

## Framework Mapping

| Service | SOC 2 (CC Series) | NIST 800-53 (Rev 5) | Check Function |
|---------|-------------------|---------------------|----------------|
| **IAM** | CC6.1-01 | AC-6 | `checks.iam_checks.check_root_access_keys` |
| **IAM** | CC6.1-02 | IA-2(1) | `checks.iam_checks.check_root_mfa` |
| **IAM** | CC6.1-03 | IA-2(2) | `checks.iam_checks.check_iam_users_mfa` |
| **IAM** | CC6.1-04 | IA-5 | `checks.iam_checks.check_iam_password_policy` |
| **IAM** | CC6.1-08 | AC-2 | `checks.iam_checks.check_iam_unused_credentials` |
| **S3** | CC6.1-05 | SC-28 | `checks.s3_checks.check_s3_bucket_encryption` |
| **S3** | CC6.1-06 | AC-3 | `checks.s3_checks.check_s3_public_access_blocked` |
| **S3** | CC6.1-07 | CP-9 | `checks.s3_checks.check_s3_versioning_enabled` |
| **CloudTrail** | CC7.2-01 | AU-2 | `checks.cloudtrail_checks.check_cloudtrail_enabled` |
| **CloudTrail** | CC7.2-02 | AU-9 | `checks.cloudtrail_checks.check_cloudtrail_log_file_validation` |
| **CloudTrail** | CC7.2-03 | SC-28-CT | `checks.cloudtrail_checks.check_cloudtrail_encrypted` |
| **EC2** | CC6.6-01 | SC-7 | `checks.ec2_checks.check_security_groups_no_unrestricted_sensitive_ports` |
| **EC2** | CC6.1-EBS | SC-28-EBS | `checks.ec2_checks.check_ebs_default_encryption` |

---

## Quickstart

### Prerequisites
- Python 3.9+
- AWS credentials configured (read-only permissions sufficient)

### Installation

```bash
# Clone the repository
git clone https://github.com/your-username/compliance-engine.git
cd compliance-engine

# Create virtual environment
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

### Running a Compliance Scan

```bash
# Scan all frameworks against default AWS profile
python main.py scan

# Scan only SOC 2 controls
python main.py scan --frameworks soc2

# Scan with custom output directories and S3 evidence upload
python main.py scan \
  --frameworks soc2,nist800-53 \
  --output reports/ \
  --evidence-dir evidence/ \
  --evidence-bucket my-compliance-evidence-bucket \
  --profile my-aws-profile
```

### Viewing Results

1. **HTML Report**: Open `reports/run-<timestamp>_report.html` in any browser
2. **Evidence Manifest**: Inspect `evidence/run-<timestamp>_manifest.json` for SHA-256 hashes
3. **Trend Dashboard**:
   ```bash
   python scripts/generate_trend_data.py
   # Open dashboard/plot.html in your browser
   ```

---

## AI-Assisted Features

The engine includes optional LLM-assisted workflows to accelerate control onboarding:

### Draft a New Check Function
```bash
python main.py draft-check AC-17 \
  --framework nist800-53 \
  --title "Remote Access Management" \
  --description "Authorize and document all remote connections." \
  --service ec2
```

### Suggest Mapping to Existing Checks
```bash
python main.py map-control \
  --title "Multi-Factor Authentication for Privileged Users" \
  --description "Require MFA for administrative console access."
```

*(Requires `ANTHROPIC_API_KEY` set in your environment.)*

---

## Running Tests

The entire test suite uses `moto` to mock AWS services. **No real AWS credentials or network calls are required.**

```bash
# Run all tests
pytest tests/ -v

# Run with coverage report
pytest tests/ --cov=engine --cov=checks -v
```

---

## Project Structure

```
compliance-engine/
├── controls/                  # Declarative control definitions (YAML)
│   ├── soc2_cc.yaml          # SOC 2 Common Criteria controls
│   └── nist_800_53.yaml      # NIST 800-53 Rev 5 controls
├── checks/                    # Pure, testable boto3 check functions
│   ├── iam_checks.py         # Root keys, MFA, password policy, stale creds
│   ├── s3_checks.py          # Default encryption, public access block, versioning
│   ├── cloudtrail_checks.py  # Multi-region trails, log validation, KMS encryption
│   └── ec2_checks.py         # Open security group ports, EBS default encryption
├── engine/                    # Core compliance engine
│   ├── models.py             # ControlDefinition, CheckResult, Status dataclasses
│   ├── loader.py             # YAML parsing & dynamic check function resolution
│   ├── runner.py             # ThreadPoolExecutor parallel runner & scoring
│   ├── evidence.py           # SHA-256 integrity hashing & manifest generation
│   ├── report.py             # Jinja2 HTML report & trend snapshot generation
│   └── ai_mapper.py          # LLM-assisted check drafting and control mapping
├── templates/
│   └── report.html.j2        # Jinja2 HTML compliance report template
├── dashboard/
│   └── plot.html             # Chart.js compliance posture trend dashboard
├── scripts/
│   └── generate_trend_data.py# Aggregates snapshot JSONs for the dashboard
├── docs/
│   ├── architecture.md       # In-depth system design and extension guide
│   └── loom_demo_script.md   # 2-3 minute portfolio demo recording script
├── tests/                    # Comprehensive pytest + moto test suite
│   ├── conftest.py           # Mocked AWS session fixtures
│   ├── test_iam_checks.py
│   ├── test_s3_checks.py
│   ├── test_cloudtrail_checks.py
│   ├── test_ec2_checks.py
│   ├── test_loader.py
│   ├── test_runner.py
│   └── test_evidence.py
├── reports/                  # Generated reports (gitignored)
├── evidence/                 # Generated evidence snapshots (gitignored)
├── requirements.txt
└── main.py                   # Click CLI entrypoint
```

---

## Why This Matters for GRC / Security Engineering

1. **Continuous vs. Point-in-Time**: Traditional audits capture state once a year. This engine can run on an hourly cron / EventBridge schedule to detect drift within minutes.
2. **Audit Defensibility**: Having raw, SHA-256 hashed JSON snapshots means you never have to scramble to produce "proof" for an external auditor — the evidence trail is continuous and cryptographic.
3. **Multi-Framework Efficiency**: A single check function (e.g. `check_root_mfa`) simultaneously satisfies SOC 2 `CC6.1-02` and NIST 800-53 `IA-2(1)` — eliminating redundant testing.
4. **Developer-Friendly Remediation**: Every failed check output includes specific, copy-pasteable remediation steps — bridging the gap between compliance requirements and engineering execution.

---

## License

MIT License. See [LICENSE](LICENSE) for details.
