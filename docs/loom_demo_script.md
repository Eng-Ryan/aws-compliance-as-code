# 2-3 Minute Portfolio Demo Script (Loom)

Use this script to record a crisp, high-impact walkthrough of the compliance engine. GRC hiring managers often prefer watching a short video over cloning a repo.

---

## Setup Before Recording

1. Open VS Code with the project folder.
2. Open a terminal split:
   - Left: Terminal ready to run commands.
   - Right: VS Code editor showing `controls/soc2_cc.yaml`.
3. Have a browser window ready in the background to show the generated HTML report and trend dashboard.
4. Run one scan beforehand so you have sample data in `reports/` and `evidence/`.

---

## Video Script

### [0:00 - 0:30] Hook & Problem Statement
> *"Hi, I'm [Your Name]. I built this Continuous Compliance-as-Code engine to solve a problem every security and compliance team faces: traditional audits rely on manual screenshots, point-in-time spreadsheets, and scramble periods that drift out of date the minute infrastructure changes.*
>
> *This engine treats compliance controls as executable, version-controlled code mapped directly to SOC 2 and NIST 800-53 frameworks."*

### [0:30 - 1:00] Architecture & Declarative Controls
*(Point to `controls/soc2_cc.yaml` in VS Code)*
> *"Controls are defined purely in YAML — separating the compliance requirement from the check implementation. Here you see SOC 2 CC6.1 mapped to a specific boto3 check function, with severity and remediation guidance.*
>
> *Each check function is completely pure and read-only. It takes a boto3 session, evaluates the AWS resource state, and returns a pass/fail status along with the raw evidence dict."*

### [1:00 - 1:30] Live Execution & Parallel Runner
*(Switch to terminal and run the scan)*
```bash
python main.py scan --frameworks soc2,nist800-53
```
> *"When I trigger a scan, the engine uses a ThreadPoolExecutor to run all 20+ controls across IAM, S3, CloudTrail, and EC2 in parallel against the AWS account in just a few seconds.*
>
> *Notice what happens under the hood: it doesn't just give a pass/fail. For every single control, it captures the raw resource state, computes a SHA-256 cryptographic hash, and writes it to an evidence manifest — the same evidentiary pattern used by commercial GRC platforms like Vanta and Drata."*

### [1:30 - 2:00] Report & Trend Dashboard
*(Switch to browser, show the generated HTML report)*
> *"Here's the generated HTML report. It shows our overall compliance posture, breakdown by severity, and specific actionable remediation steps for any failing controls.*
>
> *(Switch tab to `dashboard/plot.html`)*
> *Because each run writes an append-only JSON snapshot, we can trend compliance posture over time and catch configuration drift before an auditor does."*

### [2:00 - 2:30] Testing & AI Layer
*(Switch back to terminal, run pytest)*
```bash
pytest tests/ -v
```
> *"The entire engine is backed by a comprehensive unit test suite using `moto` — mocking AWS services so everything runs reliably in CI with zero live credentials needed.*
>
> *I also built an optional AI-assisted mapper that uses Claude to draft candidate check functions from new compliance requirements, accelerating the GRC onboarding workflow."*

### [2:30 - 2:45] Close
> *"This project demonstrates how we can bridge the gap between compliance requirements and engineering execution. All the code is open-source on my GitHub. Thanks for watching!"*

---

## Recording Tips

- **Pacing**: Speak at a steady, confident pace. Don't rush through code explanations.
- **Resolution**: Record at 1080p minimum so terminal text and YAML are easily readable.
- **Font Size**: Increase VS Code and terminal font size to 16-18px.
- **Keep it under 3 minutes**: Hiring managers appreciate concise, high-signal communication.
