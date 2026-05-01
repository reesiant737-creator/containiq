<div align="center">

# ContainIQ

### AI-Powered Security Operations Platform

**Detect. Analyze. Contain. Recover. — All in one place.**

[![Python](https://img.shields.io/badge/Python-3.10%2B-blue?logo=python)](https://python.org)
[![Flask](https://img.shields.io/badge/Flask-3.x-lightgrey?logo=flask)](https://flask.palletsprojects.com)
[![Claude AI](https://img.shields.io/badge/AI-Claude%20API-orange)](https://anthropic.com)
[![NIST CSF](https://img.shields.io/badge/Framework-NIST%20CSF%202.0-green)](https://www.nist.gov/cyberframework)
[![License](https://img.shields.io/badge/License-MIT-purple)](LICENSE)

[Features](#features) • [Quick Start](#quick-start) • [Architecture](#architecture) • [API Reference](#api-reference) • [Playbooks](#playbook-packs) • [Deploy](#deployment)

</div>

---

## What is ContainIQ?

ContainIQ is a full-stack AI-powered Security Operations and Incident Response platform built for SOC teams who need enterprise-grade tooling without enterprise-grade pricing. It replaces manual triage, scattered spreadsheet tracking, and ad-hoc runbooks with a governed, auditable, AI-assisted workflow — from first alert to closed case to compliance report.

**The problem it solves:** Small and mid-market security teams face the same threats as Fortune 500s but can't afford $50K+/yr tools like CrowdStrike Falcon Complete or Cortex XSOAR. ContainIQ brings those capabilities to organizations of any size.

---

## Features

### Case Management
- Full incident lifecycle: Open → In Progress → Contained → Closed
- Entity tracking (IPs, users, domains, file hashes, hostnames)
- Chronological timeline with evidence locker (attachments, IOC notes)
- Severity classification: Critical / High / Medium / Low
- Role-based access: Admin, Analyst, Approver, Viewer

### AI Analyst (Claude API)
- **Case analysis** — automatic MITRE ATT&CK technique mapping and threat narrative
- **Hunt queries** — generates production-ready SPL (Splunk), KQL (Sentinel), and EQL (Elastic) queries from case context
- **Severity rationale** — explains exactly why a case is rated the way it is
- **Playbook recommendation** — matches case TTPs to the best response playbook
- **Conversational chatbot** — ask any question about a case, get an analyst-grade answer
- Prompt caching enabled for cost efficiency on repeated system context

### Governed Playbook Engine
- 5 production-ready playbook packs (see [Playbook Packs](#playbook-packs) below)
- Execution flow: Dry-run preview → Approval gates → Live execution → Rollback → Verification
- Blast-radius limits: cap how many accounts/hosts a playbook can touch in one run
- Safety constraints enforced at the engine level — can't skip them
- Full rollback manifest generated before execution begins
- Evidence checklist per playbook step

### Daily Threat Intelligence
Runs automatically at 06:00 UTC every day:
- **CISA KEV** — Known Exploited Vulnerabilities catalog (official U.S. government feed)
- **URLhaus** — Malicious URL and malware distribution feed
- **AlienVault OTX** — Open Threat Exchange IOC feed
- AI synthesizes all three into plain-English threat briefings and patch proposals

### Weekly Security Patches
- Patch bundles generated every Sunday at 03:00 UTC
- Risk-tiered auto-apply: Low = auto, Medium = analyst review, High = approver sign-off
- Detection library versioned by patch release
- Rollback with full change log — every applied change is immutable and auditable

### Alert Ingestion API
Single endpoint accepts alerts from any SIEM or EDR — format auto-detected:
- Microsoft Sentinel
- Splunk
- CrowdStrike Falcon
- Elastic Security
- Generic JSON (fallback)
- Auto-deduplication by source reference ID

### NIST CSF 2.0 Compliance
Every case is mapped across all six framework functions:
- **GV** — Govern
- **ID** — Identify
- **PR** — Protect
- **DE** — Detect
- **RS** — Respond
- **RC** — Recover

Org-wide coverage report shows gaps and actionable improvement recommendations.

### Reports & Audit Packets
- Incident report (per-case narrative + timeline + entities)
- NIST compliance audit packet
- PDF export (ReportLab)
- Immutable audit log — every action by every user, forever, append-only by design

### IOC Auto-Enrichment
Runs automatically in the background when entities are created — never blocks case ingestion:
- **VirusTotal** — malicious/suspicious/harmless engine counts for IPs, domains, and file hashes
- **AbuseIPDB** — abuse confidence score, total reports, ISP, country, TOR node detection
- Color-coded threat badges on every entity: **High Risk** / **Suspicious** / **Clean**
- Geo and ASN info displayed inline (country, AS owner, ISP)
- Gracefully skips enrichment if API keys are not configured

### MTTR & Metrics Dashboard
Real-time response time analytics at `/metrics`:
- Average, p50, and p95 MTTR across all closed cases
- Breakdown by severity tier (Critical, High, Medium, Low)
- 8-week MTTR trend chart
- SLA benchmark comparison per severity
- Stale open cases breaching the 24-hour SLA threshold
- Fastest and slowest case resolutions

### Notifications
- Slack webhook: fires on new Critical/High cases, approval requests, patch ready
- Microsoft Teams webhook
- SMTP email (Gmail, SendGrid, or any SMTP provider)

---

## Architecture

```
containiq/
├── backend/
│   ├── app.py                  # Flask app factory
│   ├── config.py               # Environment config
│   ├── models/
│   │   ├── case.py             # Case, Entity, Timeline, Evidence
│   │   ├── playbook.py         # Playbook, Run, Approval
│   │   ├── patch.py            # PatchRelease, Detection, ChangeLog
│   │   ├── threat.py           # ThreatUpdate, ThreatProposal
│   │   └── audit.py            # Immutable AuditLog
│   ├── routes/
│   │   ├── auth.py             # Login / session
│   │   ├── cases.py            # Case CRUD + AI endpoints
│   │   ├── playbooks.py        # Execution engine routes
│   │   ├── patches.py          # Patch management routes
│   │   ├── reports.py          # Report generation
│   │   ├── ai.py               # AI chatbot + analysis
│   │   ├── threat_feed.py      # Threat intel routes
│   │   ├── ingest.py           # Alert ingestion API
│   │   └── metrics.py          # MTTR dashboard + API
│   ├── services/
│   │   ├── ai_analyst.py       # Claude API integration
│   │   ├── threat_intel.py     # Feed pipeline + scheduler
│   │   ├── patch_manager.py    # Patch generation + apply/rollback
│   │   ├── playbook_runner.py  # Governed execution engine
│   │   ├── nist_mapper.py      # NIST CSF 2.0 mapping
│   │   ├── report_generator.py # Incident reports + PDF export
│   │   ├── notifier.py         # Slack + email notifications
│   │   ├── ioc_enrichment.py   # VirusTotal + AbuseIPDB (background thread)
│   │   └── demo_seeder.py      # Realistic demo data
│   └── playbooks/              # Gold-standard playbook JSON
│       ├── suspicious_inbox_rule.json
│       ├── oauth_abuse.json
│       ├── ransomware_execution.json
│       ├── lateral_movement.json
│       └── suspicious_admin_activity.json
├── frontend/
│   └── templates/              # Bootstrap 5 dark theme
├── docs/
│   └── ContainIQ_Lab_Guide.pdf # 13-page customer onboarding guide
├── run.py                      # Entry point
├── requirements.txt
├── Dockerfile
├── docker-compose.yml
└── railway.toml                # Railway one-click deploy config
```

**Tech Stack**

| Layer | Technology |
|---|---|
| Backend | Python 3.10+, Flask 3.x, SQLAlchemy 2.x |
| AI | Anthropic Claude API (claude-sonnet-4-6) with prompt caching |
| Database | SQLite (dev) / PostgreSQL (production) |
| Scheduling | APScheduler (daily intel + weekly patches) |
| Frontend | Bootstrap 5 dark theme, vanilla JavaScript |
| Reports | ReportLab (PDF generation) |
| Infra | Docker + docker-compose |

---

## Quick Start

### Option 1 — Local Python

**Prerequisites:** Python 3.10+, an [Anthropic API key](https://console.anthropic.com)

```bash
# Clone the repo
git clone https://github.com/reesiant737-creator/containiq.git
cd containiq

# Create virtual environment
python -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Configure environment
cp .env.example .env
# Edit .env and add your ANTHROPIC_API_KEY

# Run the app
python run.py
```

Open `http://localhost:5001` in your browser.

**Default login:** `admin@containiq.local` / `changeme`

**Load demo data** (realistic incidents, playbook runs, threat intel, patches):

```bash
flask seed-demo
```

---

### Option 2 — Docker

```bash
git clone https://github.com/reesiant737-creator/containiq.git
cd containiq

# Set your API key
echo "ANTHROPIC_API_KEY=sk-ant-..." > .env

# Start everything
docker-compose up -d

# Load demo data
docker-compose exec web flask seed-demo
```

Open `http://localhost:5001`

---

## Environment Variables

Copy `.env.example` to `.env` and configure:

| Variable | Required | Description |
|---|---|---|
| `ANTHROPIC_API_KEY` | **Yes** | Your Anthropic API key |
| `SECRET_KEY` | **Yes** | Flask session secret (change in production) |
| `DATABASE_URL` | No | PostgreSQL URL (defaults to SQLite) |
| `INGEST_API_KEY` | No | API key for alert ingestion endpoint |
| `OTX_API_KEY` | No | AlienVault OTX feed (free registration) |
| `VIRUSTOTAL_API_KEY` | No | VirusTotal IOC enrichment |
| `ABUSEIPDB_API_KEY` | No | AbuseIPDB reputation lookups |
| `SLACK_WEBHOOK_URL` | No | Slack notifications |
| `TEAMS_WEBHOOK_URL` | No | Microsoft Teams notifications |
| `SMTP_HOST` | No | Email notifications (any SMTP) |
| `SMTP_USER` | No | SMTP username |
| `SMTP_PASS` | No | SMTP password |
| `NOTIFY_EMAIL` | No | Destination email for alerts |
| `BASE_URL` | No | Public URL for notification links |
| `FLASK_ENV` | No | Set to `production` in prod |
| `THREAT_FEED_ENABLED` | No | Enable daily scheduler (default: true) |
| `DEMO_MODE` | No | Auto-seed demo data on first boot (set `true` for Railway/hosted demos) |

---

## API Reference

### Alert Ingestion

Accepts alerts from any SIEM or EDR. Format is auto-detected.

```
POST /api/v1/alerts
X-API-Key: <your INGEST_API_KEY>
Content-Type: application/json
```

**Supported formats:** Microsoft Sentinel, Splunk, CrowdStrike Falcon, Elastic Security, Generic JSON

**Generic JSON example:**

```json
{
  "title": "Suspicious PowerShell execution",
  "description": "Encoded command detected on WORKSTATION-01",
  "severity": "high",
  "source": "edr",
  "source_ref": "alert-7829",
  "entities": [
    { "type": "hostname", "value": "WORKSTATION-01" },
    { "type": "user", "value": "jsmith@company.com" }
  ]
}
```

**Response:**

```json
{
  "status": "created",
  "case_id": 42,
  "case_url": "http://your-server/cases/42"
}
```

Auto-deduplication: duplicate `source_ref` values return the existing case ID with `"status": "duplicate"`.

---

## Playbook Packs

### Pack A — Business Email Compromise
| Playbook | TTPs Covered |
|---|---|
| Suspicious Inbox Rule | T1564.008 — Email hiding rules, inbox forwarding exfil |
| OAuth App Abuse | T1550.001 — Pass-the-token, OAuth consent abuse |

### Pack B — Ransomware & Lateral Movement
| Playbook | TTPs Covered |
|---|---|
| Ransomware Execution | T1486 — Data encrypted for impact, T1490 — Inhibit recovery |
| Lateral Movement | T1021 — Remote services, credential hopping, SMB/RDP spread |

### Pack C — Insider Threat
| Playbook | TTPs Covered |
|---|---|
| Suspicious Admin Activity | T1078 — Valid accounts abused, privilege misuse, off-hours access |

Every playbook includes:
- Step-by-step response actions with approval gates
- Blast-radius limits (max accounts/hosts affected per run)
- Pre-execution dry-run preview
- Full rollback manifest
- Post-execution verification steps
- Evidence collection checklist

---

## NIST CSF 2.0 Coverage

ContainIQ maps every incident to all six NIST CSF 2.0 functions and generates an org-wide coverage gap report with specific, actionable recommendations.

| Function | What ContainIQ tracks |
|---|---|
| **GV — Govern** | Policy adherence, change approval workflows, audit trails |
| **ID — Identify** | Asset involvement, vulnerability context, threat actor attribution |
| **PR — Protect** | Containment actions taken, access revocation, patch application |
| **DE — Detect** | Detection rule matched, alert source, time-to-detect |
| **RS — Respond** | Playbook executed, approval chain, response timeline |
| **RC — Recover** | Rollback actions, system restoration, lessons-learned capture |

---

## Deployment

### Railway (Recommended — free tier available)

This repo includes a `railway.toml` config — Railway detects it automatically.

1. Push this repo to GitHub
2. Go to [railway.app](https://railway.app) → New Project → Deploy from GitHub
3. Select this repo
4. Add environment variables in the Railway dashboard (copy from `.env.example`)
5. Set `DEMO_MODE=true` to auto-load demo data on first boot
6. Railway builds and deploys — health check at `/api/v1/health`

### Render / Fly.io / Any Docker host

```bash
docker build -t containiq .
docker run -p 5001:5001 --env-file .env containiq
```

### Production checklist
- [ ] Set `FLASK_ENV=production`
- [ ] Set a strong random `SECRET_KEY`
- [ ] Set `DATABASE_URL` to PostgreSQL
- [ ] Set `INGEST_API_KEY` to a random value
- [ ] Configure `BASE_URL` to your public domain

---

## Use Cases

- **MSSP operations** — Manage multiple client tenants with role-based access
- **Startup security teams** — Enterprise-grade workflow without enterprise budget
- **Security training** — Load demo data + use the included 13-page lab guide for team onboarding
- **Compliance audit prep** — NIST CSF 2.0 gap report ready for auditors, immutable audit trail for SOC 2
- **SIEM integration** — One webhook call from Sentinel/Splunk/CrowdStrike creates a managed case
- **SLA reporting** — MTTR dashboard gives management real data on response time performance

---

## Customer Onboarding

A 13-page professional lab guide is included in `docs/ContainIQ_Lab_Guide.pdf` — three hands-on exercises covering the full SOC workflow:

| Lab | Scenario | Skills |
|---|---|---|
| Lab 1 | Phishing / Inbox Forwarding | Alert ingestion, IOC enrichment |
| Lab 2 | Ransomware Containment | AI analysis, playbook execution |
| Lab 3 | Incident Closure | Reporting, NIST CSF, MTTR metrics |

---

## Roadmap

- [ ] Full-text case search
- [ ] SSO / SAML (enterprise deployments)
- [ ] SLA breach alerting (time-to-acknowledge per severity)
- [ ] Stripe billing (hosted SaaS tier)
- [ ] Public landing page

---

## Contributing

Pull requests are welcome. For major changes, open an issue first to discuss what you'd like to change.

---

## License

MIT — free for personal and commercial use.

---

<div align="center">

Built by a security practitioner who wanted CrowdStrike-level workflow at startup prices.

**[Live Demo](#quick-start) • [Report a Bug](https://github.com/reesiant737-creator/containiq/issues) • [Request a Feature](https://github.com/reesiant737-creator/containiq/issues)**

</div>
