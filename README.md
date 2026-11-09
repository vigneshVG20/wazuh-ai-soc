# Wazuh AI SOC Monitor

<p align="center">
  <strong>Automated Wazuh alert triage, evidence-aware AI analysis, PDF reporting, and email delivery.</strong>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Python-Automation-3776AB?style=for-the-badge&logo=python&logoColor=white" alt="Python automation" />
  <img src="https://img.shields.io/badge/Wazuh-Alert%20Monitoring-00A9E0?style=for-the-badge" alt="Wazuh monitoring" />
  <img src="https://img.shields.io/badge/Ollama-AI%20Analysis-111827?style=for-the-badge" alt="Ollama analysis" />
  <img src="https://img.shields.io/badge/ReportLab-PDF%20Reports-DC2626?style=for-the-badge" alt="PDF reports" />
</p>

> [!WARNING]
> This project handles security telemetry and mail delivery. Keep `.env`, alert databases, logs, and generated PDFs private. They are intentionally excluded from Git.

## Overview

Wazuh AI SOC Monitor is a Python-based security operations workflow for monitoring Wazuh indexer alerts. It records alert metadata in a local SQLite database, evaluates critical alerts with a locally configured Ollama model, creates a PDF SOC report, and delivers the report through SMTP.

The analysis prompt is designed to be evidence-aware: it preserves the original Wazuh rule ID and level, distinguishes confirmed facts from potential risks, and treats alert content as untrusted data.

## Architecture

```text
Wazuh Indexer
     │  (HTTPS / authenticated query)
     ▼
Alert collector ───────────────► SQLite state store
                                      │
                                      ▼
                               Critical alert queue
                                      │
                   ┌──────────────────┼──────────────────┐
                   ▼                  ▼                  ▼
            Wazuh evidence       Ollama analysis     PDF report
                   └──────────────────┴──────────────────┘
                                      │
                                      ▼
                              SMTP email notification
```

## Features

- Polls Wazuh indexer alerts from `wazuh-alerts-4.x-*`.
- Stores alert state locally to avoid duplicate processing.
- Applies configurable collection and critical-alert thresholds.
- Fetches original Wazuh evidence before AI analysis.
- Uses Ollama for structured, evidence-bounded SOC Level 1 analysis.
- Produces styled PDF reports with alert metadata and analysis.
- Sends PDF reports through configurable SMTP delivery.
- Retries failed automation work on a future monitor cycle.
- Marks historical alerts during initial setup to prevent a first-run email flood.

## Project layout

```text
.
├── monitor.py              # Continuous collection and critical-alert workflow
├── ai_analyzer.py          # Wazuh evidence retrieval and Ollama analysis
├── pdf_generator.py        # SOC PDF report generator
├── email_sender.py         # SMTP report delivery
├── database.py             # SQLite initialization helpers
├── collect_new_alerts.py   # Standalone alert collection utility
├── connection_test.py      # Wazuh/Ollama connectivity check
├── fetch_alerts.py         # Wazuh alert query utility
├── test_ai.py              # Ollama API smoke test
├── test_wazuh.py           # Wazuh API smoke test
├── .env.example            # Safe configuration template
└── requirements.txt        # Python dependencies
```

## Quick start

### 1. Clone and create a virtual environment

```powershell
git clone https://github.com/YOUR-USERNAME/YOUR-REPOSITORY.git
cd YOUR-REPOSITORY
python -m venv venv
.\venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

### 2. Configure local settings

Copy the template and fill in values for your own environment. Do not commit the resulting `.env` file.

```powershell
Copy-Item .env.example .env
```

Required settings include:

| Setting | Purpose |
| --- | --- |
| `WAZUH_INDEXER_URL` | Wazuh indexer endpoint |
| `WAZUH_USERNAME` / `WAZUH_PASSWORD` | Wazuh credentials |
| `OLLAMA_URL` / `OLLAMA_MODEL` | Ollama inference endpoint and model |
| `SMTP_*` | SMTP server and port |
| `SENDER_EMAIL` / `SENDER_APP_PASSWORD` | Mail-sending account and app password |
| `ADMIN_EMAIL` | Recipient for generated reports |

### 3. Verify connectivity

Run the supplied checks after configuring `.env`:

```powershell
python connection_test.py
python test_wazuh.py
python test_ai.py
```

### 4. Start the monitor

```powershell
python monitor.py
```

Stop it safely with `Ctrl+C`.

## Workflow

1. `monitor.py` polls Wazuh for alerts at or above `ALERT_LEVEL`.
2. New alert metadata is added to the local `soc_monitor.db` state store.
3. Alerts at or above `CRITICAL_EMAIL_LEVEL` enter the automation workflow.
4. The original alert is retrieved from Wazuh and sent to Ollama for analysis.
5. A PDF report is generated under `reports/`.
6. The report is emailed through the configured SMTP server.
7. The local database records completion or a retryable error.

## Testing and checks

The repository includes lightweight, environment-dependent smoke checks:

```powershell
python connection_test.py
python test_wazuh.py
python test_ai.py
```

These commands require a correctly configured `.env`, a reachable Wazuh indexer, and an available Ollama endpoint. No live credentials, alert data, databases, logs, or generated reports are included in this repository.

## Screenshots

Add sanitized screenshots here before making a public release:

| Monitor workflow | Generated report | Email notification |
| --- | --- | --- |
| `docs/screenshots/monitor.png` | `docs/screenshots/report.png` | `docs/screenshots/email.png` |

Only use redacted images that contain no hostnames, IP addresses, email addresses, alert identifiers, or other sensitive security data.

## Security notes

- `.env`, virtual environments, SQLite files, logs, and PDFs are ignored by Git.
- Use a dedicated least-privilege Wazuh account where possible.
- Rotate any credential that may have been exposed outside your local machine.
- Validate AI output against the original Wazuh evidence before taking remediation action.
- Configure certificate validation for production deployments; the current scripts disable verification for their HTTPS requests.

## Author

Created and maintained by the project owner. Update this section with your preferred name and GitHub profile before publishing.

## License

No license has been selected yet. Add a license before sharing or accepting contributions.
