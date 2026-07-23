# 🕵️ DeepVault — The OSINT Investigation Framework

**DeepVault** is a locally deployed, Docker-orchestrated open-source
intelligence (OSINT) platform for authorized investigations of individuals. It
collects and correlates public-profile, person-search, breach-metadata, and
authorized infrastructure evidence in a single auditable pipeline.

> ⚠️ **This tool is for authorized security professionals conducting lawful investigations only.** Authorization is your responsibility. DeepVault provides the engine; you provide the legal mandate.

---

## 🚀 Quick Start

```bash
# Requirements: Docker, Docker Compose, Git
git clone https://github.com/KnightSec0/KnightSec0.git
cd KnightSec0
cp .env.example .env
# Add optional API keys to .env, then start the local stack
docker compose up --build
```

Open **http://127.0.0.1:8080** in your browser. The dashboard is bound to the
local machine: it is not a public hosting service. Create a case only after
entering a lawful purpose, written authorization reference, future
authorization expiry, explicit source allowlist, and a username or email.
The default Compose stack starts only PostgreSQL, Redis, the worker, and the
dashboard. Unused legacy data/proxy services are isolated behind the optional
`legacy` Compose profile and are not required for person reports.

The case view polls the local API for live stage progress, source status, and
safe evidence summaries. When processing is complete, use **Download JSON** for
machine-readable evidence or **Download HTML** for a portable, printable
report. The HTML report can be saved as PDF from the browser's print dialog.
Both downloads include a redacted evidence appendix so every cited evidence ID
can be audited against its source, observation, confidence, and metadata.

For a first run, select only the keyless public connectors: GitHub, Sherlock,
Maigret, and Holehe. API-backed sources can be enabled later through `.env`.
Never paste API keys, passwords, cookies, tokens, private messages, or leaked
credentials into the dashboard.

## 📋 Features

| Layer | Capability | Tools Integrated |
|-------|-----------|------------------|
| Public profiles | Public account metadata and person-search results | GitHub, Brave Search |
| Identity enrichment | Email verification and public registration signals | Hunter, Holehe |
| Social media | Username-based public-profile discovery | Sherlock, Maigret |
| Data Breaches | Breach names, dates and exposed data classes (no credentials) | HIBP |
| Passive scanning | Results from an authorized SpiderFoot server | SpiderFoot |
| Infrastructure | Explicitly authorized literal-IP enrichment | Shodan, Censys |
| Correlation | Provenance normalization, identity confidence and contradiction detection | Local correlation engine |
| Reporting | Evidence-linked findings, timeline, contradictions and source coverage | Downloadable JSON and printable HTML |
| LLM analysis | Optional single-provider or consensus synthesis | OpenAI, Anthropic, Gemini, Ollama, OpenAI-compatible APIs |

## 🏗 Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                     DEEPVAULT ORCHESTRATOR (Celery + Python)         │
│  ┌────────────┐  ┌───────────┐  ┌──────────┐  ┌──────────────────┐ │
│  │ Surface    │  │ Identity  │  │ Deep Web │  │ Dark Web / Tor   │ │
│  │ Recon Layer│  │ Correlation│  │ Layer    │  │ Layer            │ │
│  └─────┬──────┘  └─────┬─────┘  └────┬─────┘  └────────┬─────────┘ │
└────────┼───────────────┼──────────────┼──────────────────┼──────────┘
         ▼               ▼              ▼                  ▼
   ┌──────────────────────────────────────────────────────────────────┐
   │                    DATA LAKE & CORRELATION ENGINE                 │
   │  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌─────────────────┐ │
   │  │ PostgreSQL│  │ Neo4j    │  │ Elastic  │  │ MinIO (S3)     │ │
   │  │ Raw Data  │  │ Relation │  │ Search   │  │ Screenshots/   │ │
   │  │ Store     │  │ Graph    │  │ Index    │  │ Artifacts      │ │
   │  └──────────┘  └──────────┘  └──────────┘  └─────────────────┘ │
   └──────────────────────────────────────────────────────────────────┘
         ▼
   ┌──────────────────────────────────────────────────────────────────┐
   │                    LOCAL WEB DASHBOARD (FastAPI)                  │
   │  - Create investigation / enter identifiers                      │
   │  - Live stage progress                                            │
   │  - Evidence-linked findings and source coverage                  │
   │  - Downloadable JSON and printable HTML reports                  │
   └──────────────────────────────────────────────────────────────────┘
```

## 🧩 Modules Deep Dive

### 1. Identity Investigator (orchestrator/investigators/identity.py)
- Generates deterministic email and username candidates from a supplied name
- Uses only the sources allowed by the case policy
- Leaves every unverified candidate clearly marked as a lead

### 2. Social Media Investigator (orchestrator/investigators/social.py)
- Executes Sherlock and Maigret for supplied usernames
- Normalizes public-profile results into evidence records
- Treats a username match as a possible identity until corroborated

### 3. Breach Investigator (orchestrator/investigators/breach.py)
- Checks Have I Been Pwned for breach metadata
- Retains breach names, dates and data classes, never passwords or hashes
- Treats breach association as an exposure signal, not proof of account ownership

### 4. Dark Web Investigator (orchestrator/investigators/darkweb.py)
- Legacy opt-in module for Ahmia's public search endpoint and public paste checks
- Not enabled for source-scoped dashboard cases
- Does not claim to crawl hidden services or private forums

### 5. Correlation Engine (orchestrator/intelligence/correlation.py)
- Normalizes and de-duplicates evidence from independent sources
- Raises confidence only when multiple sources corroborate the same observation
- Preserves provenance, reliability, identity status, and evidence IDs

### 6. Structured Reporting Engine (orchestrator/reporting/person_report.py)
- Produces evidence-linked findings with an executive summary and risk level
- Includes timeline, contradictions, source coverage, limitations, and recommendations
- Exposes machine-readable JSON plus standalone HTML that can be printed to PDF

## 🔧 Configuration

Copy `.env.example` to `.env`. The following person-intelligence sources can be
used without a paid API subscription when their local command-line tools are
installed in the worker image:

- GitHub public profiles (a `GITHUB_TOKEN` is optional for higher rate limits)
- Sherlock public username discovery
- Maigret public username discovery
- Holehe public service-registration signals

The following connectors require their own service or API configuration:

- HIBP: `HIBP_API_KEY`
- Hunter: `HUNTER_API_KEY`
- Brave Search: `BRAVE_API_KEY`
- SpiderFoot: `SPIDERFOOT_URL`
- Shodan: `SHODAN_API_KEY`
- Censys: `CENSYS_API_ID` and `CENSYS_API_SECRET`

Shodan and Censys are restricted to literal IP addresses already included in
the written authorization scope; they are not person-search sources. Missing
keys are handled as unavailable sources rather than fabricated results.

Secrets belong only in the local `.env` file or a secrets manager. Do not enter
them in target, purpose, authorization, or context fields: those fields can be
persisted and included in reports.

## 📖 Usage Guide

### Local dashboard workflow

1. Visit **http://127.0.0.1:8080**.
2. Enter the authorized person's name and at least one known username or email.
3. Record the lawful purpose, authorization reference, and a future expiry.
4. Select only sources covered by that authorization and confirm consent.
5. Start the case and keep the page open to see live progress updates.
6. Review evidence citations, limitations, contradictions, timeline, and source
   coverage before accepting any identity match.
7. Download the completed report as JSON or HTML.

The dashboard refreshes case state every few seconds; refreshing the browser
does not stop the worker. A report is made available only after a structured
report has been stored. Every report claim must cite one or more valid evidence
IDs.

Use your own identifiers for the first test, for example with an authorization
reference such as `SELF-TEST-001`. A name match or username match alone does
not establish identity.

## 📁 Repository Structure

```
deepvault/
├── docker-compose.yml           # All services orchestrated
├── docker-compose.override.yml  # OpSec overrides (optional)
├── .env.example                 # API keys template
├── .gitignore
├── LICENSE                      # MIT License
├── README.md
├── CONTRIBUTING.md
├── SECURITY.md
├── CODE_OF_CONDUCT.md
├── .github/
│   └── workflows/               # CI/CD pipelines
├── docs/                        # Full documentation
│   ├── ARCHITECTURE.md
│   ├── API.md
│   ├── SETUP.md
│   ├── INVESTIGATION_WORKFLOW.md
│   ├── DARK_WEB_OPREC.md
│   └── LEGAL.md
├── orchestrator/                # Core Python application
│   ├── main.py                  # Celery entrypoint
│   ├── config.py                # Settings & secrets
│   ├── db/                      # Data models
│   ├── investigators/           # Investigation modules
│   ├── correlator/              # Graph & correlation
│   └── reporting/               # Evidence-linked report generation
├── dashboard/                   # Local FastAPI dashboard
│   ├── app.py                   # API server and report downloads
│   ├── static/index.html        # Live local browser interface
│   └── Dockerfile
└── tests/                       # Test suite
```

## ⚙️ Requirements

- Docker 24+ & Docker Compose 2.24+
- 8 GB RAM minimum (16 GB recommended for full stack)
- API keys for paid services (optional, degrades gracefully)

### Without Docker (bare metal)

```bash
pip install -r orchestrator/requirements.txt
pip install -r dashboard/requirements.txt
pip install sherlock-project maigret holehe
# Install PostgreSQL 16, Neo4j 5, Elasticsearch 8, Redis 7, MinIO
```

## 🛡 Operational Security

| Risk | Mitigation |
|------|------------|
| Network exposure | Dashboard and data services bind to localhost by default |
| Provider traffic | API and CLI connectors contact their named public providers directly |
| Data at rest | Use host-level disk encryption and define a retention policy for Docker volumes |
| API key exposure | Keys in .env only, never in code |
| Browser caching | Dashboard responses use `no-store` and restrictive security headers |

## 🔒 Legal & Ethical Use

DeepVault is designed for authorized security assessments, background checks with consent, and lawful investigations only. By using this software you agree to:

- Obtain explicit written authorization before investigating any target
- Comply with all applicable laws (GDPR, CFAA, DPA, etc.)
- Maintain chain of custody for all collected evidence
- Respect platform Terms of Service during data collection
- Not use this tool for stalking, harassment, or any unlawful purpose

See LEGAL.md for a comprehensive legal framework.

## 🤝 Contributing

See CONTRIBUTING.md for guidelines. We welcome:

- Additional investigator modules
- New data source integrations
- Dashboard UI improvements
- Documentation & translation

## 📄 License

MIT License — see LICENSE for full text.

## ⭐ Support

- **Issues**: GitHub Issues for bugs and feature requests
- **Discussions**: GitHub Discussions for questions and workflow help
- **Documentation**: Full docs in the /docs directory
