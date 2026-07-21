# 🕵️ DeepVault — The OSINT Investigation Framework

**DeepVault** is a locally-deployed, Docker-orchestrated open-source intelligence (OSINT) platform designed for **deep-dive background investigations** on individuals. It automates the collection, correlation, and reporting of digital artifacts across the surface web, deep web, data breaches, and the Tor dark web — all within a single, auditable pipeline.

> ⚠️ **This tool is for authorized security professionals conducting lawful investigations only.** Authorization is your responsibility. DeepVault provides the engine; you provide the legal mandate.

---

## 🚀 Quick Start

```bash
# Requirements: Docker, Docker Compose, Git
git clone https://github.com/KnightSec0/KnightSec0.git
cd KnightSec0
cp .env.example .env
# Edit .env with your API keys
docker compose up -d --build

# Queue your first investigation
curl -X POST http://localhost:8080/api/investigations \
  -H "Content-Type: application/json" \
  -d '{"target_name": "Jane Smith", "target_email": "jane@example.com", "depth": "full"}'

# Open the dashboard
open http://localhost:8080
```

## 📋 Features

| Layer | Capability | Tools Integrated |
|-------|-----------|------------------|
| Surface Web | Email/Domain harvesting, public documents | theHarvester, Recon-ng, Brave/Bing APIs |
| Identity Expansion | Name → email/phone/address permutations | Hunter.io, social-analyzer, holehe, custom dorking |
| Social Media | Profile discovery across 400+ platforms | Sherlock, Maigret, WhatsMyName |
| Data Breaches | Credential exposure, stealer logs, paste sites | HIBP, DeHashed, IntelX |
| Dark Web | Tor hidden service crawling, .onion mentions | TorBot, Ahmia, OnionScan |
| Geolocation | IP history, Wi-Fi networks, physical addresses | Shodan, ipinfo.io, WiGLE |
| Crypto | Bitcoin/Ethereum wallet discovery | Blockchain explorers, WalletExplorer |
| Correlation | Knowledge graph linking all artifacts | Neo4j graph database |
| Reporting | PDF dossier with risk scoring, timeline, evidence | WeasyPrint, Jinja2 |
| Visualization | Interactive graph explorer, timeline view | Neo4j Browser + custom D3.js |

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
   │                      WEB DASHBOARD (FastAPI + React)              │
   │  - Create investigation / enter identifiers                      │
   │  - Live progress / logs                                          │
   │  - Interactive graph explorer                                    │
   │  - Automated dossier generation (PDF)                            │
   │  - Timeline view (historical artifact correlation)               │
   └──────────────────────────────────────────────────────────────────┘
```

## 🧩 Modules Deep Dive

### 1. Identity Investigator (orchestrator/investigators/identity.py)
- Takes a name and generates 50+ email username permutations
- Searches Hunter.io, Google dorks, and public people-search APIs
- Returns associated emails, phones, addresses, and potential usernames

### 2. Social Media Investigator (orchestrator/investigators/social.py)
- Executes Sherlock, Maigret, and WhatsMyName in parallel
- Discovers profiles on 400+ platforms from a single username
- Automatically pivots: every new username found gets re-scanned

### 3. Breach Investigator (orchestrator/investigators/breach.py)
- Checks Have I Been Pwned, DeHashed, and Intelligence X
- Reveals exposed passwords, credential pairs, and sensitive data classes
- Cross-references email, username, and phone across all breach databases

### 4. Dark Web Investigator (orchestrator/investigators/darkweb.py)
- Routes all traffic through Tor SOCKS5 proxy
- Searches Ahmia (.onion search engine) for target mentions
- Crawls dark web paste sites and forums via TorBot

### 5. Correlation Engine (orchestrator/correlator/graph_builder.py)
- Builds a Neo4j knowledge graph linking every artifact to the target
- Creates relationship chains: email → breach → password → other accounts
- Confidence-scored connections with source provenance

### 6. Reporting Engine (orchestrator/reporting/pdf_generator.py)
- Generates professional PDF dossiers with executive summary
- Risk scoring based on breach severity, dark web exposure, and data sensitivity
- Complete artifact timeline and evidence chain

## 🔧 Configuration

Copy `.env.example` to `.env` and populate API keys:

```bash
# Required for breach detection
INTELX_API_KEY=your_key        # intelx.io
DEHASHED_API_KEY=your_key      # dehashed.com  
DEHASHED_API_LOGIN=your_email

# Strongly recommended
HIBP_API_KEY=your_key          # haveibeenpwned.com
HUNTER_API_KEY=your_key        # hunter.io (email discovery)
SHODAN_API_KEY=your_key        # shodan.io (IP/device recon)
BRAVE_API_KEY=your_key         # brave.com/search (web search)

# Optional but powerful
SOCIALLINKS_API_KEY=your_key   # sociallinks.io (dark + social)
```

## 📖 Usage Guide

### Creating an Investigation

```bash
# Minimal — just a name
curl -X POST http://localhost:8080/api/investigations \
  -d '{"target_name": "John Doe"}'

# Full surface
curl -X POST http://localhost:8080/api/investigations \
  -d '{
    "target_name": "Jane Smith",
    "target_aliases": ["Jane Doe", "Janet Smith"],
    "target_username": "janesmith92",
    "target_email": "jane.smith@example.com",
    "target_phone": "+1-555-0123",
    "depth": "full"
  }'
```

### Retrieving Results

```bash
# Get investigation status
curl http://localhost:8080/api/investigations/{id}

# Download PDF dossier
curl -o dossier.pdf http://localhost:8080/api/investigations/{id}/report

# Export raw artifacts as JSON
curl http://localhost:8080/api/investigations/{id}/artifacts > artifacts.json

# Get knowledge graph data (Neo4j JSON)
curl http://localhost:8080/api/investigations/{id}/graph > graph.json
```

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
│   └── reporting/               # PDF generation
├── dashboard/                   # FastAPI web frontend
│   ├── app/
│   │   ├── main.py             # API server
│   │   └── routes/             # API endpoints
│   └── templates/
├── workers/                     # Specialized service workers
│   ├── tor_worker/              # Tor proxy + controller
│   └── screenshot_worker/       # Playwright screenshots
├── scripts/                     # Utility scripts
└── tests/                       # Test suite
```

## ⚙️ Requirements

- Docker 24+ & Docker Compose 2.24+
- 8 GB RAM minimum (16 GB recommended for full stack)
- Tor (bundled in the tor_worker container)
- API keys for paid services (optional, degrades gracefully)

### Without Docker (bare metal)

```bash
pip install -r orchestrator/requirements.txt
pip install -r dashboard/requirements.txt
./scripts/seed_tools.sh
# Install PostgreSQL 16, Neo4j 5, Elasticsearch 8, Redis 7, MinIO
```

## 🛡 Operational Security

| Risk | Mitigation |
|------|------------|
| IP leakage | All outbound traffic via Tor SOCKS5 |
| DNS leaks | Tor worker on isolated network namespace |
| Data at rest | LUKS-encrypted Docker volumes |
| API key exposure | Keys in .env only, never in code |
| Tool fingerprinting | Randomized User-Agents, request throttling |

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
