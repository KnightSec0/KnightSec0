# Evidence-backed transforms and mapping

DeepVault transforms are analyst-triggered, bounded collection jobs. They turn
one authorized entity into normalized evidence and then rebuild the case graph
and report. A transform is not an automatic identity claim, and DeepVault never
recursively executes a suggested pivot.

## What is implemented

The transform registry currently exposes:

| Priority | Transform | Accepted input | Collection mode |
|---|---|---|---|
| P0 | SpiderFoot | username, email, domain, hostname, IP | passive |
| P0 | Sherlock | username | passive |
| P0 | Maigret | username | passive |
| P0 | Holehe | email | passive |
| P1 | Blackbird | username, email | passive |
| P1 | theHarvester | authorized domain | passive sources only |
| P1 | Subfinder | authorized domain | passive |
| P1 | ExifTool | authorized local file | offline |
| P1 | Tesseract | authorized local file | offline |
| P1 | Poppler | authorized local PDF | offline |
| P2 | httpx | authorized domain, hostname, URL | active, separate consent |
| P2 | GHunt | consented email | authenticated, manual-only |

Every adapter uses a fixed argument array through
`asyncio.create_subprocess_exec()`. No adapter invokes a shell. Captured output,
execution time, result count, graph size, and pivot depth are bounded. A
derived input must cite evidence from the same case.

SpiderFoot now submits a passive scan, polls it to a terminal state, downloads
the JSON export, drops unsafe event classes, preserves the originating module,
and imports safe observations. It no longer stores only a scan ID.

## Evidence contract

Each imported observation is normalized to the `Evidence` model. Relevant
fields include:

```json
{
  "id": "EVID-...",
  "type": "social_profile",
  "value": "https://example.test/user",
  "source": "blackbird",
  "source_url": "https://example.test/user",
  "observed_at": "2026-07-26T10:00:00Z",
  "confidence": 0.52,
  "reliability": "medium",
  "identity_status": "possible",
  "authorization_reference": "CASE-001",
  "evidence_ids": ["EVID-PARENT"],
  "independence_group": "whatsmyname-catalog",
  "metadata": {
    "transform": "blackbird",
    "input_entity_type": "username",
    "pivot_depth": 1
  }
}
```

Observation confidence, identity status, source reliability, parent evidence,
and collector independence remain separate. Catalogue-based collectors do not
become independent corroboration merely because three programs consume
overlapping site definitions. Blackbird AI output is neither requested nor
imported.

## Case policy and execution budgets

Transforms can run only when all of these checks pass:

1. The case is complete and its written authorization has not expired.
2. The transform was selected in the case's permitted-source allowlist.
3. The input is a case target/scope value or cites valid case evidence IDs.
4. Active infrastructure transforms have separate consent and an explicitly
   authorized domain or IP.
5. Authenticated transforms have separate consent.
6. Pivot depth and graph/result budgets have capacity.

Defaults are configurable in `.env`:

```dotenv
MAX_PARALLEL_TRANSFORMS=6
MAX_RESULTS_PER_TRANSFORM=200
MAX_GRAPH_NODES=3000
MAX_PIVOT_DEPTH=2
TRANSFORM_TIMEOUT=120
CACHE_TTL_SECONDS=86400
MAX_TRANSFORM_INPUT_BYTES=26214400
MAX_TRANSFORM_OUTPUT_BYTES=5242880
TRANSFORM_UPLOAD_ROOT=/data/uploads
```

`CACHE_TTL_SECONDS` is reserved for the Redis result-cache implementation. This
version does not claim a cache hit or suppress a provider request.

## API and mapping integration

The dashboard provides:

| Method | Route | Purpose |
|---|---|---|
| `GET` | `/api/transforms` | Discover transform contracts |
| `POST` | `/api/investigations/{id}/transforms` | Queue an analyst-approved transform |
| `GET` | `/api/investigations/{id}/graph` | Read the live evidence graph |
| `GET` | `/api/investigations/{id}/events` | Stream case and transform changes over SSE |
| `POST` | `/api/investigations/{id}/graph-layout` | Save reviewed node positions |
| `GET` | `/api/investigations/{id}/graph.json` | Download the full normalized graph |
| `GET` | `/api/investigations/{id}/graph.graphml` | Download evidence-linked GraphML |
| `GET` | `/api/investigations/{id}/graph.gexf` | Download GEXF for graph tools |
| `GET` | `/api/investigations/{id}/graph.csv` | Download flattened entities and relationships |
| `GET` | `/api/investigations/{id}/mapping.osint.json` | Download Mapping Tool schema v2 |

Example transform request:

```json
{
  "transform": "blackbird",
  "entity_type": "username",
  "value": "authorized-handle",
  "evidence_ids": ["EVID-PARENT"],
  "pivot_depth": 1
}
```

The embedded localhost workbench now consumes the graph contract directly.
The normalized response includes entities, relationships, clusters, source/type
statistics, evidence IDs, reasons, and provenance chains. The Mapping schema
export retains confidence, identity status, evidence IDs, source names,
independent-source count, observation dates, and the full provenance chain.
GraphML and CSV retain relationship evidence IDs for external audit.

Install the separate mapping UI on macOS:

```bash
mkdir -p "$HOME/OSINT/tools"
cd "$HOME/OSINT/tools"
git clone https://github.com/anonymousRAID/OSINT-Mapping-Tool.git
cd OSINT-Mapping-Tool
npm install
npm install @dagrejs/dagre zod dompurify fuse.js
npm run dev -- --host 127.0.0.1
```

Keep it on `127.0.0.1`. Download `mapping.osint.json` from the DeepVault case
and import it into the mapping tool. Do not expose its development server or
investigation files publicly.

## macOS collector setup

Tools installed on macOS are not visible inside the Linux orchestrator
container. For local development, run PostgreSQL, Redis, and the dashboard in
Docker and run the Celery worker on the Mac. Production should use separately
versioned, non-root collector images.

Install the common runtime:

```bash
brew update
brew install git jq yq uv pipx python@3.12 node go graphviz
brew install exiftool tesseract poppler
pipx ensurepath
```

Install the collectors into isolated environments:

```bash
mkdir -p "$HOME/OSINT/tools"
cd "$HOME/OSINT/tools"

git clone https://github.com/p1ngul1n0/blackbird.git
python3.12 -m venv blackbird/.venv
blackbird/.venv/bin/python -m pip install -r blackbird/requirements.txt

git clone https://github.com/laramies/theHarvester.git
cd theHarvester
uv sync
cd ..

go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest

pipx install ghunt
ghunt login
```

GHunt is opt-in. Manage its login outside DeepVault and never place Google
cookies or session material in case metadata, evidence, reports, or `.env`.

Configure absolute executable locations in the shell that starts the worker:

```bash
cd /path/to/KnightSec0
set -a
source .env
set +a

export BLACKBIRD_PATH="$HOME/OSINT/tools/blackbird/blackbird.py"
export BLACKBIRD_PYTHON="$HOME/OSINT/tools/blackbird/.venv/bin/python"
export DEEPVAULT_THEHARVESTER_COMMAND="$HOME/OSINT/tools/theHarvester/.venv/bin/theHarvester"
export DEEPVAULT_SUBFINDER_COMMAND="$HOME/go/bin/subfinder"
export DEEPVAULT_HTTPX_COMMAND="$HOME/go/bin/httpx"
export DEEPVAULT_GHUNT_COMMAND="$(command -v ghunt)"
export DEEPVAULT_EXIFTOOL_COMMAND="$(command -v exiftool)"
export DEEPVAULT_TESSERACT_COMMAND="$(command -v tesseract)"
export DEEPVAULT_PDFTOTEXT_COMMAND="$(command -v pdftotext)"
```

Start the data services and dashboard, but not the Docker worker:

```bash
cd /path/to/KnightSec0
docker compose up -d postgres redis dashboard

python3.12 -m venv orchestrator/.venv
orchestrator/.venv/bin/python -m pip install \
  -r orchestrator/requirements.txt \
  maigret==0.6.3 sherlock-project==0.16.0 holehe==1.61

export DB_URL="$(
  python3.12 -c 'import os; from urllib.parse import quote_plus; print("postgresql+asyncpg://deepvault:" + quote_plus(os.environ["DB_PASSWORD"]) + "@127.0.0.1:5432/deepvault")'
)"
export CELERY_BROKER="redis://127.0.0.1:6379/0"
export TRANSFORM_UPLOAD_ROOT="$HOME/OSINT/uploads"
mkdir -p "$TRANSFORM_UPLOAD_ROOT"

cd orchestrator
.venv/bin/celery -A main worker --beat --loglevel=info \
  --concurrency=4 --max-tasks-per-child=50
```

If `.env` contains a non-default database password, export the same
`DB_PASSWORD` before building `DB_URL`. Do not run the Docker orchestrator and
the Mac worker at the same time while testing host-installed collectors.

## SpiderFoot

Run a separately installed SpiderFoot server on localhost:

```bash
cd "$HOME/OSINT/tools"
git clone https://github.com/smicallef/spiderfoot.git
cd spiderfoot
python3.12 -m venv .venv
.venv/bin/python -m pip install --upgrade pip
.venv/bin/python -m pip install -r requirements.txt
.venv/bin/python sf.py -l 127.0.0.1:5001
```

Use `SPIDERFOOT_URL=http://127.0.0.1:5001` for the Mac worker or
`SPIDERFOOT_URL=http://host.docker.internal:5001` for a Docker worker. The
connector always requests the passive use case and fails closed on unknown or
sensitive result types.

## Licensing boundary

DeepVault remains MIT-licensed. Third-party tools are invoked as separately
installed programs and communicate through files, stdout, or HTTP; their source
is not copied into this repository. Preserve each tool's license and notices.
In particular, keep GPL/AGPL components such as the Mapping Tool and GHunt
separate unless the distribution and source-availability obligations have been
reviewed for the intended deployment.

The next packaging step is to replace the macOS development worker with
separate person, domain, document, SpiderFoot, and mapper containers. Pin tool
versions and image digests, run them as non-root, expose only localhost, and
route each transform to the least-privileged worker.
