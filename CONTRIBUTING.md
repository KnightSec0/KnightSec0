# Contributing to DeepVault

## Getting Started

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/amazing-module`
3. Install pre-commit hooks: `pre-commit install`
4. Make your changes
5. Run tests: `pytest tests/`
6. Submit a Pull Request

## Development Setup

```bash
# Clone your fork
git clone https://github.com/YOUR_USERNAME/deepvault.git
cd deepvault

# Create Python virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dev dependencies
pip install -r orchestrator/requirements.txt -r dashboard/requirements.txt
pip install pytest pytest-asyncio black flake8 mypy pre-commit

# Start only the infrastructure (no orchestrator)
docker compose up -d postgres neo4j elasticsearch redis minio tor-proxy
```

## Adding a New Investigator Module

1. Create `orchestrator/investigators/your_module.py`
2. Follow the pattern:

```python
class YourInvestigator:
    """Discover XYZ information about a target."""
    
    def __init__(self):
        self.name = "your_module"
    
    async def run(self, target_data: dict) -> list[dict]:
        # Your logic here
        return artifacts
```

3. Register the module in `orchestrator/main.py` task list
4. Add tests in `tests/test_your_module.py`
5. Update docs in `docs/`

## Code Style

- Type hints required on all functions
- Async-first for I/O-bound operations
- Docstrings on all public methods (Google style)
- Maximum line length: 100 characters
- Use `black` for formatting, `flake8` for linting

## Commit Messages

```
type(scope): brief description

- bullet point details
- reference issues with #123
```

Types: `feat`, `fix`, `docs`, `refactor`, `test`, `chore`
