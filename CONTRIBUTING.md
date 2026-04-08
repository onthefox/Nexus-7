# Contributing to Nexus-7

Thank you for your interest in contributing to Nexus-7 — the CTF-OS Ecosystem for AI agents!

## Getting Started

1. Fork the repository
2. Create a feature branch: `git checkout -b feat/my-feature`
3. Make your changes
4. Run tests: `python -m pytest tests/ -v`
5. Commit with a descriptive message
6. Push and open a Pull Request

## Code Standards

- **Python 3.11+** — Use modern type hints and features
- **Type hints** — All public functions and methods must be typed
- **Docstrings** — Document all public classes and methods
- **Line length** — 100 characters max
- **Imports** — Standard library first, then third-party, then local

## Testing

- All new code must have corresponding tests
- Run the full test suite before submitting: `python -m pytest tests/ -v`
- Aim for ≥80% test coverage
- Tests live in `tests/`

## Pull Request Guidelines

- Use descriptive titles: `feat: add X`, `fix: resolve Y`, `docs: update Z`
- Include a description of what changed and why
- Link any related issues
- Ensure CI passes (tests + Docker build)

## Commit Convention

We follow [Conventional Commits](https://www.conventionalcommits.org/):

```
feat: add new capability
fix: resolve a bug
docs: update documentation
refactor: restructure code without changing behavior
test: add or update tests
ci: update CI/CD configuration
chore: maintenance tasks
```

## Architecture

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for the full system design.

Key principles:
- **Core** depends on nothing outside itself
- **Engine** depends on Core, not on UI or Meta
- **UI** depends on Core and Engine
- **Meta** depends on Core, independent of Engine

## Security

- Never commit secrets or API keys
- Use environment variables for configuration
- All inputs must be validated (Pydantic schemas)
- Report security vulnerabilities privately

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
