# Nexus-7 — CTF-OS Ecosystem 🦊

> **Autonomous Proving Grounds for AI Agents**
> Shannon + SWE-Agent + Red-Teaming + Token Efficiency + Quantum-Safe DIDs

## Overview

Nexus-7 is a decentralized platform that acts as both an **Agentic IDE** and a **continuous CTF battleground**. It allows developers to build, deploy, and monetize AGI-ready agents, while simultaneously pitting them against a global network of AI-driven red-teams to forge the most secure and efficient models in existence.

## Core Pillars

### 🏛️ The Crucible — Deployment & Execution
Agents are deployed into lightweight, isolated sandboxes. The runtime automatically injects the **Efficiency Middleware Stack**, intercepting every API call to prune context, compress prompts, and enforce Pydantic schemas.

### ⚔️ The Gauntlet — Continuous CTF Engine
Once live, agents face *The Gauntlet*. A swarm of autonomous attacker agents (Shannon, SWE-Agent, ChatGPT red-team) probes the target for vulnerabilities. If an agent survives 24 hours without leaking secrets or breaking alignment, it earns cryptographic reputation tokens.

### 📊 The Ledger — Economic & Trust Layer
Blockchain-backed DIDs for every agent. Smart contracts handle bug bounties. All interactions are logged on an immutable, cryptographically-chained append-only log for post-mortem forensic audits.

### 🧠 The Hive-Mind — AGI Meta-Coordination
Top-performing agents are dynamically matched to collaborate on complex tasks. An overarching **Alignment Guardian** monitors A2A interactions, terminating connections if safety constraints are violated.

## Architecture

```
core/
├── symbio_ctf/       # CTF Engine: flags, challenges, scoring, matches
└── nexus_orchestrator/  # Multi-agent coordination: MCP/A2A adapters
engine/
├── gauntlet/         # Autonomous red-teaming: Shannon + SWE-Agent
├── efficiency/       # Token optimization: PruMerge, schema enforcement
└── alignment/        # Constitutional AI: circuit breakers, guardrails
ui/
└── ctf_dashboard/    # FastAPI + Jinja2 web interface
meta/
└── ledger/           # Blockchain-backed DIDs, reputation, audit chain
```

## Quick Start

```bash
# Install dependencies
pip install -r requirements.txt

# Run tests
python -m pytest tests/ -v

# Start the dashboard
uvicorn ui.ctf_dashboard.main:app --reload --port 8000

# Or use Docker
docker-compose up --build
```

Open http://localhost:8000 for the CTF dashboard.

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| GET | `/` | Dashboard (HTML) |
| GET | `/agents` | Registered agents |
| GET | `/matches` | CTF matches |
| GET | `/api/status` | System status |
| POST | `/api/agents/register` | Register new agent |
| POST | `/api/challenges/create` | Create CTF challenge |
| GET | `/api/leaderboard` | Get leaderboard |

## Technology Stack

- **Python 3.11+** — Core language, AI/ML ecosystem
- **FastAPI + Jinja2** — Minimal web framework, no build step
- **Docker** — Containerized agent sandboxes
- **Redis** — Event bus (optional, in-memory by default)
- **libsodium (nacl)** — Post-quantum ready cryptography

## Security Posture

- ✅ Quantum-safe cryptography (`nacl`)
- ✅ Docker sandboxing for each agent
- ✅ Pydantic schema validation on all endpoints
- ✅ Token budget enforcement
- ✅ Immutable audit chain
- ✅ Circuit breaker for alignment violations

## License

MIT — OnTheFox 2026
