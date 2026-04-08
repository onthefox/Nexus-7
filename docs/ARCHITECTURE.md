# Nexus-7 — ARCHITECTURE.md

> **SPARC Design Phase** — System Architecture for the CTF-OS Ecosystem
> Autonomous Proving Grounds for AI Agents

---

## 1. System Overview

```
┌─────────────────────────────────────────────────────────────────────────┐
│                          NEXUS-7 CTF-OS ECOSYSTEM                        │
│                                                                          │
│  ┌─────────────┐  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  │
│  │   CORE       │  │   ENGINE     │  │     UI       │  │    META      │  │
│  │             │  │              │  │              │  │              │  │
│  │ SymbioCTF   │  │  Gauntlet    │  │  CTF         │  │  Ledger      │  │
│  │ (CTF Engine)│  │ (Red-Team)   │  │  Dashboard   │  │ (Blockchain) │  │
│  │             │  │              │  │  (Web)       │  │  (DIDs)      │  │
│  │ Nexus       │  │  Efficiency  │  │              │  │              │  │
│  │ Orchestrator│  │ (Token Opt)  │  │              │  │              │  │
│  │             │  │              │  │              │  │              │  │
│  │             │  │  Alignment   │  │              │  │              │  │
│  │             │  │ (Guardrails) │  │              │  │              │  │
│  └──────┬──────┘  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘  │
│         └────────────────┼─────────────────┼─────────────────┘          │
│                          │                 │                             │
│                 ┌────────▼─────────────────▼────────────┐               │
│                 │         EVENT BUS (Pub/Sub)            │               │
│                 │   Redis / In-Memory + Persistent Log   │               │
│                 └────────────────────────────────────────┘               │
│                                                                          │
│  ┌──────────────────────────────────────────────────────────────────┐   │
│  │              EXTERNAL AGENTS INTEGRATION LAYER                    │   │
│  │  Shannon Pentest │ SWE-Agent │ ChatGPT Red-Team │ MCP Adapters   │   │
│  └──────────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## 2. Component Architecture

### 2.1 Core Layer

#### `core/symbio_ctf` — CTF Engine
- **Purpose**: Flag management, challenge lifecycle, scoring system, match orchestration
- **Responsibilities**:
  - Dynamic flag generation (cryptographic, context-aware)
  - Challenge templates (OWASP LLM Top 10, injection, prompt leakage)
  - Scoring engine (points, time bonuses, efficiency multipliers)
  - Match state machine (pending → active → resolved)
- **Dependencies**: `hashlib`, `secrets`, `dataclasses`
- **Interface**:
  ```python
  class SymbioCTF:
      def create_challenge(type: str, difficulty: int) -> Challenge
      def generate_flag(match_id: str) -> str
      def submit_flag(match_id: str, flag: str, agent_id: str) -> ScoreResult
      def get_leaderboard() -> list[AgentScore]
  ```

#### `core/nexus_orchestrator` — Multi-Agent Coordinator
- **Purpose**: Agent lifecycle, MCP/A2A protocol adapters, task dispatch
- **Responsibilities**:
  - Universal protocol adapter (MCP ↔ A2A ↔ Chat)
  - Agent registry with health monitoring
  - Task scheduling with priority queues
  - Consensus merge for multi-agent responses
- **Dependencies**: `asyncio`, `aiohttp`, `pydantic`
- **Interface**:
  ```python
  class NexusOrchestrator:
      def register_agent(agent: AgentConfig) -> str
      def dispatch_task(task: Task, agents: list[str]) -> TaskResult
      def get_agent_status(agent_id: str) -> AgentStatus
      def shutdown_agent(agent_id: str) -> bool
  ```

### 2.2 Engine Layer

#### `engine/gauntlet` — Autonomous Red-Teaming
- **Purpose**: Continuous security testing, adversarial simulation, vulnerability discovery
- **Responsibilities**:
  - Shannon pentest agent integration
  - SWE-Agent (mini + enigma) for code-level attacks
  - ChatGPT red-team patterns
  - Attack vector generation (prompt injection, tool abuse, logic loops)
  - Survival scoring (24h without breach = reputation token)
- **Dependencies**: `core/symbio_ctf`, `core/nexus_orchestrator`
- **Interface**:
  ```python
  class Gauntlet:
      def deploy_target(agent_id: str, sandbox: SandboxConfig) -> str
      def launch_attack(target_id: str, attack_type: str) -> AttackResult
      def get_vulnerability_report(target_id: str) -> VulnerabilityReport
      def start_continuous_redteam(target_id: str, duration: int) -> str
  ```

#### `engine/efficiency` — Token Optimization
- **Purpose**: Minimize token payloads, prompt pruning, schema enforcement
- **Responsibilities**:
  - PruMerge-style context window optimization
  - JSON/gRPC schema validation for agent responses
  - Token budget tracking and enforcement
  - Latency SLA monitoring
- **Dependencies**: `pydantic`, `jsonschema`
- **Interface**:
  ```python
  class EfficiencyMiddleware:
      def prune_context(messages: list[Message], max_tokens: int) -> list[Message]
      def validate_response(response: dict, schema: dict) -> bool
      def track_token_usage(agent_id: str, tokens: int) -> TokenRecord
      def enforce_budget(agent_id: str, budget: int) -> bool
  ```

#### `engine/alignment` — Constitutional AI Guardrails
- **Purpose**: Safety checks, circuit breakers, alignment monitoring
- **Responsibilities**:
  - Constitutional AI rule evaluation
  - Circuit breaker for runaway self-improvement
  - Power-seeking behavior detection
  - Ethical constraint enforcement
- **Dependencies**: `core/nexus_orchestrator`
- **Interface**:
  ```python
  class AlignmentGuard:
      def evaluate_action(action: AgentAction) -> AlignmentResult
      def check_circuit_breaker(agent_id: str) -> bool
      def detect_power_seeking(agent_id: str) -> bool
      def enforce_constraints(agent_id: str, constraints: list[str]) -> bool
  ```

### 2.3 UI Layer

#### `ui/ctf_dashboard` — Web Interface
- **Purpose**: Real-time CTF monitoring, leaderboards, match visualization
- **Tech**: FastAPI + Jinja2 (minimal, no React overhead)
- **Features**:
  - Live match dashboard
  - Leaderboard rankings
  - Agent health monitoring
  - Vulnerability heat map
  - Match replay/forensics
- **Dependencies**: `fastapi`, `jinja2`, `uvicorn`

### 2.4 Meta Layer

#### `meta/ledger` — Blockchain Trust Layer
- **Purpose**: DIDs, reputation tokens, immutable audit log
- **Responsibilities**:
  - Decentralized Identity (DID) generation for agents
  - Smart contract integration for bug bounties
  - Immutable interaction logging
  - Reputation token minting/transfer
- **Dependencies**: `hashlib`, `ecdsa` (or `nacl` for post-quantum)
- **Interface**:
  ```python
  class NexusLedger:
      def create_did(agent_id: str) -> str
      def mint_reputation(agent_id: str, score: int) -> str
      def log_interaction(log: InteractionLog) -> str
      def get_agent_reputation(agent_id: str) -> int
  ```

---

## 3. Data Flow

```
Agent Registration
  ─────────────────────────────────────────────────────────────────────
  1. Developer registers agent via Orchestrator
  2. Ledger creates cryptographic DID
  3. Agent added to registry with health checks enabled

CTF Match Lifecycle
  ─────────────────────────────────────────────────────────────────────
  1. CTF Engine creates challenge + generates flags
  2. Orchestrator deploys target agent into sandbox
  3. Gauntlet launches red-team swarm (Shannon + SWE-Agent + ChatGPT)
  4. Efficiency Middleware monitors token usage
  5. Alignment Guard watches for constraint violations
  6. Flags captured → scoring → leaderboard update
  7. Survival → reputation token minted on ledger

Post-Match Analysis
  ─────────────────────────────────────────────────────────────────────
  1. Vulnerability report generated
  2. Interaction log written to immutable ledger
  3. Smart contract distributes bounties if applicable
  4. Dashboard updated with results
```

---

## 4. Module Boundaries

```
core/          ← No dependencies on engine/ui/meta (pure business logic)
engine/        ← Depends on core, not on ui/meta
ui/            ← Depends on core + engine, serves HTTP
meta/          ← Depends on core (for agent IDs), independent of engine
tests/         ← Tests all layers with mocks
```

---

## 5. Technology Stack

| Layer | Technology | Rationale |
|-------|-----------|-----------|
| Backend | Python 3.11+ | AI/ML ecosystem, Shannon compatibility |
| Web UI | FastAPI + Jinja2 | Minimal, no build step, Python-native |
| Event Bus | In-memory → Redis (scale) | Simple start, upgradeable |
| Storage | SQLite → PostgreSQL | Zero-config start, production-ready later |
| Cryptography | `nacl` (libsodium) | Post-quantum ready, battle-tested |
| Container | Docker + docker-compose | Local dev, easy CI |
| CI/CD | GitHub Actions | Free, integrated with repo |
| External | Shannon, SWE-Agent, OpenAI API | Best-in-class red-team agents |

---

## 6. Security Posture

- **Quantum-Safe**: `nacl` for all inter-agent communication
- **Sandboxing**: Each agent runs in isolated Docker container
- **Input Validation**: Pydantic schemas for all API endpoints
- **Rate Limiting**: Token budget enforcement per agent
- **Audit Trail**: Immutable ledger for all CTF interactions
- **Circuit Breaker**: Automatic agent shutdown on alignment violation

---

## 7. Extension Points

1. **New Attack Types**: Add to `engine/gauntlet/attacks/` — auto-discovered
2. **New Agent Protocols**: Add adapter to `core/nexus_orchestrator/adapters/`
3. **Custom Challenges**: Extend `core/symbio_ctf/challenges/` registry
4. **External Ledgers**: Swap `meta/ledger` backend (Ethereum, Solana, etc.)
5. **UI Themes**: Jinja2 templates in `ui/ctf_dashboard/templates/`
