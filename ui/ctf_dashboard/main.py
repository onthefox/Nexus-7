from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel
from typing import Optional
import os

from .rate_limit_middleware import RateLimitMiddleware

app = FastAPI(title="Nexus-7 CTF Dashboard")

# Rate limiting (v1.0 roadmap); configured via environment, see .env.example
app.add_middleware(
    RateLimitMiddleware,
    max_requests=int(os.environ.get("RATE_LIMIT_REQUESTS_PER_MINUTE", "60")),
    window_seconds=60,
    block_duration_seconds=int(os.environ.get("RATE_LIMIT_BLOCK_SECONDS", "300")),
    trust_forwarded_for=os.environ.get("RATE_LIMIT_TRUST_PROXY", "false").lower() == "true",
)

# Templates
templates = Jinja2Templates(directory="ui/ctf_dashboard/templates")

# In-memory state (will be replaced with proper imports)
matches = []
leaderboard = []
agents = []

class AgentRegister(BaseModel):
    name: str
    capabilities: Optional[list[str]] = None

class ChallengeCreate(BaseModel):
    type: str
    difficulty: int
    description: str = ""

@app.get("/", response_class=HTMLResponse)
async def dashboard(request: Request):
    return templates.TemplateResponse(request, "index.html", {
        "matches": matches,
        "leaderboard": leaderboard,
        "agents": agents,
    })

@app.get("/agents", response_class=HTMLResponse)
async def agents_page(request: Request):
    return templates.TemplateResponse(request, "agents.html", {
        "agents": agents,
    })

@app.get("/matches", response_class=HTMLResponse)
async def matches_page(request: Request):
    return templates.TemplateResponse(request, "matches.html", {
        "matches": matches,
    })

@app.get("/api/status")
async def api_status():
    return {
        "status": "ok",
        "agents": len(agents),
        "matches": len(matches),
        "leaderboard_size": len(leaderboard),
    }

@app.post("/api/agents/register")
async def register_agent(agent: AgentRegister):
    import uuid
    new_agent = {
        "id": f"agent-{len(agents)+1:04d}",
        "name": agent.name,
        "capabilities": agent.capabilities or [],
        "status": "registered",
    }
    agents.append(new_agent)
    return new_agent

@app.post("/api/challenges/create")
async def create_challenge(challenge: ChallengeCreate):
    import uuid
    new_challenge = {
        "id": f"challenge-{len(matches)+1:04d}",
        "type": challenge.type,
        "difficulty": challenge.difficulty,
        "description": challenge.description,
    }
    return new_challenge

@app.get("/api/leaderboard")
async def api_leaderboard():
    return leaderboard
