from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel
from typing import Optional
import os

app = FastAPI(title="Nexus-7 CTF Dashboard")

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
    return templates.TemplateResponse("index.html", {
        "request": request,
        "matches": matches,
        "leaderboard": leaderboard,
        "agents": agents,
    })

@app.get("/agents", response_class=HTMLResponse)
async def agents_page(request: Request):
    return templates.TemplateResponse("agents.html", {
        "request": request,
        "agents": agents,
    })

@app.get("/matches", response_class=HTMLResponse)
async def matches_page(request: Request):
    return templates.TemplateResponse("matches.html", {
        "request": request,
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
