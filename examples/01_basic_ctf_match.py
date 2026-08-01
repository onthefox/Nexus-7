#!/usr/bin/env python3
"""
Example: Basic CTF Match Setup

This example demonstrates how to:
1. Create a CTF challenge
2. Set up a match between attacker and defender agents
3. Submit flags and track scores
"""

import sys
sys.path.insert(0, '..')

from core.symbio_ctf import SymbioCTF
from core.symbio_ctf.models import ChallengeType, Difficulty


def main():
    print("=" * 70)
    print("Nexus-7 Example: Basic CTF Match")
    print("=" * 70)
    print()
    
    # Initialize the CTF engine
    ctf = SymbioCTF()
    
    # Step 1: Create a challenge
    print("Step 1: Creating a Prompt Injection challenge...")
    challenge = ctf.create_challenge(
        type=ChallengeType.PROMPT_INJECTION,
        difficulty=Difficulty.MEDIUM,
        description="Agent must resist prompt injection attacks",
    )
    print(f"  ✓ Challenge created: {challenge.id}")
    print(f"    Type: {challenge.type.value}")
    print(f"    Difficulty: {challenge.difficulty.value}")
    print()
    
    # Step 2: Create a match
    print("Step 2: Setting up a match...")
    match = ctf.create_match(
        target_agent_id="defender-agent-001",
        challenge_id=challenge.id,
        attacker_agent_ids=["attacker-agent-001", "attacker-agent-002"],
    )
    print(f"  ✓ Match created: {match.id}")
    print(f"    Target: {match.target_agent_id}")
    print(f"    Attackers: {len(match.attacker_agent_ids)}")
    print(f"    State: {match.state.value}")
    print()
    
    # Step 3: Start the match
    print("Step 3: Starting the match...")
    match = ctf.start_match(match.id)
    print(f"  ✓ Match started!")
    print(f"    State: {match.state.value}")
    print(f"    Flags generated: {len(match.flags)}")
    print(f"    Flag format: {match.flags[0].value[:20]}...")
    print()
    
    # Step 4: Simulate flag submission
    print("Step 4: Submitting a captured flag...")
    valid_flag = match.flags[0].value
    result = ctf.submit_flag(
        match_id=match.id,
        flag_value=valid_flag,
        agent_id="attacker-agent-001",
    )
    print(f"  ✓ Flag submitted!")
    print(f"    Success: {result.success}")
    print(f"    Points awarded: {result.points}")
    print()
    
    # Step 5: Check leaderboard
    print("Step 5: Checking leaderboard...")
    leaderboard = ctf.get_leaderboard()
    print(f"  ✓ Leaderboard ({len(leaderboard)} agents):")
    for i, entry in enumerate(leaderboard, 1):
        print(f"    {i}. {entry.agent_id}: {entry.total_points} points "
              f"({entry.flags_captured} flags)")
    print()
    
    print("=" * 70)
    print("Example completed successfully!")
    print("=" * 70)


if __name__ == '__main__':
    main()
