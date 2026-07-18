Quick Start Guide
=================

This guide will help you get started with SymbioCTF quickly.

Basic Usage
-----------

Creating a CTF Match
~~~~~~~~~~~~~~~~~~~~

.. code-block:: python

   from symbio_ctf import CTFEngine, Challenge, Difficulty
   from symbio_ctf.models import Team

   # Initialize the engine
   engine = CTFEngine()

   # Create a match
   match = engine.create_match("Summer CTF 2026")

   # Add challenges
   challenge = engine.add_challenge(
       match_id=match.id,
       name="Buffer Overflow 101",
       description="Exploit the buffer overflow vulnerability",
       category="Pwn",
       difficulty=Difficulty.MEDIUM,
       flag="CTF{buffer_overflow_master}"
   )

   # Create a team
   team = Team(name="HackersUnited")
   engine.register_team(match.id, team)

   # Submit a flag
   result = engine.submit_flag(
       match_id=match.id,
       team_id=team.id,
       challenge_id=challenge.id,
       flag="CTF{buffer_overflow_master}"
   )

   print(f"Flag submission: {result.status}")
   print(f"Score: {result.points_awarded}")

Working with Agents
-------------------

Using Nexus Orchestrator
~~~~~~~~~~~~~~~~~~~~~~~~~

.. code-block:: python

   from nexus_orchestrator import AgentOrchestrator, AgentConfig
   from nexus_orchestrator.models import AgentType

   # Initialize orchestrator
   orchestrator = AgentOrchestrator()

   # Register an agent
   config = AgentConfig(
       name="security-scanner",
       agent_type=AgentType.SCANNER,
       capabilities=["vulnerability_detection", "port_scanning"]
   )

   agent = orchestrator.register_agent(config)

   # Dispatch a task
   task = orchestrator.dispatch_task(
       agent_id=agent.id,
       task_type="scan",
       payload={"target": "192.168.1.1", "ports": [22, 80, 443]}
   )

   # Get task status
   status = orchestrator.get_task_status(task.id)
   print(f"Task status: {status.state}")

Running Examples
----------------

Check the ``examples/`` directory for complete working examples:

.. code-block:: bash

   python examples/01_basic_ctf_match.py

Next Steps
----------

- Read the :doc:`API Reference <api/modules>` for detailed documentation
- Explore the :doc:`Architecture <architecture>` documentation
- Run the test suite to verify your setup
