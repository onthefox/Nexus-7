"""
Tests for meta/ledger chain tampering detection (issue #3).

Covers the NexusLedger cryptographic audit chain:
- verify_chain() accepts an intact chain
- value tampering on any entry is detected
- entry deletion (middle) and tail truncation are detected
- entry reordering is detected
- post-tamper writes do not "heal" the chain
Plus basic DID / reputation behavior used by the chain scenario.
"""

import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from meta.ledger import NexusLedger


def build_ledger(entries: int = 4) -> NexusLedger:
    ledger = NexusLedger()
    for i in range(1, entries + 1):
        ledger.log_interaction(
            source_agent=f"agent-{i}",
            target_agent="match-engine",
            action=f"action-{i}",
            result=f"result-{i}",
            metadata=None,
        )
    return ledger


class TestChainIntegrity:
    def test_fresh_chain_is_valid(self):
        ledger = NexusLedger()
        assert ledger.verify_chain() is True
        assert ledger.get_chain_hash() == "0" * 64

    def test_chain_valid_after_multiple_entries(self):
        ledger = build_ledger(6)
        assert ledger.verify_chain() is True
        assert len(ledger.get_logs()) == 6

    def test_chain_hash_matches_last_entry_hash(self):
        ledger = build_ledger(3)
        logs = ledger.get_logs()
        assert ledger.get_chain_hash() == logs[-1].hash

    def test_entries_are_sequentially_numbered(self):
        ledger = build_ledger(3)
        assert [log.id for log in ledger.get_logs()] == [
            "log-000001",
            "log-000002",
            "log-000003",
        ]

    def test_each_hash_depends_on_previous_entry(self):
        ledger = build_ledger(2)
        first, second = ledger.get_logs()
        assert first.hash != second.hash
        assert ledger.get_chain_hash() == second.hash


class TestValueTamperingDetection:
    def test_tampered_middle_entry_detected(self):
        ledger = build_ledger(4)
        middle = ledger.get_logs()[1]
        middle.action = "forged-action"
        assert ledger.verify_chain() is False

    def test_tampered_first_entry_detected(self):
        ledger = build_ledger(4)
        first = ledger.get_logs()[0]
        first.source_agent = "attacker"
        assert ledger.verify_chain() is False

    def test_tampered_last_entry_detected(self):
        ledger = build_ledger(4)
        last = ledger.get_logs()[-1]
        last.result = "forged-result"
        assert ledger.verify_chain() is False

    def test_single_character_tampering_detected(self):
        ledger = build_ledger(2)
        second = ledger.get_logs()[1]
        second.target_agent = "match-engerine"  # one char changed
        assert ledger.verify_chain() is False

    def test_tampering_does_not_heal_after_new_writes(self):
        ledger = build_ledger(3)
        ledger.get_logs()[0].action = "forged"
        # A tampered history stays detectable even as the chain keeps growing
        ledger.log_interaction("agent-x", "agent-y", "new-action", "ok")
        assert ledger.verify_chain() is False
        assert len(ledger.get_logs()) == 4


class TestStructuralTamperingDetection:
    def test_middle_entry_deletion_detected(self):
        ledger = build_ledger(4)
        del ledger._logs[1]  # remove log-000002
        assert ledger.verify_chain() is False

    def test_tail_truncation_detected(self):
        ledger = build_ledger(4)
        del ledger._logs[-1]  # silently drop the newest entry
        assert ledger.verify_chain() is False

    def test_truncate_all_entries_detected(self):
        ledger = build_ledger(3)
        ledger._logs.clear()
        assert ledger.verify_chain() is False

    def test_entry_reordering_detected(self):
        ledger = build_ledger(3)
        ledger._logs[0], ledger._logs[1] = ledger._logs[1], ledger._logs[0]
        assert ledger.verify_chain() is False

    def test_replaced_chain_hash_detected(self):
        ledger = build_ledger(2)
        ledger._chain_hash = "f" * 64
        assert ledger.verify_chain() is False


class TestLedgerQueriesAfterTampering:
    def test_get_logs_returns_live_objects(self):
        """get_logs exposes the same objects stored in the chain (audit view)."""
        ledger = build_ledger(2)
        (log,) = ledger.get_logs(agent_id="agent-1")
        log.action = "audited"
        assert ledger.verify_chain() is False

    def test_get_logs_filter_and_limit(self):
        ledger = build_ledger(4)
        agent_two = ledger.get_logs(agent_id="agent-2")
        assert [log.id for log in agent_two] == ["log-000002"]
        limited = ledger.get_logs(limit=2)
        assert [log.id for log in limited] == ["log-000003", "log-000004"]

    def test_get_stats_reflects_chain_state(self):
        ledger = build_ledger(2)
        stats = ledger.get_stats()
        assert stats["log_entries"] == 2
        assert stats["dids"] == 0
        assert stats["chain_hash"] != ""

    def test_reset_restores_genesis_state(self):
        ledger = build_ledger(3)
        ledger.reset()
        assert ledger.verify_chain() is True
        assert ledger.get_chain_hash() == "0" * 64
        assert ledger.get_logs() == []


class TestLedgerIdentityAndReputation:
    def test_did_creation_and_verification(self):
        ledger = NexusLedger()
        did = ledger.create_did("agent-1")
        assert did.did.startswith("did:nexus7:")
        assert ledger.verify_did("agent-1", did.did) is True
        assert ledger.verify_did("agent-1", "did:nexus7:fake") is False
        assert ledger.verify_did("unknown", did.did) is False

    def test_did_is_stable_per_agent(self):
        ledger = NexusLedger()
        first = ledger.create_did("agent-1")
        assert ledger.get_did("agent-1") == first

    def test_reputation_accumulates(self):
        ledger = NexusLedger()
        ledger.mint_reputation("agent-1", 40)
        ledger.mint_reputation("agent-1", 60)
        assert ledger.get_agent_reputation("agent-1") == 100
        assert len(ledger.get_reputation_history("agent-1")) == 2

    def test_mint_reputation_creates_did_automatically(self):
        ledger = NexusLedger()
        ledger.mint_reputation("fresh-agent", 10)
        assert ledger.get_did("fresh-agent") is not None
