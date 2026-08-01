"""
Tests for input validation and sanitization added to core/symbio_ctf.

Covers:
- validate_flag_format() and sanitize_input() helpers in models.py
- __post_init__ validation on Challenge, Flag, and Match dataclasses
- New validation/exception behavior in engine.py (create_challenge,
  create_match, submit_flag) and the CTFError exception hierarchy
- Rate limiter configuration wiring in SymbioCTF.__init__
"""

import sys
import os

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


class TestValidateFlagFormat:
    def test_valid_flag(self):
        from core.symbio_ctf.models import validate_flag_format

        assert validate_flag_format("nexus7{abcdef1234567890}")

    def test_valid_flag_minimum_length_content(self):
        from core.symbio_ctf.models import validate_flag_format

        # Exactly 8 alphanumeric characters inside braces
        assert validate_flag_format("nexus7{abcdefgh}")

    def test_rejects_short_content(self):
        from core.symbio_ctf.models import validate_flag_format

        assert not validate_flag_format("nexus7{short}")

    def test_rejects_missing_braces(self):
        from core.symbio_ctf.models import validate_flag_format

        assert not validate_flag_format("nexus7abcdefgh12345")

    def test_rejects_special_characters_in_content(self):
        from core.symbio_ctf.models import validate_flag_format

        assert not validate_flag_format("nexus7{abcdefgh$$}")

    def test_rejects_empty_string(self):
        from core.symbio_ctf.models import validate_flag_format

        assert not validate_flag_format("")


class TestSanitizeInputCtf:
    def test_truncates_to_max_length(self):
        from core.symbio_ctf.models import sanitize_input

        result = sanitize_input("a" * 50, max_length=10)
        assert len(result) == 10

    def test_strips_surrounding_whitespace(self):
        from core.symbio_ctf.models import sanitize_input

        assert sanitize_input("  hello  ") == "hello"

    def test_removes_control_characters(self):
        from core.symbio_ctf.models import sanitize_input

        result = sanitize_input("hello\x00\x01world")
        assert "\x00" not in result
        assert "\x01" not in result

    def test_preserves_newlines_and_tabs(self):
        from core.symbio_ctf.models import sanitize_input

        result = sanitize_input("line1\nline2\tend")
        assert "\n" in result
        assert "\t" in result

    def test_raises_on_non_string_input(self):
        from core.symbio_ctf.models import sanitize_input

        with pytest.raises(ValueError):
            sanitize_input(12345)


class TestChallengeValidation:
    def test_sanitizes_description(self):
        from core.symbio_ctf.models import Challenge, ChallengeType

        challenge = Challenge(type=ChallengeType.PROMPT_INJECTION, description="  padded  ")
        assert challenge.description == "padded"

    def test_rejects_negative_max_points(self):
        from core.symbio_ctf.models import Challenge

        with pytest.raises(ValueError):
            Challenge(max_points=-1)

    def test_rejects_non_positive_time_limit(self):
        from core.symbio_ctf.models import Challenge

        with pytest.raises(ValueError):
            Challenge(time_limit=0)

    def test_accepts_valid_values(self):
        from core.symbio_ctf.models import Challenge

        challenge = Challenge(max_points=500, time_limit=1800)
        assert challenge.max_points == 500
        assert challenge.time_limit == 1800


class TestFlagValidation:
    def test_rejects_invalid_flag_value(self):
        from core.symbio_ctf.models import Flag

        with pytest.raises(ValueError):
            Flag(match_id="match-1", value="not-a-valid-flag")

    def test_rejects_empty_match_id(self):
        from core.symbio_ctf.models import Flag

        with pytest.raises(ValueError):
            Flag(match_id="", value="nexus7{abcdefgh12345}")

    def test_accepts_valid_flag(self):
        from core.symbio_ctf.models import Flag

        flag = Flag(match_id="match-1", value="nexus7{abcdefgh12345}")
        assert flag.value == "nexus7{abcdefgh12345}"
        assert not flag.captured


class TestMatchValidation:
    def test_rejects_empty_target_agent_id(self):
        from core.symbio_ctf.models import Match

        with pytest.raises(ValueError):
            Match(target_agent_id="")

    def test_rejects_non_list_attacker_ids(self):
        from core.symbio_ctf.models import Match

        with pytest.raises(ValueError):
            Match(target_agent_id="target-1", attacker_agent_ids="not-a-list")

    def test_accepts_valid_match(self):
        from core.symbio_ctf.models import Match

        match = Match(target_agent_id="target-1", attacker_agent_ids=["attacker-1"])
        assert match.target_agent_id == "target-1"
        assert match.attacker_agent_ids == ["attacker-1"]


class TestCTFExceptionHierarchy:
    def test_exceptions_inherit_from_ctf_error(self):
        from core.symbio_ctf.engine import (
            CTFError,
            ChallengeNotFoundError,
            MatchNotFoundError,
            InvalidFlagError,
        )

        assert issubclass(ChallengeNotFoundError, CTFError)
        assert issubclass(MatchNotFoundError, CTFError)
        assert issubclass(InvalidFlagError, CTFError)
        assert issubclass(CTFError, Exception)


class TestSymbioCTFEngineValidation:
    def test_create_challenge_rejects_negative_max_points(self):
        from core.symbio_ctf import SymbioCTF
        from core.symbio_ctf.models import ChallengeType

        ctf = SymbioCTF()
        with pytest.raises(ValueError):
            ctf.create_challenge(ChallengeType.PROMPT_INJECTION, max_points=-5)

    def test_create_challenge_rejects_non_positive_time_limit(self):
        from core.symbio_ctf import SymbioCTF
        from core.symbio_ctf.models import ChallengeType

        ctf = SymbioCTF()
        with pytest.raises(ValueError):
            ctf.create_challenge(ChallengeType.PROMPT_INJECTION, time_limit=-100)

    def test_create_challenge_sanitizes_description(self):
        from core.symbio_ctf import SymbioCTF
        from core.symbio_ctf.models import ChallengeType

        ctf = SymbioCTF()
        challenge = ctf.create_challenge(
            ChallengeType.PROMPT_INJECTION, description="  trimmed desc  "
        )
        assert challenge.description == "trimmed desc"

    def test_create_match_rejects_empty_target_agent_id(self):
        from core.symbio_ctf import SymbioCTF
        from core.symbio_ctf.models import ChallengeType

        ctf = SymbioCTF()
        challenge = ctf.create_challenge(ChallengeType.PROMPT_INJECTION)
        with pytest.raises(ValueError):
            ctf.create_match("", challenge.id)

    def test_create_match_rejects_empty_challenge_id(self):
        from core.symbio_ctf import SymbioCTF

        ctf = SymbioCTF()
        with pytest.raises(ValueError):
            ctf.create_match("target-1", "")

    def test_create_match_raises_challenge_not_found(self):
        from core.symbio_ctf import SymbioCTF
        from core.symbio_ctf.engine import ChallengeNotFoundError

        ctf = SymbioCTF()
        with pytest.raises(ChallengeNotFoundError):
            ctf.create_match("target-1", "does-not-exist")

    def test_submit_flag_raises_invalid_flag_error_for_malformed_flag(self):
        from core.symbio_ctf import SymbioCTF
        from core.symbio_ctf.engine import InvalidFlagError
        from core.symbio_ctf.models import ChallengeType

        ctf = SymbioCTF()
        challenge = ctf.create_challenge(ChallengeType.PROMPT_INJECTION)
        match = ctf.create_match("target-1", challenge.id, ["attacker-1"])
        ctf.start_match(match.id)

        with pytest.raises(InvalidFlagError):
            ctf.submit_flag(match.id, "totally-not-a-flag", "attacker-1")

    def test_submit_flag_sanitizes_agent_id(self):
        from core.symbio_ctf import SymbioCTF
        from core.symbio_ctf.models import ChallengeType

        ctf = SymbioCTF()
        challenge = ctf.create_challenge(ChallengeType.PROMPT_INJECTION)
        match = ctf.create_match("target-1", challenge.id, ["  attacker-1  "])
        ctf.start_match(match.id)

        flag_value = match.flags[0].value
        result = ctf.submit_flag(match.id, flag_value, "  attacker-1  ")
        assert result.success
        assert result.agent_id == "attacker-1"

    def test_engine_accepts_custom_rate_limit_config(self):
        from core.symbio_ctf import SymbioCTF

        ctf = SymbioCTF(
            rate_limit_max_requests=5,
            rate_limit_window_seconds=30,
            rate_limit_block_duration=60,
        )
        assert ctf._rate_limiter.max_requests == 5
        assert ctf._rate_limiter.window_seconds == 30
        assert ctf._rate_limiter.block_duration_seconds == 60

    def test_engine_default_rate_limit_config(self):
        from core.symbio_ctf import SymbioCTF

        ctf = SymbioCTF()
        assert ctf._rate_limiter.max_requests == 100
        assert ctf._rate_limiter.window_seconds == 60
        assert ctf._rate_limiter.block_duration_seconds == 300