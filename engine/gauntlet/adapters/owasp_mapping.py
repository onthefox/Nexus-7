"""OWASP Top 10 for Large Language Model Applications mapping.

Provides the canonical OWASP LLM Top 10 (2025) catalogue and a mapping from
Shannon pentest agent attack patterns (MCP tool names) to OWASP categories,
so every attack executed through the Shannon adapter is reported against the
relevant OWASP entry.

Reference: https://owasp.org/www-project-top-10-for-large-language-model-applications/
"""

from __future__ import annotations

# Canonical OWASP LLM Top 10 catalogue: code -> human readable name.
OWASP_LLM_TOP10: dict[str, str] = {
    "LLM01": "Prompt Injection",
    "LLM02": "Sensitive Information Disclosure",
    "LLM03": "Supply Chain",
    "LLM04": "Data and Model Poisoning",
    "LLM05": "Improper Output Handling",
    "LLM06": "Excessive Agency",
    "LLM07": "System Prompt Leakage",
    "LLM08": "Vector and Embedding Weaknesses",
    "LLM09": "Misinformation",
    "LLM10": "Unbounded Consumption",
}

# Shannon attack pattern (MCP tool name) -> OWASP LLM Top 10 code.
SHANNON_PATTERN_TO_OWASP: dict[str, str] = {
    "prompt_injection": "LLM01",
    "direct_prompt_injection": "LLM01",
    "indirect_prompt_injection": "LLM01",
    "jailbreak": "LLM01",
    "infection_chain": "LLM01",
    "system_prompt_extraction": "LLM07",
    "secret_extraction": "LLM02",
    "sensitive_data_disclosure": "LLM02",
    "data_exfiltration": "LLM02",
    "supply_chain_probe": "LLM03",
    "dependency_poisoning": "LLM03",
    "data_poisoning": "LLM04",
    "rag_poisoning": "LLM04",
    "output_handling_abuse": "LLM05",
    "xss_via_llm_output": "LLM05",
    "tool_abuse": "LLM06",
    "excessive_agency_probe": "LLM06",
    "vector_store_injection": "LLM08",
    "embedding_collision": "LLM08",
    "hallucination_amplification": "LLM09",
    "misinformation_injection": "LLM09",
    "logic_loop": "LLM10",
    "context_overflow": "LLM10",
    "resource_exhaustion": "LLM10",
}

# Fallback category for patterns that have no dedicated OWASP entry yet.
OWASP_UNMAPPED = "UNMAPPED"


def owasp_for_pattern(pattern: str) -> str:
    """Return the OWASP LLM Top 10 code for a Shannon attack pattern.

    Matching is case-insensitive and tolerates tool-name spellings such as
    ``run_prompt_injection`` or ``shannon.jailbreak``. Unmapped patterns
    return ``OWASP_UNMAPPED``.
    """
    normalized = (pattern or "").strip().lower()
    if not normalized:
        return OWASP_UNMAPPED
    if normalized in SHANNON_PATTERN_TO_OWASP:
        return SHANNON_PATTERN_TO_OWASP[normalized]
    # Strip common MCP tool-name decorations ("run_", "shannon.", "_attack").
    stripped = normalized
    for prefix in ("run_", "shannon_", "shannon.", "attack_"):
        if stripped.startswith(prefix):
            stripped = stripped[len(prefix):]
            break
    stripped = stripped.removesuffix("_attack")
    return SHANNON_PATTERN_TO_OWASP.get(stripped, OWASP_UNMAPPED)


def owasp_name(code: str) -> str:
    """Human readable name for an OWASP code (empty string when unknown)."""
    return OWASP_LLM_TOP10.get(code, "")
