"""
SASTDASTPipeline — Static and Dynamic Analysis Integration
Combines Shannon's static code analysis with live DAST testing.
"""

from __future__ import annotations

import re
import time
from dataclasses import dataclass, field
from typing import Any


@dataclass
class SASTFinding:
    """A static analysis finding."""
    file_path: str
    line_number: int
    rule_id: str
    severity: str
    title: str
    description: str
    code_snippet: str = ""
    cwe_id: str = ""


@dataclass
class DASTFinding:
    """A dynamic analysis finding."""
    url: str
    method: str
    payload: str
    severity: str
    title: str
    response_code: int = 0
    response_body: str = ""
    proof: str = ""


class SASTDASTPipeline:
    """
    Combined SAST/DAST pipeline for comprehensive vulnerability detection.
    SAST: Static code analysis (source code scanning)
    DAST: Dynamic application security testing (live probing)
    """

    # SAST Rules based on OWASP Top 10 + Shannon's patterns
    SAST_RULES = {
        "S001": {
            "pattern": r'(?:execute|exec|eval)\s*\(\s*(?:f["\']|.*\+|.*\.format|.*%s)',
            "title": "Potential Command Injection",
            "severity": "critical",
            "cwe": "CWE-78",
        },
        "S002": {
            "pattern": r'(?i)(?:cursor|query|execute)\s*\(.*(?:\+|%s|%d|\.format|f["\'])',
            "title": "Potential SQL Injection",
            "severity": "critical",
            "cwe": "CWE-89",
        },
        "S003": {
            "pattern": r'(?i)(?:innerHTML|outerHTML|document\.write|\.html\s*\()',
            "title": "Potential XSS via DOM manipulation",
            "severity": "high",
            "cwe": "CWE-79",
        },
        "S004": {
            "pattern": r'(?i)(?:requests\.get|requests\.post|urllib|http\.client)\s*\(\s*(?:f["\']|.*\+)',
            "title": "Potential SSRF",
            "severity": "high",
            "cwe": "CWE-918",
        },
        "S005": {
            "pattern": r'(?i)(?:jwt|token|secret|password|api_key)\s*=\s*["\'][^"\']+["\']',
            "title": "Hardcoded credential",
            "severity": "high",
            "cwe": "CWE-798",
        },
        "S006": {
            "pattern": r'(?i)(?:pickle|marshal|yaml\.load|yaml\.unsafe_load)\s*\(',
            "title": "Unsafe deserialization",
            "severity": "high",
            "cwe": "CWE-502",
        },
        "S007": {
            "pattern": r'(?i)(?:os\.system|subprocess\.call|subprocess\.run|popen)\s*\(.*(?:\+|%|\.format|f["\'])',
            "title": "Potential OS command injection",
            "severity": "critical",
            "cwe": "CWE-78",
        },
        "S008": {
            "pattern": r'(?i)(?:file|open)\s*\(.*(?:request|params|input|user)',
            "title": "Potential path traversal",
            "severity": "medium",
            "cwe": "CWE-22",
        },
        "S009": {
            "pattern": r'(?i)@app\.route.*methods.*GET.*POST',
            "title": "Route accepts multiple methods without CSRF protection",
            "severity": "medium",
            "cwe": "CWE-352",
        },
        "S010": {
            "pattern": r'(?i)(?:md5|sha1)\s*\(',
            "title": "Weak hashing algorithm",
            "severity": "low",
            "cwe": "CWE-328",
        },
    }

    def __init__(self):
        self._sast_findings: list[SASTFinding] = []
        self._dast_findings: list[DASTFinding] = []

    # ── Static Analysis ───────────────────────────────────────────────

    def run_sast(self, source_files: dict[str, str]) -> list[SASTFinding]:
        """
        Run static analysis on source code.
        source_files: {filepath: content}
        """
        findings = []

        for filepath, content in source_files.items():
            lines = content.split("\n")

            for rule_id, rule in self.SAST_RULES.items():
                for i, line in enumerate(lines, 1):
                    if re.search(rule["pattern"], line):
                        finding = SASTFinding(
                            file_path=filepath,
                            line_number=i,
                            rule_id=rule_id,
                            severity=rule["severity"],
                            title=rule["title"],
                            description=f"Rule {rule_id}: {rule['title']}",
                            code_snippet=line.strip()[:200],
                            cwe_id=rule["cwe"],
                        )
                        findings.append(finding)

        self._sast_findings.extend(findings)
        return findings

    # ── Dynamic Analysis ──────────────────────────────────────────────

    def run_dast_probe(self, url: str, method: str = "GET",
                       payload: str = "", response_code: int = 0,
                       response_body: str = "") -> DASTFinding | None:
        """
        Record a DAST probe result.
        In production, this would make actual HTTP requests.
        """
        severity = "info"
        title = f"{method} {url}"

        # Assess severity based on response
        if response_code == 500:
            severity = "high"
            title = f"Server error on {method} {url}"
        elif response_code == 403:
            severity = "medium"
            title = f"Access denied on {method} {url}"
        elif "error" in response_body.lower() or "exception" in response_body.lower():
            severity = "medium"
            title = f"Error response from {method} {url}"
        elif payload and payload in response_body:
            severity = "critical"
            title = f"Payload reflected in response: {method} {url}"

        finding = DASTFinding(
            url=url,
            method=method,
            payload=payload[:200],
            severity=severity,
            title=title,
            response_code=response_code,
            response_body=response_body[:500],
            proof=f"Response contained payload" if payload in response_body else "",
        )

        self._dast_findings.append(finding)
        return finding

    def run_dast_scan(self, endpoints: list[dict]) -> list[DASTFinding]:
        """
        Run DAST against multiple endpoints.
        endpoints: [{url, method, payloads}]
        """
        findings = []
        # Common DAST payloads
        default_payloads = {
            "xss": "<script>alert(1)</script>",
            "sqli": "' OR '1'='1",
            "path_traversal": "../../../etc/passwd",
            "command_injection": "; id",
        }

        for ep in endpoints:
            url = ep.get("url", "")
            method = ep.get("method", "GET")

            for vuln_type, payload in default_payloads.items():
                # Simulate probe (in production, make actual request)
                finding = self.run_dast_probe(
                    url=url,
                    method=method,
                    payload=payload,
                    response_code=200,  # Simulated
                    response_body="",
                )
                if finding:
                    findings.append(finding)

        return findings

    # ── Combined Reporting ───────────────────────────────────────────

    def get_combined_report(self) -> dict[str, Any]:
        """Get combined SAST+DAST report."""
        all_findings = []

        for f in self._sast_findings:
            all_findings.append({
                "type": "SAST",
                "source": f"{f.file_path}:{f.line_number}",
                "severity": f.severity,
                "title": f.title,
                "rule": f.rule_id,
                "cwe": f.cwe_id,
            })

        for f in self._dast_findings:
            all_findings.append({
                "type": "DAST",
                "source": f"{f.method} {f.url}",
                "severity": f.severity,
                "title": f.title,
                "response_code": f.response_code,
            })

        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for f in all_findings:
            sev = f["severity"]
            if sev in severity_counts:
                severity_counts[sev] += 1

        return {
            "total_findings": len(all_findings),
            "sast_findings": len(self._sast_findings),
            "dast_findings": len(self._dast_findings),
            "severity_counts": severity_counts,
            "findings": all_findings,
            "generated_at": time.time(),
        }

    def get_sast_findings(self, severity: str | None = None) -> list[SASTFinding]:
        if severity:
            return [f for f in self._sast_findings if f.severity == severity]
        return list(self._sast_findings)

    def get_dast_findings(self, severity: str | None = None) -> list[DASTFinding]:
        if severity:
            return [f for f in self._dast_findings if f.severity == severity]
        return list(self._dast_findings)

    def reset(self):
        self._sast_findings.clear()
        self._dast_findings.clear()
