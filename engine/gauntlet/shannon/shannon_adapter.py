"""
ShannonAdapter — Main Shannon Integration for Nexus-7 Gauntlet
Combines all Shannon patterns into a unified adapter for the Gauntlet engine.

Integrates:
- Shannon's 5-phase pentest pipeline
- Preflight validation (3-step)
- Exploit chaining (Tenzai pattern)
- Behavioral reasoning (Tenzai pattern)
- Context relay (NDSS 2026 pattern)
- Audit logging (Shannon pattern)
- Infection chain detection (2026 research)
- SAST/DAST pipeline
"""

from __future__ import annotations

import time
from typing import Any

from .models import ShannonConfig, ShannonResult, ShannonVulnerability, VulnSeverity, PipelinePhase
from .preflight import PreflightValidator
from .exploit_chain import ExploitChainEngine
from .behavioral import BehavioralReasoner
from .context_relay import ContextRelay
from .audit import ShannonAudit
from .infection import InfectionChainDetector
from .sast_dast import SASTDASTPipeline


class ShannonAdapter:
    """
    Shannon pentesting adapter for Nexus-7 Gauntlet.
    Provides real pentesting capabilities by integrating Shannon's patterns
    with Nexus-7's CTF infrastructure.
    """

    def __init__(self, ctf_engine=None, gauntlet=None):
        self._config = ShannonConfig()
        self._preflight = PreflightValidator()
        self._exploit_chain = ExploitChainEngine()
        self._behavioral = BehavioralReasoner()
        self._context_relay = ContextRelay()
        self._audit = ShannonAudit()
        self._infection = InfectionChainDetector()
        self._sast_dast = SASTDASTPipeline()
        self._ctf = ctf_engine
        self._gauntlet = gauntlet
        self._active_sessions: dict[str, ShannonResult] = {}

    def configure(self, config: ShannonConfig):
        """Configure the adapter."""
        self._config = config

    def run_pentest(self, target_id: str, config: ShannonConfig | None = None) -> ShannonResult:
        """
        Run a full Shannon pentest pipeline against a target.
        Implements the 5-phase workflow from Shannon:
        1. Preflight validation
        2. Pre-reconnaissance (static analysis)
        3. Reconnaissance (behavioral analysis)
        4. Vulnerability analysis + exploitation (parallel)
        5. Reporting
        """
        if config:
            self._config = config

        result = ShannonResult(target_id=target_id)
        self._active_sessions[target_id] = result

        start_time = time.time()

        # Phase 0: Preflight
        result.phase = PipelinePhase.PREFLIGHT
        preflight = self._preflight.validate(self._config)
        if not preflight.passed:
            result.errors = preflight.errors
            result.duration = time.time() - start_time
            self._audit.log_event("shannon", "preflight_failed",
                                  success=False, error="; ".join(preflight.errors))
            return result

        self._audit.log_event("shannon", "preflight_passed",
                              metadata={"checks": preflight.checks})
        self._context_relay.create_snapshot("preflight", "Preflight validation passed")

        # Phase 1: Pre-Reconnaissance (SAST)
        result.phase = PipelinePhase.PRE_RECON
        self._audit.log_event("shannon", "pre_recon_start")

        if self._config.enable_sast:
            sast_findings = self._sast_dast.get_sast_findings()
            for f in sast_findings:
                vuln = self._shannon_finding_to_vuln(f)
                result.vulnerabilities.append(vuln)
                self._audit.log_event("shannon-sast", f"Found: {f.title}",
                                      metadata={"file": f.file_path, "line": f.line_number})

        self._context_relay.create_snapshot("pre_recon",
                                             f"SAST complete: {len(result.vulnerabilities)} findings",
                                             findings=[v.title for v in result.vulnerabilities[:10]])

        # Phase 2: Reconnaissance (Behavioral Analysis)
        result.phase = PipelinePhase.RECON
        self._audit.log_event("shannon", "recon_start")

        # Analyze behavioral patterns
        behavioral_findings = self._behavioral.get_findings()
        for f in behavioral_findings:
            vuln = ShannonVulnerability(
                type=f"behavioral_{f.category}",
                severity=self._map_severity(f.severity),
                title=f.title,
                description=f.description,
                poc=" | ".join(f.attack_path[:3]),
                remediation=f.recommendation,
            )
            result.vulnerabilities.append(vuln)

        self._context_relay.create_snapshot("recon",
                                             f"Recon complete: {len(result.vulnerabilities)} total findings",
                                             findings=[v.title for v in result.vulnerabilities[:15]])

        # Phase 3-4: Vulnerability Analysis + Exploitation
        result.phase = PipelinePhase.VULN_ANALYSIS
        self._audit.log_event("shannon", "vuln_analysis_start")

        # Recommend exploit chains based on findings
        vuln_dicts = [{"type": v.type} for v in result.vulnerabilities]
        recommended_chains = self._exploit_chain.get_available_chains(vuln_dicts)

        for chain_rec in recommended_chains[:3]:
            chain = self._exploit_chain.create_chain(chain_rec["chain"], target_id)
            if chain:
                self._audit.log_event("shannon", "chain_created",
                                      metadata={"chain": chain.name, "confidence": chain_rec["confidence"]})

        # Simulate exploitation
        result.phase = PipelinePhase.EXPLOITATION
        self._audit.log_event("shannon", "exploitation_start")

        # Run DAST
        if self._config.enable_dast:
            dast_findings = self._sast_dast.get_dast_findings()
            for f in dast_findings:
                vuln = ShannonVulnerability(
                    type=f"dast_{f.severity}",
                    severity=self._map_severity(f.severity),
                    title=f.title,
                    location=f.url,
                    poc=f.payload[:100] if f.payload else "",
                )
                result.vulnerabilities.append(vuln)

        # Check for infection chains
        infection_stats = self._infection.get_stats()
        if infection_stats["critical_chains"] > 0:
            critical_chains = self._infection.get_critical_chains()
            for chain in critical_chains:
                vuln = ShannonVulnerability(
                    type="infection_chain",
                    severity=VulnSeverity.CRITICAL,
                    title=f"Critical infection chain detected: {chain.id}",
                    description=f"Viral prompt propagated across {len(chain.involved_agents)} agents",
                )
                result.vulnerabilities.append(vuln)

        result.phase = PipelinePhase.REPORTING
        self._audit.log_event("shannon", "reporting_start")

        # Calculate totals
        result.total_attacks = len(result.vulnerabilities)
        result.successful_attacks = sum(
            1 for v in result.vulnerabilities if v.severity in (VulnSeverity.HIGH, VulnSeverity.CRITICAL)
        )
        result.duration = time.time() - start_time
        result.completed_at = time.time()

        # Generate report
        result.report = self._generate_report(result)

        # Export audit log
        self._audit.export_log()

        self._audit.log_event("shannon", "pentest_complete",
                              duration=result.duration,
                              metadata={
                                  "vulnerabilities": len(result.vulnerabilities),
                                  "critical": result.critical_count,
                                  "high": result.high_count,
                                  "risk_score": result.risk_score,
                              })

        return result

    def _shannon_finding_to_vuln(self, finding) -> ShannonVulnerability:
        """Convert a SAST finding to ShannonVulnerability."""
        return ShannonVulnerability(
            type=f"sast_{finding.rule_id.lower()}",
            severity=self._map_severity(finding.severity),
            title=finding.title,
            description=finding.description,
            location=f"{finding.file_path}:{finding.line_number}",
            poc=finding.code_snippet[:100] if finding.code_snippet else "",
            owasp_category=finding.cwe_id,
        )

    def _map_severity(self, severity: str) -> VulnSeverity:
        """Map string severity to VulnSeverity enum."""
        mapping = {
            "critical": VulnSeverity.CRITICAL,
            "high": VulnSeverity.HIGH,
            "medium": VulnSeverity.MEDIUM,
            "low": VulnSeverity.LOW,
            "info": VulnSeverity.INFO,
        }
        return mapping.get(severity.lower(), VulnSeverity.MEDIUM)

    def _generate_report(self, result: ShannonResult) -> str:
        """Generate executive pentest report."""
        lines = [
            f"# Shannon Pentest Report",
            f"",
            f"## Summary",
            f"- Target: {result.target_id}",
            f"- Session: {result.session_id}",
            f"- Duration: {result.duration:.1f}s",
            f"- Total vulnerabilities: {len(result.vulnerabilities)}",
            f"- Critical: {result.critical_count}",
            f"- High: {result.high_count}",
            f"- Risk Score: {result.risk_score}/100",
            f"",
            f"## Findings",
            f"",
        ]

        for i, vuln in enumerate(result.vulnerabilities, 1):
            lines.extend([
                f"### {i}. [{vuln.severity.value.upper()}] {vuln.title}",
                f"- Type: {vuln.type}",
                f"- Location: {vuln.location}",
                f"- Description: {vuln.description}",
                f"- PoC: {vuln.poc}",
                f"- OWASP: {vuln.owasp_category}",
                f"- CVSS: {vuln.cvss_score}",
                f"",
            ])

        lines.extend([
            f"## Recommendations",
            f"1. Address all critical vulnerabilities immediately",
            f"2. Fix high-severity issues within 7 days",
            f"3. Schedule medium-severity fixes for next sprint",
            f"4. Review and update security controls",
            f"",
            f"--- Report generated by Shannon Adapter for Nexus-7 ---",
        ])

        return "\n".join(lines)

    # ── Accessors ─────────────────────────────────────────────────────

    @property
    def audit(self) -> ShannonAudit:
        return self._audit

    @property
    def exploit_chain(self) -> ExploitChainEngine:
        return self._exploit_chain

    @property
    def behavioral(self) -> BehavioralReasoner:
        return self._behavioral

    @property
    def context_relay(self) -> ContextRelay:
        return self._context_relay

    @property
    def infection_detector(self) -> InfectionChainDetector:
        return self._infection

    @property
    def sast_dast(self) -> SASTDASTPipeline:
        return self._sast_dast

    def get_audit_metrics(self) -> dict:
        return self._audit.get_metrics()

    def get_session(self, target_id: str) -> ShannonResult | None:
        return self._active_sessions.get(target_id)

    def reset(self):
        self._active_sessions.clear()
        self._preflight = PreflightValidator()
        self._exploit_chain = ExploitChainEngine()
        self._behavioral = BehavioralReasoner()
        self._context_relay = ContextRelay()
        self._audit = ShannonAudit()
        self._infection = InfectionChainDetector()
        self._sast_dast = SASTDASTPipeline()
