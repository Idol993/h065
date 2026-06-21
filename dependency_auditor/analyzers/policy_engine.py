from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta

from dependency_auditor.analyzers.vulnerability_analyzer import VulnerabilityResult, Vulnerability
from dependency_auditor.analyzers.license_analyzer import LicenseResult, LicenseRisk
from dependency_auditor.analyzers.circular_detector import CircularDependency
from dependency_auditor.analyzers.outdated_checker import OutdatedResult
from dependency_auditor.parsers.python_parser import Dependency
from dependency_auditor.utils.config_loader import ConfigLoader


_SEVERITY_WEIGHT = {"critical": 4, "high": 3, "medium": 2, "low": 1}


@dataclass
class PolicyViolation:
    type: str
    package: str
    version: str
    severity: str
    reason: str
    details: dict = field(default_factory=dict)


@dataclass
class PolicyAction:
    action: str
    rule: str
    package: str
    reason: str
    details: dict = field(default_factory=dict)


@dataclass
class PolicyResult:
    filtered_vulns: list[VulnerabilityResult]
    filtered_licenses: list[LicenseResult]
    filtered_cycles: list[CircularDependency]
    filtered_outdated: list[OutdatedResult]
    violations: list[PolicyViolation]
    actions: list[PolicyAction]


class PolicyEngine:
    def __init__(self, config: ConfigLoader):
        self.config = config
        self._severity_threshold = self._parse_severity(config.severity_threshold)
        self._license_threshold = self._parse_severity(config.license_threshold)
        self._license_allowlist = set(config.license_allowlist)
        self._license_denylist = set(config.license_denylist)
        self._ignore_packages = set(config.ignore_packages)
        self._allowed_outdated = set(config.allowed_outdated_packages)
        self._grace_days = config.outdated_grace_days

    def _parse_severity(self, s: str) -> int:
        return _SEVERITY_WEIGHT.get(s.lower(), 1)

    def apply(
        self,
        vuln_results: list[VulnerabilityResult],
        license_results: list[LicenseResult],
        cycles: list[CircularDependency],
        outdated_results: list[OutdatedResult],
    ) -> PolicyResult:
        actions: list[PolicyAction] = []
        violations: list[PolicyViolation] = []

        filtered_vulns = self._filter_vulns(vuln_results, actions, violations)
        filtered_licenses = self._filter_licenses(license_results, actions, violations)
        filtered_cycles = self._filter_cycles(cycles, actions, violations)
        filtered_outdated = self._filter_outdated(outdated_results, actions, violations)

        return PolicyResult(
            filtered_vulns=filtered_vulns,
            filtered_licenses=filtered_licenses,
            filtered_cycles=filtered_cycles,
            filtered_outdated=filtered_outdated,
            violations=violations,
            actions=actions,
        )

    def _should_ignore_package(self, pkg_name: str) -> bool:
        return pkg_name in self._ignore_packages

    def _filter_vulns(
        self,
        results: list[VulnerabilityResult],
        actions: list[PolicyAction],
        violations: list[PolicyViolation],
    ) -> list[VulnerabilityResult]:
        filtered: list[VulnerabilityResult] = []

        for vr in results:
            pkg_name = vr.dependency.name

            if self._should_ignore_package(pkg_name):
                actions.append(PolicyAction(
                    action="ignore",
                    rule="ignore_packages",
                    package=pkg_name,
                    reason=f"Package '{pkg_name}' is in ignore list",
                ))
                continue

            kept_vulns: list[Vulnerability] = []
            for v in vr.vulnerabilities:
                sev_weight = _SEVERITY_WEIGHT.get(v.severity.lower(), 1)
                if sev_weight < self._severity_threshold:
                    actions.append(PolicyAction(
                        action="allow",
                        rule="severity_threshold",
                        package=pkg_name,
                        reason=f"Vulnerability {v.cve_id} severity {v.severity} below threshold",
                        details={"cve_id": v.cve_id, "severity": v.severity},
                    ))
                    continue

                kept_vulns.append(v)
                violations.append(PolicyViolation(
                    type="vulnerability",
                    package=pkg_name,
                    version=vr.dependency.version_spec,
                    severity=v.severity,
                    reason=f"{v.severity.upper()} severity vulnerability: {v.title}",
                    details={"cve_id": v.cve_id, "cvss_score": v.cvss_score},
                ))

            if kept_vulns:
                filtered.append(VulnerabilityResult(
                    dependency=vr.dependency,
                    vulnerabilities=kept_vulns,
                    coordinate=vr.coordinate,
                ))

        return filtered

    def _filter_licenses(
        self,
        results: list[LicenseResult],
        actions: list[PolicyAction],
        violations: list[PolicyViolation],
    ) -> list[LicenseResult]:
        filtered: list[LicenseResult] = []

        for lr in results:
            pkg_name = lr.dependency.name

            if self._should_ignore_package(pkg_name):
                actions.append(PolicyAction(
                    action="ignore",
                    rule="ignore_packages",
                    package=pkg_name,
                    reason=f"Package '{pkg_name}' is in ignore list",
                ))
                continue

            kept_licenses: list[LicenseRisk] = []
            has_violation = False

            for lic in lr.licenses:
                if lic.license_id in self._license_allowlist:
                    actions.append(PolicyAction(
                        action="allow",
                        rule="license_allowlist",
                        package=pkg_name,
                        reason=f"License '{lic.license_id}' is in allowlist",
                        details={"license_id": lic.license_id},
                    ))
                    continue

                if lic.license_id in self._license_denylist:
                    kept_licenses.append(lic)
                    has_violation = True
                    violations.append(PolicyViolation(
                        type="copyleft_license",
                        package=pkg_name,
                        version=lr.dependency.version_spec,
                        severity="high" if lic.is_copyleft else "medium",
                        reason=f"License '{lic.license_id}' is in denylist",
                        details={"license_id": lic.license_id, "risk_level": lic.risk_level},
                    ))
                    continue

                lic_risk_weight = _SEVERITY_WEIGHT.get(lic.risk_level.lower(), 1)
                if lic_risk_weight < self._license_threshold:
                    actions.append(PolicyAction(
                        action="allow",
                        rule="license_threshold",
                        package=pkg_name,
                        reason=f"License risk {lic.risk_level} below threshold",
                        details={"license_id": lic.license_id, "risk_level": lic.risk_level},
                    ))
                    continue

                if lic.is_copyleft:
                    kept_licenses.append(lic)
                    has_violation = True
                    violations.append(PolicyViolation(
                        type="copyleft_license",
                        package=pkg_name,
                        version=lr.dependency.version_spec,
                        severity=lic.risk_level,
                        reason=f"Copyleft license '{lic.license_id}' has {lic.risk_level} risk",
                        details={"license_id": lic.license_id, "is_copyleft": True},
                    ))
                else:
                    kept_licenses.append(lic)

            if kept_licenses:
                filtered.append(LicenseResult(
                    dependency=lr.dependency,
                    licenses=kept_licenses,
                    has_copyleft=any(l.is_copyleft for l in kept_licenses),
                ))

        return filtered

    def _filter_cycles(
        self,
        cycles: list[CircularDependency],
        actions: list[PolicyAction],
        violations: list[PolicyViolation],
    ) -> list[CircularDependency]:
        filtered: list[CircularDependency] = []

        for cd in cycles:
            ignored_nodes = [n for n in cd.cycle if self._should_ignore_package(n)]
            if ignored_nodes:
                actions.append(PolicyAction(
                    action="ignore",
                    rule="ignore_packages",
                    package=",".join(ignored_nodes),
                    reason=f"Cycle contains ignored packages: {', '.join(ignored_nodes)}",
                    details={"cycle": cd.cycle},
                ))
                continue

            filtered.append(cd)
            first_pkg = cd.cycle[0] if cd.cycle else ""
            violations.append(PolicyViolation(
                type="circular_dependency",
                package=first_pkg,
                version="",
                severity="medium",
                reason=f"Circular dependency detected: {' → '.join(cd.cycle)}",
                details={"cycle": cd.cycle, "length": cd.length},
            ))

        return filtered

    def _filter_outdated(
        self,
        results: list[OutdatedResult],
        actions: list[PolicyAction],
        violations: list[PolicyViolation],
    ) -> list[OutdatedResult]:
        filtered: list[OutdatedResult] = []
        now = datetime.utcnow()

        for r in results:
            if not r.is_outdated:
                continue

            pkg_name = r.dependency.name

            if self._should_ignore_package(pkg_name):
                actions.append(PolicyAction(
                    action="ignore",
                    rule="ignore_packages",
                    package=pkg_name,
                    reason=f"Package '{pkg_name}' is in ignore list",
                ))
                continue

            if pkg_name in self._allowed_outdated:
                actions.append(PolicyAction(
                    action="allow",
                    rule="allowed_outdated_packages",
                    package=pkg_name,
                    reason=f"Package '{pkg_name}' is allowed to be outdated",
                ))
                continue

            if self._grace_days > 0:
                release_date = getattr(r, "_latest_release_date", None)
                if release_date:
                    try:
                        if isinstance(release_date, str):
                            release_dt = datetime.fromisoformat(release_date.replace("Z", "+00:00"))
                        else:
                            release_dt = release_date
                        age = now - release_dt
                        if age < timedelta(days=self._grace_days):
                            actions.append(PolicyAction(
                                action="allow",
                                rule="outdated_grace_days",
                                package=pkg_name,
                                reason=f"Latest version released {age.days} days ago, within grace period",
                                details={"release_date": str(release_date), "age_days": age.days},
                            ))
                            continue
                    except (ValueError, TypeError):
                        pass

            filtered.append(r)
            violations.append(PolicyViolation(
                type="outdated_package",
                package=pkg_name,
                version=r.current_version,
                severity="low",
                reason=f"Package is outdated: {r.current_version} → {r.latest_version}",
                details={"current_version": r.current_version, "latest_version": r.latest_version},
            ))

        return filtered
