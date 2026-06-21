import json
import os
from datetime import datetime

from dependency_auditor.analyzers.vulnerability_analyzer import VulnerabilityResult
from dependency_auditor.analyzers.license_analyzer import LicenseResult
from dependency_auditor.analyzers.circular_detector import CircularDependency
from dependency_auditor.analyzers.outdated_checker import OutdatedResult
from dependency_auditor.analyzers.policy_engine import PolicyResult, PolicyViolation, PolicyAction
from dependency_auditor.analyzers.baseline_comparator import BaselineDiff


class JsonExporter:
    def export(
        self,
        vuln_results: list[VulnerabilityResult],
        license_results: list[LicenseResult],
        cycles: list[CircularDependency],
        outdated_results: list[OutdatedResult],
        output_dir: str = ".",
        policy_result: PolicyResult | None = None,
        baseline_diff: BaselineDiff | None = None,
        config_dict: dict | None = None,
    ) -> str:
        vulnerabilities = []
        for result in vuln_results:
            vulnerabilities.extend(self._serialize_vuln_result(result))

        licenses = []
        for result in license_results:
            licenses.extend(self._serialize_license_result(result))

        circular_dependencies = [
            {"cycle": cd.cycle, "length": cd.length}
            for cd in cycles
        ]

        outdated = [
            {
                "package": r.dependency.name,
                "current_version": r.current_version,
                "latest_version": r.latest_version,
                "ecosystem": r.ecosystem,
                "is_outdated": r.is_outdated,
            }
            for r in outdated_results
            if r.is_outdated
        ]

        timestamp = datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")

        vuln_by_severity: dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for v in vulnerabilities:
            sev = v["severity"].lower()
            vuln_by_severity[sev] = vuln_by_severity.get(sev, 0) + 1

        copyleft_pkg_count = sum(1 for lr in license_results if lr.has_copyleft)
        outdated_count = len(outdated)

        violations = []
        if policy_result:
            violations = [self._serialize_violation(v) for v in policy_result.violations]

        actions = []
        if policy_result:
            actions = [self._serialize_action(a) for a in policy_result.actions]

        diff_data = None
        if baseline_diff:
            diff_data = {
                "new_violations": [self._serialize_violation(v) for v in baseline_diff.new_violations],
                "existing_violations": [self._serialize_violation(v) for v in baseline_diff.existing_violations],
                "fixed_violations": baseline_diff.fixed_violations,
            }

        report = {
            "violations": violations,
            "vulnerabilities": vulnerabilities,
            "licenses": licenses,
            "circular_dependencies": circular_dependencies,
            "outdated": outdated,
            "metadata": {
                "timestamp": timestamp,
                "tool_version": "1.0.0",
                "summary": {
                    "total_violations": len(violations),
                    "total_vulnerabilities": len(vulnerabilities),
                    "critical": vuln_by_severity.get("critical", 0),
                    "high": vuln_by_severity.get("high", 0),
                    "medium": vuln_by_severity.get("medium", 0),
                    "low": vuln_by_severity.get("low", 0),
                    "total_licenses": len(licenses),
                    "copyleft_licenses": copyleft_pkg_count,
                    "total_circular_dependencies": len(circular_dependencies),
                    "total_outdated": outdated_count,
                },
            },
        }

        if actions:
            report["policy_actions"] = actions
        if diff_data:
            report["baseline_diff"] = diff_data
        if config_dict:
            report["policy_config"] = config_dict

        os.makedirs(output_dir, exist_ok=True)
        filename = f"dependency_audit_{timestamp}.json"
        output_path = os.path.join(output_dir, filename)

        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2, ensure_ascii=False)

        return output_path

    def _serialize_violation(self, v: PolicyViolation) -> dict:
        return {
            "type": v.type,
            "package": v.package,
            "version": v.version,
            "severity": v.severity,
            "reason": v.reason,
            "details": v.details,
        }

    def _serialize_action(self, a: PolicyAction) -> dict:
        return {
            "action": a.action,
            "rule": a.rule,
            "package": a.package,
            "reason": a.reason,
            "details": a.details,
        }

    def _serialize_vuln_result(self, result: VulnerabilityResult) -> list[dict]:
        items = []
        for vuln in result.vulnerabilities:
            items.append({
                "package": result.dependency.name,
                "version": result.dependency.version_spec,
                "ecosystem": result.dependency.ecosystem,
                "severity": vuln.severity,
                "cve_id": vuln.cve_id,
                "cvss_score": vuln.cvss_score,
                "title": vuln.title,
                "description": vuln.description,
                "references": vuln.reference_urls,
            })
        return items

    def _serialize_license_result(self, result: LicenseResult) -> list[dict]:
        items = []
        for lic in result.licenses:
            items.append({
                "package": result.dependency.name,
                "version": result.dependency.version_spec,
                "license_id": lic.license_id,
                "risk_level": lic.risk_level,
                "is_copyleft": lic.is_copyleft,
            })
        return items
