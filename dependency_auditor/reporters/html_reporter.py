import json
import os
from datetime import datetime

from jinja2 import Environment, FileSystemLoader

from dependency_auditor.analyzers.circular_detector import CircularDependency
from dependency_auditor.analyzers.license_analyzer import LicenseResult
from dependency_auditor.analyzers.outdated_checker import OutdatedResult
from dependency_auditor.analyzers.vulnerability_analyzer import VulnerabilityResult
from dependency_auditor.analyzers.policy_engine import PolicyResult, PolicyViolation, PolicyAction
from dependency_auditor.analyzers.baseline_comparator import BaselineDiff
from dependency_auditor.parsers.python_parser import Dependency


class HtmlReporter:
    def __init__(self):
        template_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "templates")
        self.env = Environment(loader=FileSystemLoader(template_dir))

    def export(
        self,
        vuln_results: list[VulnerabilityResult],
        license_results: list[LicenseResult],
        cycles: list[CircularDependency],
        outdated_results: list[OutdatedResult],
        dep_tree: dict | None = None,
        output_dir: str = ".",
        policy_result: PolicyResult | None = None,
        baseline_diff: BaselineDiff | None = None,
        config_dict: dict | None = None,
    ) -> str:
        vulnerability_data = []
        for result in vuln_results:
            for vuln in result.vulnerabilities:
                vulnerability_data.append({
                    "package": result.dependency.name,
                    "version": result.dependency.version_spec,
                    "severity": vuln.severity,
                    "cve_id": vuln.cve_id,
                    "cvss_score": vuln.cvss_score,
                    "title": vuln.title,
                    "description": vuln.description,
                    "references": vuln.reference_urls,
                })

        license_data = []
        for result in license_results:
            for lic in result.licenses:
                license_data.append({
                    "package": result.dependency.name,
                    "license_id": lic.license_id,
                    "risk_level": lic.risk_level,
                    "is_copyleft": lic.is_copyleft,
                })

        circular_data = [
            {"cycle": cd.cycle, "length": cd.length}
            for cd in cycles
        ]

        outdated_data = []
        for r in outdated_results:
            if r.is_outdated:
                outdated_data.append({
                    "package": r.dependency.name,
                    "current": r.current_version,
                    "latest": r.latest_version,
                    "ecosystem": r.ecosystem,
                })

        all_deps = self._collect_deps(vuln_results, license_results, outdated_results)
        graph_data = self._build_graph_data(all_deps, dep_tree, cycles)

        vuln_by_severity: dict[str, int] = {}
        for item in vulnerability_data:
            sev = item["severity"].lower()
            vuln_by_severity[sev] = vuln_by_severity.get(sev, 0) + 1

        summary = {
            "total_vulnerabilities": len(vulnerability_data),
            "critical": vuln_by_severity.get("critical", 0),
            "high": vuln_by_severity.get("high", 0),
            "medium": vuln_by_severity.get("medium", 0),
            "low": vuln_by_severity.get("low", 0),
            "total_licenses": len(license_data),
            "copyleft_licenses": sum(1 for lr in license_results if lr.has_copyleft),
            "copyleft": sum(1 for lr in license_results if lr.has_copyleft),
            "total_circular_dependencies": len(circular_data),
            "circular": len(circular_data),
            "total_outdated": len(outdated_data),
            "outdated": len(outdated_data),
        }

        violations_data = []
        if policy_result:
            violations_data = [self._serialize_violation(v) for v in policy_result.violations]

        actions_data = []
        if policy_result:
            actions_data = [self._serialize_action(a) for a in policy_result.actions]

        diff_data = None
        if baseline_diff:
            diff_data = {
                "new_violations": [self._serialize_violation(v) for v in baseline_diff.new_violations],
                "existing_violations": [self._serialize_violation(v) for v in baseline_diff.existing_violations],
                "fixed_violations": baseline_diff.fixed_violations,
            }
            summary["new_violations"] = len(baseline_diff.new_violations)
            summary["existing_violations"] = len(baseline_diff.existing_violations)
            summary["fixed_violations"] = len(baseline_diff.fixed_violations)

        template = self.env.get_template("report.html")
        timestamp = datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")

        html_content = template.render(
            vulnerability_data=vulnerability_data,
            license_data=license_data,
            circular_data=circular_data,
            outdated_data=outdated_data,
            graph_data=graph_data,
            summary=summary,
            timestamp=timestamp,
            violations=violations_data,
            policy_actions=actions_data,
            baseline_diff=diff_data,
            policy_config=config_dict or {},
        )

        os.makedirs(output_dir, exist_ok=True)
        filename = f"dependency_audit_{timestamp}.html"
        output_path = os.path.join(output_dir, filename)

        with open(output_path, "w", encoding="utf-8") as f:
            f.write(html_content)

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

    def _build_graph_data(
        self,
        deps: list[Dependency],
        dep_tree: dict | None,
        cycles: list[CircularDependency],
    ) -> dict:
        nodes = []
        seen: set[str] = set()

        cycle_nodes: set[str] = set()
        cycle_edges: set[tuple[str, str]] = set()
        for cd in cycles:
            cycle_len = len(cd.cycle)
            for i in range(cycle_len):
                u = cd.cycle[i]
                v = cd.cycle[(i + 1) % cycle_len]
                cycle_nodes.add(u)
                cycle_nodes.add(v)
                cycle_edges.add((u, v))

        for dep in deps:
            if dep.name in seen:
                continue
            seen.add(dep.name)

            vuln_count = getattr(dep, "_vuln_count", 0)
            if vuln_count == 0:
                risk = "low"
            elif vuln_count >= 3:
                risk = "high"
            else:
                risk = "medium"

            is_in_cycle = dep.name in cycle_nodes

            nodes.append({
                "id": dep.name,
                "group": dep.ecosystem,
                "vulnerabilities": vuln_count,
                "risk": risk,
                "is_cycle": is_in_cycle,
            })

        if dep_tree is not None:
            for node_name in self._extract_node_names(dep_tree):
                if node_name in seen:
                    continue
                seen.add(node_name)
                is_in_cycle = node_name in cycle_nodes
                nodes.append({
                    "id": node_name,
                    "group": "npm",
                    "vulnerabilities": 0,
                    "risk": "low",
                    "is_cycle": is_in_cycle,
                })

        links = []
        if dep_tree is not None:
            raw_links = self._extract_links(dep_tree)
            for link in raw_links:
                is_cycle_edge = (link["source"], link["target"]) in cycle_edges
                link["is_cycle"] = is_cycle_edge
                links.append(link)

        return {"nodes": nodes, "links": links}

    def _extract_links(self, tree: dict, parent: str | None = None) -> list[dict]:
        links = []
        for name, subtree in tree.items():
            clean_name = name.lstrip("⟳↩ ").strip()
            if parent is not None:
                links.append({"source": parent, "target": clean_name})
            if subtree:
                links.extend(self._extract_links(subtree, clean_name))
        return links

    def _extract_node_names(self, tree: dict) -> set[str]:
        names: set[str] = set()
        for name, subtree in tree.items():
            clean_name = name.lstrip("⟳↩ ").strip()
            names.add(clean_name)
            if subtree:
                names.update(self._extract_node_names(subtree))
        return names

    def _collect_deps(
        self,
        vuln_results: list[VulnerabilityResult],
        license_results: list[LicenseResult],
        outdated_results: list[OutdatedResult],
    ) -> list[Dependency]:
        seen: set[str] = set()
        deps: list[Dependency] = []

        for result in vuln_results:
            if result.dependency.name not in seen:
                seen.add(result.dependency.name)
                dep = result.dependency
                dep._vuln_count = len(result.vulnerabilities)
                deps.append(dep)

        for result in license_results:
            if result.dependency.name not in seen:
                seen.add(result.dependency.name)
                deps.append(result.dependency)

        for result in outdated_results:
            if result.dependency.name not in seen:
                seen.add(result.dependency.name)
                deps.append(result.dependency)

        return deps
