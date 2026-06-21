import json
import os
from datetime import datetime

from jinja2 import Environment, FileSystemLoader

from dependency_auditor.analyzers.circular_detector import CircularDependency
from dependency_auditor.analyzers.license_analyzer import LicenseResult
from dependency_auditor.analyzers.outdated_checker import OutdatedResult
from dependency_auditor.analyzers.vulnerability_analyzer import VulnerabilityResult
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
            outdated_data.append({
                "package": r.dependency.name,
                "current": r.current_version,
                "latest": r.latest_version,
                "ecosystem": r.ecosystem,
            })

        all_deps = self._collect_deps(vuln_results, license_results, outdated_results)
        graph_data = self._build_graph_data(all_deps, dep_tree)

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
            "copyleft_licenses": sum(1 for ld in license_data if ld["is_copyleft"]),
            "total_circular_dependencies": len(circular_data),
            "total_outdated": sum(
                1 for r in outdated_results if r.is_outdated
            ),
        }

        template = self.env.get_template("report.html")
        timestamp = datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")

        html_content = template.render(
            vulnerability_data=vulnerability_data,
            license_data=license_data,
            circular_data=circular_data,
            outdated_data=outdated_data,
            graph_data=json.dumps(graph_data),
            summary=summary,
            timestamp=timestamp,
        )

        os.makedirs(output_dir, exist_ok=True)
        filename = f"dependency_audit_{timestamp}.html"
        output_path = os.path.join(output_dir, filename)

        with open(output_path, "w", encoding="utf-8") as f:
            f.write(html_content)

        return output_path

    def _build_graph_data(
        self,
        deps: list[Dependency],
        dep_tree: dict | None,
    ) -> dict:
        nodes = []
        seen: set[str] = set()

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

            nodes.append({
                "id": dep.name,
                "group": dep.ecosystem,
                "vulnerabilities": vuln_count,
                "risk": risk,
            })

        links = []
        if dep_tree is not None:
            links = self._extract_links(dep_tree)

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
