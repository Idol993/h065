import time
from dataclasses import dataclass

import requests

from dependency_auditor.parsers.python_parser import Dependency
from dependency_auditor.utils.config_loader import ConfigLoader
from dependency_auditor.utils.version_comparer import compare_versions, parse_version, version_to_str


@dataclass
class OutdatedResult:
    dependency: Dependency
    current_version: str
    latest_version: str
    is_outdated: bool
    ecosystem: str


class OutdatedChecker:
    def __init__(self, config: ConfigLoader):
        self.config = config

    def check(self, deps: list[Dependency]) -> list[OutdatedResult]:
        results: list[OutdatedResult] = []
        by_ecosystem: dict[str, list[Dependency]] = {}
        for dep in deps:
            by_ecosystem.setdefault(dep.ecosystem, []).append(dep)

        for ecosystem, ecosystem_deps in by_ecosystem.items():
            for dep in ecosystem_deps:
                latest = self._get_latest(ecosystem, dep)
                if latest is None:
                    results.append(OutdatedResult(
                        dependency=dep,
                        current_version=dep.version_spec,
                        latest_version="",
                        is_outdated=False,
                        ecosystem=ecosystem,
                    ))
                else:
                    current_ver = parse_version(dep.version_spec.lstrip("=<>~^!"))
                    latest_ver = parse_version(latest)
                    is_outdated = compare_versions(current_ver, latest_ver) < 0
                    results.append(OutdatedResult(
                        dependency=dep,
                        current_version=dep.version_spec,
                        latest_version=latest,
                        is_outdated=is_outdated,
                        ecosystem=ecosystem,
                    ))
                time.sleep(0.05)

        return results

    def _get_latest(self, ecosystem: str, dep: Dependency) -> str | None:
        if ecosystem == "pypi":
            return self._check_pypi(dep.name)
        if ecosystem == "npm":
            return self._check_npm(dep.name)
        if ecosystem == "maven":
            parts = dep.name.split(":", 1)
            if len(parts) == 2:
                return self._check_maven(parts[0], parts[1])
            return self._check_maven(parts[0], parts[0])
        return None

    def _check_pypi(self, name: str) -> str | None:
        pypi_api_url = self.config.get("pypi_api_url", "https://pypi.org/pypi")
        try:
            resp = requests.get(f"{pypi_api_url}/{name}/json", timeout=10)
            resp.raise_for_status()
            data = resp.json()
            return data.get("info", {}).get("version")
        except requests.RequestException:
            return None

    def _check_npm(self, name: str) -> str | None:
        npm_api_url = self.config.get("npm_api_url", "https://registry.npmjs.org")
        try:
            resp = requests.get(f"{npm_api_url}/{name}", timeout=10)
            resp.raise_for_status()
            data = resp.json()
            dist_tags = data.get("dist-tags", {})
            return dist_tags.get("latest")
        except requests.RequestException:
            return None

    def _check_maven(self, group_id: str, artifact_id: str) -> str | None:
        maven_api_url = self.config.get(
            "maven_api_url",
            "https://search.maven.org/solrsearch/select",
        )
        try:
            params = {
                "q": f"a:{artifact_id}+AND+g:{group_id}",
                "core": "gav",
                "rows": 1,
                "wt": "json",
            }
            resp = requests.get(maven_api_url, params=params, timeout=10)
            resp.raise_for_status()
            data = resp.json()
            docs = data.get("response", {}).get("docs", [])
            if not docs:
                return None
            doc = docs[0]
            return doc.get("latestVersion") or doc.get("v")
        except requests.RequestException:
            return None
