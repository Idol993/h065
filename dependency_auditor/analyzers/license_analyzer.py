from dataclasses import dataclass

from dependency_auditor.parsers.python_parser import Dependency

HIGH_RISK = frozenset({
    "GPL-2.0", "GPL-3.0", "AGPL-3.0",
    "GPL-2.0-only", "GPL-3.0-only", "AGPL-3.0-only",
    "SSPL-1.0", "RPL-1.1", "RPL-1.5", "OSL-3.0",
})

MEDIUM_RISK = frozenset({
    "LGPL-2.0", "LGPL-2.1", "LGPL-3.0",
    "MPL-2.0", "EPL-1.0", "EPL-2.0",
    "CDDL-1.0", "CDDL-1.1", "CPL-1.0",
})

LOW_RISK = frozenset({
    "MIT", "Apache-2.0", "BSD-2-Clause", "BSD-3-Clause",
    "0BSD", "ISC", "Unlicense", "PSF-2.0", "Python-2.0",
})

_LICENSE_ALIASES: dict[str, str] = {
    "gpl-2.0": "GPL-2.0",
    "gplv2": "GPL-2.0",
    "gpl v2": "GPL-2.0",
    "gpl-3.0": "GPL-3.0",
    "gplv3": "GPL-3.0",
    "gpl v3": "GPL-3.0",
    "agpl-3.0": "AGPL-3.0",
    "agplv3": "AGPL-3.0",
    "gpl-2.0-only": "GPL-2.0-only",
    "gpl-3.0-only": "GPL-3.0-only",
    "agpl-3.0-only": "AGPL-3.0-only",
    "sspl-1.0": "SSPL-1.0",
    "rpl-1.1": "RPL-1.1",
    "rpl-1.5": "RPL-1.5",
    "osl-3.0": "OSL-3.0",
    "lgpl-2.0": "LGPL-2.0",
    "lgpl-2.1": "LGPL-2.1",
    "lgpl-3.0": "LGPL-3.0",
    "mpl-2.0": "MPL-2.0",
    "epl-1.0": "EPL-1.0",
    "epl-2.0": "EPL-2.0",
    "cddl-1.0": "CDDL-1.0",
    "cddl-1.1": "CDDL-1.1",
    "cpl-1.0": "CPL-1.0",
    "mit": "MIT",
    "apache-2.0": "Apache-2.0",
    "apache2": "Apache-2.0",
    "apache 2.0": "Apache-2.0",
    "bsd-2-clause": "BSD-2-Clause",
    "bsd-3-clause": "BSD-3-Clause",
    "0bsd": "0BSD",
    "isc": "ISC",
    "unlicense": "Unlicense",
    "psf-2.0": "PSF-2.0",
    "python-2.0": "Python-2.0",
}


@dataclass
class LicenseRisk:
    license_id: str
    license_name: str
    risk_level: str
    is_copyleft: bool


@dataclass
class LicenseResult:
    dependency: Dependency
    licenses: list[LicenseRisk]
    has_copyleft: bool


class LicenseAnalyzer:

    def analyze(self, deps: list[Dependency]) -> list[LicenseResult]:
        results: list[LicenseResult] = []
        for dep in deps:
            license_risks = self._extract_licenses(dep)
            has_copyleft = any(lr.is_copyleft for lr in license_risks)
            results.append(LicenseResult(
                dependency=dep,
                licenses=license_risks,
                has_copyleft=has_copyleft,
            ))
        return results

    def _extract_licenses(self, dep: Dependency) -> list[LicenseRisk]:
        license_strs: list[str] = []
        oss_licenses = getattr(dep, "_oss_licenses", None)
        if oss_licenses and isinstance(oss_licenses, list):
            for entry in oss_licenses:
                if isinstance(entry, dict):
                    lid = entry.get("licenseId") or entry.get("id")
                    if lid:
                        license_strs.append(str(lid))
                elif isinstance(entry, str):
                    license_strs.append(entry)

        if not license_strs:
            license_strs = self._heuristic_licenses(dep)

        return [self._identify_license(ls) for ls in license_strs]

    def _heuristic_licenses(self, dep: Dependency) -> list[str]:
        name_lower = dep.name.lower()
        if "django" in name_lower:
            return ["BSD-3-Clause"]
        if "flask" in name_lower:
            return ["BSD-3-Clause"]
        if "requests" in name_lower:
            return ["Apache-2.0"]
        if "numpy" in name_lower:
            return ["BSD-3-Clause"]
        if "pillow" in name_lower:
            return ["MIT"]
        return ["UNKNOWN"]

    def _identify_license(self, license_str: str) -> LicenseRisk:
        normalized = license_str.strip().lower()

        canonical = _LICENSE_ALIASES.get(normalized)
        if canonical is None:
            for canonical_id in HIGH_RISK:
                if normalized == canonical_id.lower():
                    canonical = canonical_id
                    break
            if canonical is None:
                for canonical_id in MEDIUM_RISK:
                    if normalized == canonical_id.lower():
                        canonical = canonical_id
                        break
            if canonical is None:
                for canonical_id in LOW_RISK:
                    if normalized == canonical_id.lower():
                        canonical = canonical_id
                        break

        if canonical is None:
            return LicenseRisk(
                license_id=license_str.strip(),
                license_name=license_str.strip(),
                risk_level="medium",
                is_copyleft=False,
            )

        if canonical in HIGH_RISK:
            return LicenseRisk(
                license_id=canonical,
                license_name=canonical,
                risk_level="high",
                is_copyleft=True,
            )

        if canonical in MEDIUM_RISK:
            return LicenseRisk(
                license_id=canonical,
                license_name=canonical,
                risk_level="medium",
                is_copyleft=True,
            )

        return LicenseRisk(
            license_id=canonical,
            license_name=canonical,
            risk_level="low",
            is_copyleft=False,
        )
