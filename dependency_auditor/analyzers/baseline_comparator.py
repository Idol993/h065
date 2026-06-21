from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any

from dependency_auditor.analyzers.policy_engine import PolicyViolation


@dataclass
class BaselineDiff:
    new_violations: list[PolicyViolation] = field(default_factory=list)
    existing_violations: list[PolicyViolation] = field(default_factory=list)
    fixed_violations: list[dict] = field(default_factory=list)


class BaselineComparator:
    def __init__(self, baseline_path: str):
        self.baseline_path = baseline_path
        self._baseline_data = self._load_baseline()

    def _load_baseline(self) -> dict:
        try:
            with open(self.baseline_path, "r", encoding="utf-8") as f:
                return json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            return {}

    def _violation_key(self, v: PolicyViolation | dict) -> str:
        if isinstance(v, dict):
            pkg = v.get("package", "")
            vtype = v.get("type", "")
            details = v.get("details", {})
        else:
            pkg = v.package
            vtype = v.type
            details = v.details

        if vtype == "vulnerability":
            cve = details.get("cve_id", "")
            return f"{vtype}:{pkg}:{cve}"
        elif vtype == "copyleft_license":
            lic = details.get("license_id", "")
            return f"{vtype}:{pkg}:{lic}"
        elif vtype == "circular_dependency":
            cycle = details.get("cycle", [])
            return f"{vtype}:{','.join(sorted(cycle))}"
        elif vtype == "outdated_package":
            return f"{vtype}:{pkg}"
        else:
            return f"{vtype}:{pkg}"

    def compare(self, violations: list[PolicyViolation]) -> BaselineDiff:
        baseline_violations = self._baseline_data.get("violations", [])
        baseline_keys = {self._violation_key(bv): bv for bv in baseline_violations}

        new_violations: list[PolicyViolation] = []
        existing_violations: list[PolicyViolation] = []
        seen_current_keys: set[str] = set()

        for v in violations:
            key = self._violation_key(v)
            seen_current_keys.add(key)
            if key in baseline_keys:
                existing_violations.append(v)
            else:
                new_violations.append(v)

        fixed_violations: list[dict] = []
        for key, bv in baseline_keys.items():
            if key not in seen_current_keys:
                fixed_violations.append(bv)

        return BaselineDiff(
            new_violations=new_violations,
            existing_violations=existing_violations,
            fixed_violations=fixed_violations,
        )
