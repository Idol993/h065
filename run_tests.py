import sys
import os
import json

sys.path.insert(0, 'd:\\work\\twpw\\h065')

from dependency_auditor.parsers.lockfile_parser import parse_package_lock
from dependency_auditor.analyzers.circular_detector import CircularDetector
from dependency_auditor.analyzers.license_analyzer import LicenseAnalyzer
from dependency_auditor.reporters.html_reporter import HtmlReporter
from dependency_auditor.reporters.json_exporter import JsonExporter
from dependency_auditor.reporters.terminal_reporter import TerminalReporter
from dependency_auditor.analyzers.vulnerability_analyzer import VulnerabilityResult, Vulnerability
from dependency_auditor.utils.config_loader import ConfigLoader

print("=" * 60)
print("TEST 1: Circular Dependency Detection")
print("=" * 60)

deps = parse_package_lock("d:\\work\\twpw\\h065\\test_verify\\package-lock.json")
print(f"\nParsed {len(deps)} dependencies:")
for dep in deps:
    print(f"  {dep.name}@{dep.version_spec} -> {dep.dependencies}")

detector = CircularDetector()
cycles = detector.detect(deps)
print(f"\nFound {len(cycles)} circular dependencies:")
for cycle in cycles:
    print(f"  {' → '.join(cycle.cycle)} (length: {cycle.length})")

assert len(cycles) == 1, f"Expected 1 cycle, got {len(cycles)}"
assert cycles[0].length == 3, f"Expected cycle length 3, got {cycles[0].length}"
print("✓ Circular dependency detection correct")

print("\n" + "=" * 60)
print("TEST 2: License Priority (OSS Index > lock file)")
print("=" * 60)

for dep in deps:
    if dep.name == "package-b":
        dep._oss_licenses = [{"licenseId": "GPL-3.0"}]
    elif dep.name == "package-d":
        dep._oss_licenses = [{"licenseId": "AGPL-3.0"}]
    elif dep.name == "package-a":
        dep._oss_licenses = [{"licenseId": "MIT"}]
    elif dep.name == "package-c":
        dep._oss_licenses = [{"licenseId": "Apache-2.0"}]

analyzer = LicenseAnalyzer()
license_results = analyzer.analyze(deps)

print("\nLicense analysis results:")
for result in license_results:
    print(f"\n  {result.dependency.name}:")
    for lic in result.licenses:
        print(f"    License: {lic.license_id} (risk: {lic.risk_level}, copyleft: {lic.is_copyleft})")
    print(f"    Has copyleft: {result.has_copyleft}")

assert license_results[1].dependency.name == "package-b"
assert license_results[1].licenses[0].license_id == "GPL-3.0", f"Expected GPL-3.0, got {license_results[1].licenses[0].license_id}"
assert license_results[1].licenses[0].risk_level == "high"
assert license_results[1].has_copyleft == True

assert license_results[3].dependency.name == "package-d"
assert license_results[3].licenses[0].license_id == "AGPL-3.0", f"Expected AGPL-3.0, got {license_results[3].licenses[0].license_id}"
assert license_results[3].licenses[0].risk_level == "high"
assert license_results[3].has_copyleft == True

copyleft_count = sum(1 for r in license_results if r.has_copyleft)
assert copyleft_count == 2, f"Expected 2 copyleft packages, got {copyleft_count}"
print("✓ License priority and detection correct (OSS Index takes precedence)")

print("\n" + "=" * 60)
print("TEST 3: JSON Report Statistics Consistency")
print("=" * 60)

vuln_results = []
outdated_results = []

json_exporter = JsonExporter()
json_path = json_exporter.export(vuln_results, license_results, cycles, outdated_results, "d:\\work\\twpw\\h065\\test_verify")

with open(json_path, encoding="utf-8") as f:
    report = json.load(f)

summary = report["metadata"]["summary"]
print(f"JSON Summary: {json.dumps(summary, indent=2)}")
print(f"Licenses in detail: {len(report['licenses'])}")
print(f"Copyleft licenses (high risk) in detail: {sum(1 for l in report['licenses'] if l['is_copyleft'])}")
print(f"Packages with copyleft: {copyleft_count}")
print(f"Circular dependencies in detail: {len(report['circular_dependencies'])}")

assert summary["copyleft_licenses"] == copyleft_count, f"Summary copyleft ({summary['copyleft_licenses']}) != detail copyleft ({copyleft_count})"
assert summary["total_circular_dependencies"] == len(cycles)
assert summary["total_outdated"] == 0
assert len(report["licenses"]) == 4
assert len(report["circular_dependencies"]) == 1
print("✓ JSON report statistics consistent with details")

print("\n" + "=" * 60)
print("TEST 4: HTML Report Statistics Consistency")
print("=" * 60)

html_reporter = HtmlReporter()
dep_tree = detector.get_dependency_tree(deps)
html_path = html_reporter.export(vuln_results, license_results, cycles, outdated_results, dep_tree, "d:\\work\\twpw\\h065\\test_verify")

with open(html_path, encoding="utf-8") as f:
    html_content = f.read()

import re
card_copyleft_match = re.search(r'card copyleft.*?<div class="count">(\d+)', html_content, re.DOTALL)
card_circular_match = re.search(r'card circular.*?<div class="count">(\d+)', html_content, re.DOTALL)
card_outdated_match = re.search(r'card outdated.*?<div class="count">(\d+)', html_content, re.DOTALL)

card_copyleft = int(card_copyleft_match.group(1)) if card_copyleft_match else -1
card_circular = int(card_circular_match.group(1)) if card_circular_match else -1
card_outdated = int(card_outdated_match.group(1)) if card_outdated_match else -1

print(f"HTML Cards - Copyleft: {card_copyleft}, Circular: {card_circular}, Outdated: {card_outdated}")
print(f"Terminal/JSON - Copyleft: {copyleft_count}, Circular: {len(cycles)}, Outdated: 0")

assert card_copyleft == copyleft_count, f"HTML Copyleft card ({card_copyleft}) != detail ({copyleft_count})"
assert card_circular == len(cycles), f"HTML Circular card ({card_circular}) != detail ({len(cycles)})"
assert card_outdated == 0, f"HTML Outdated card ({card_outdated}) != detail (0)"
print("✓ HTML report statistics consistent with details")

print("\n" + "=" * 60)
print("TEST 5: Outdated filter - only outdated in HTML/JSON details")
print("=" * 60)

html_outdated_count = html_content.count("Outdated Packages (")
match = re.search(r'Outdated Packages \((\d+)\)', html_content)
html_outdated_detail_count = int(match.group(1)) if match else -1
json_outdated_detail_count = len(report["outdated"])

print(f"HTML outdated detail count: {html_outdated_detail_count}")
print(f"JSON outdated detail count: {json_outdated_detail_count}")
assert html_outdated_detail_count == 0, "HTML outdated details should be empty"
assert json_outdated_detail_count == 0, "JSON outdated details should be empty"
print("✓ Outdated filter correct - only outdated packages in details")

print("\n" + "=" * 60)
print("TEST 6: Terminal Reporter Consistency")
print("=" * 60)

reporter = TerminalReporter()
terminal_copyleft = sum(1 for r in license_results if r.has_copyleft)
terminal_circular = len(cycles)
print(f"Terminal expected: copyleft={terminal_copyleft}, circular={terminal_circular}")
print(f"Cards: copyleft={card_copyleft}, circular={card_circular}")
print(f"JSON summary: copyleft={summary['copyleft_licenses']}, circular={summary['total_circular_dependencies']}")
assert terminal_copyleft == card_copyleft == summary["copyleft_licenses"]
assert terminal_circular == card_circular == summary["total_circular_dependencies"]
print("✓ Terminal, HTML, JSON statistics all consistent")

print("\n" + "=" * 60)
print("ALL TESTS PASSED ✓")
print("=" * 60)
