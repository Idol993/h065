import os
import sys
from pathlib import Path

import click
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn
from rich.panel import Panel

from dependency_auditor.parsers.python_parser import Dependency, parse as py_parse
from dependency_auditor.parsers.node_parser import parse as node_parse
from dependency_auditor.parsers.java_parser import parse as java_parse
from dependency_auditor.parsers.lockfile_parser import parse as lock_parse
from dependency_auditor.analyzers.vulnerability_analyzer import VulnerabilityAnalyzer, classify_severity
from dependency_auditor.analyzers.license_analyzer import LicenseAnalyzer
from dependency_auditor.analyzers.circular_detector import CircularDetector
from dependency_auditor.analyzers.outdated_checker import OutdatedChecker
from dependency_auditor.analyzers.policy_engine import PolicyEngine, PolicyResult
from dependency_auditor.analyzers.baseline_comparator import BaselineComparator, BaselineDiff
from dependency_auditor.reporters.terminal_reporter import TerminalReporter
from dependency_auditor.reporters.html_reporter import HtmlReporter
from dependency_auditor.reporters.json_exporter import JsonExporter
from dependency_auditor.utils.config_loader import ConfigLoader


console = Console()


SUPPORTED_FILES = {
    "requirements.txt": "python",
    "pyproject.toml": "python",
    "package.json": "node",
    "pom.xml": "java",
    "build.gradle": "java",
    "Pipfile.lock": "python_lock",
    "package-lock.json": "node_lock",
    "yarn.lock": "node_lock",
}


def _discover_files(project_dir: str) -> list[tuple[str, str]]:
    results = []
    project_path = Path(project_dir)
    if not project_path.is_dir():
        if project_path.is_file():
            name = project_path.name
            ftype = SUPPORTED_FILES.get(name, "")
            if ftype:
                return [(str(project_path), ftype)]
            console.print(f"[yellow]Unsupported file: {name}[/yellow]")
            return []
        console.print(f"[red]Path not found: {project_dir}[/red]")
        return []

    for root, dirs, files in os.walk(project_dir):
        dirs[:] = [d for d in dirs if d not in {".git", "node_modules", ".venv", "venv", "__pycache__", ".tox", ".mypy_cache"}]
        for fname in files:
            ftype = SUPPORTED_FILES.get(fname, "")
            if ftype:
                results.append((os.path.join(root, fname), ftype))

    return results


def _parse_file(filepath: str, ftype: str) -> list[Dependency]:
    if ftype == "python":
        return py_parse(filepath)
    elif ftype == "node":
        return node_parse(filepath)
    elif ftype == "java":
        return java_parse(filepath)
    elif ftype in ("python_lock", "node_lock"):
        return lock_parse(filepath)
    return []


def _parse_all(project_dir: str, include_dev: bool = False) -> list[Dependency]:
    files = _discover_files(project_dir)
    if not files:
        console.print("[yellow]No dependency files found.[/yellow]")
        return []

    all_deps: list[Dependency] = []
    seen: set[str] = set()

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        TimeElapsedColumn(),
        console=console,
    ) as progress:
        task = progress.add_task("Parsing dependency files...", total=len(files))
        for filepath, ftype in files:
            progress.update(task, description=f"Parsing {Path(filepath).name}")
            deps = _parse_file(filepath, ftype)
            for dep in deps:
                if not include_dev and dep.is_dev:
                    continue
                key = f"{dep.ecosystem}:{dep.name}:{dep.version_spec}"
                if key not in seen:
                    seen.add(key)
                    all_deps.append(dep)
            progress.advance(task)

    return all_deps


def _run_analyses(deps, cfg, no_vuln, no_license, no_circular, no_outdated):
    vuln_results = []
    license_results = []
    cycles = []
    outdated_results = []

    if not no_vuln:
        console.print("[bold cyan]▸ Scanning vulnerabilities...[/bold cyan]")
        analyzer = VulnerabilityAnalyzer(cfg)
        vuln_results = analyzer.analyze(deps)

    if not no_license:
        console.print("[bold cyan]▸ Analyzing licenses...[/bold cyan]")
        license_analyzer = LicenseAnalyzer()
        license_results = license_analyzer.analyze(deps)

    if not no_circular:
        console.print("[bold cyan]▸ Detecting circular dependencies...[/bold cyan]")
        detector = CircularDetector()
        cycles = detector.detect(deps)

    if not no_outdated:
        console.print("[bold cyan]▸ Checking outdated dependencies...[/bold cyan]")
        checker = OutdatedChecker(cfg)
        outdated_results = checker.check(deps)

    return vuln_results, license_results, cycles, outdated_results


def _apply_policy(cfg, vuln_results, license_results, cycles, outdated_results):
    policy_engine = PolicyEngine(cfg)
    return policy_engine.apply(vuln_results, license_results, cycles, outdated_results)


def _compare_baseline(baseline_path, policy_result):
    if not baseline_path:
        return None
    comparator = BaselineComparator(baseline_path)
    return comparator.compare(policy_result.violations)


def _print_diff_summary(diff: BaselineDiff):
    if not diff:
        return
    lines = []
    if diff.new_violations:
        lines.append(f"[#ff0080]⚠️  New violations: {len(diff.new_violations)}[/#ff0080]")
    if diff.existing_violations:
        lines.append(f"[#ffaa00]🔶 Existing violations: {len(diff.existing_violations)}[/#ffaa00]")
    if diff.fixed_violations:
        lines.append(f"[#00cc88]✅ Fixed violations: {len(diff.fixed_violations)}[/#00cc88]")
    if lines:
        console.print(Panel("\n".join(lines), title="Baseline Comparison", border_style="bold"))


@click.group()
@click.version_option(version="1.0.0", prog_name="dep-audit")
def cli():
    pass


@cli.command()
@click.argument("project_dir", default=".")
@click.option("--include-dev", is_flag=True, help="Include dev dependencies")
@click.option("--config", default=None, help="Path to config YAML file")
@click.option("--no-vuln", is_flag=True, help="Skip vulnerability analysis")
@click.option("--no-license", is_flag=True, help="Skip license analysis")
@click.option("--no-circular", is_flag=True, help="Skip circular dependency detection")
@click.option("--no-outdated", is_flag=True, help="Skip outdated dependency check")
@click.option("--html", is_flag=True, help="Generate HTML report")
@click.option("--json", "json_output", is_flag=True, help="Generate JSON report")
@click.option("--output-dir", default=".", help="Output directory for reports")
@click.option("--baseline", default=None, help="Path to baseline JSON report for diff comparison")
def audit(project_dir, include_dev, config, no_vuln, no_license, no_circular, no_outdated, html, json_output, output_dir, baseline):
    """Full dependency audit: vulnerabilities, licenses, circular deps, outdated checks."""
    cfg = ConfigLoader(config)
    reporter = TerminalReporter(console)

    deps = _parse_all(project_dir, include_dev)
    if not deps:
        console.print("[yellow]No dependencies found to audit.[/yellow]")
        sys.exit(0)

    console.print(f"\n[bold]Found {len(deps)} dependencies[/bold]\n")

    vuln_results, license_results, cycles, outdated_results = _run_analyses(
        deps, cfg, no_vuln, no_license, no_circular, no_outdated
    )

    policy_result = _apply_policy(cfg, vuln_results, license_results, cycles, outdated_results)

    fv = policy_result.filtered_vulns
    fl = policy_result.filtered_licenses
    fc = policy_result.filtered_cycles
    fo = policy_result.filtered_outdated

    diff = _compare_baseline(baseline, policy_result)
    if diff:
        _print_diff_summary(diff)

    if not no_vuln:
        reporter.report_vulnerabilities(fv)
    if not no_license:
        reporter.report_licenses(fl)
    if not no_circular:
        reporter.report_circular(fc)
    if not no_outdated:
        reporter.report_outdated(fo)

    reporter.print_summary(fv, fl, fc, fo)

    dep_tree = None
    if not no_circular:
        detector = CircularDetector()
        dep_tree = detector.get_dependency_tree(deps, cfg.max_depth)

    if html:
        html_reporter = HtmlReporter()
        path = html_reporter.export(fv, fl, fc, fo, dep_tree, output_dir, policy_result, diff, cfg.to_dict())
        console.print(f"\n[green]HTML report saved: {path}[/green]")

    if json_output:
        json_exporter = JsonExporter()
        path = json_exporter.export(fv, fl, fc, fo, output_dir, policy_result, diff, cfg.to_dict())
        console.print(f"[green]JSON report saved: {path}[/green]")

    exit_code = _determine_exit_code(policy_result, cfg, diff)
    sys.exit(exit_code)


@cli.command()
@click.argument("project_dir", default=".")
@click.option("--include-dev", is_flag=True, help="Include dev dependencies")
@click.option("--config", default=None, help="Path to config YAML file")
@click.option("--html", is_flag=True, help="Generate HTML report")
@click.option("--json", "json_output", is_flag=True, help="Generate JSON report")
@click.option("--output-dir", default=".", help="Output directory for reports")
@click.option("--baseline", default=None, help="Path to baseline JSON report for diff comparison")
def licenses(project_dir, include_dev, config, html, json_output, output_dir, baseline):
    """Analyze dependency licenses for copyleft risks."""
    cfg = ConfigLoader(config)
    deps = _parse_all(project_dir, include_dev)
    if not deps:
        console.print("[yellow]No dependencies found.[/yellow]")
        sys.exit(0)

    console.print("[bold cyan]▸ Fetching license info from OSS Index...[/bold cyan]")
    vuln_analyzer = VulnerabilityAnalyzer(cfg)
    vuln_results = vuln_analyzer.analyze(deps)

    analyzer = LicenseAnalyzer()
    license_results = analyzer.analyze(deps)

    policy_result = _apply_policy(cfg, vuln_results, license_results, [], [])

    fv = policy_result.filtered_vulns
    fl = policy_result.filtered_licenses
    fc = policy_result.filtered_cycles
    fo = policy_result.filtered_outdated

    diff = _compare_baseline(baseline, policy_result)
    if diff:
        _print_diff_summary(diff)

    reporter = TerminalReporter(console)
    reporter.report_licenses(fl)

    if html:
        html_reporter = HtmlReporter()
        path = html_reporter.export(fv, fl, fc, fo, None, output_dir, policy_result, diff, cfg.to_dict())
        console.print(f"\n[green]HTML report saved: {path}[/green]")

    if json_output:
        json_exporter = JsonExporter()
        path = json_exporter.export(fv, fl, fc, fo, output_dir, policy_result, diff, cfg.to_dict())
        console.print(f"[green]JSON report saved: {path}[/green]")

    exit_code = _determine_exit_code(policy_result, cfg, diff)
    sys.exit(exit_code)


@cli.command()
@click.argument("project_dir", default=".")
@click.option("--include-dev", is_flag=True, help="Include dev dependencies")
@click.option("--config", default=None, help="Path to config YAML file")
@click.option("--max-depth", default=5, help="Max tree depth")
def graph(project_dir, include_dev, config, max_depth):
    """Display dependency tree and detect circular dependencies."""
    cfg = ConfigLoader(config)
    deps = _parse_all(project_dir, include_dev)
    if not deps:
        console.print("[yellow]No dependencies found.[/yellow]")
        sys.exit(0)

    detector = CircularDetector()
    cycles = detector.detect(deps)

    policy_result = _apply_policy(cfg, [], [], cycles, [])
    fc = policy_result.filtered_cycles

    reporter = TerminalReporter(console)
    reporter.report_circular(fc)

    console.print("\n[bold cyan]Dependency Tree:[/bold cyan]")
    tree = detector.get_dependency_tree(deps, max_depth)
    reporter.report_dependency_tree(tree, max_depth)

    exit_code = _determine_exit_code(policy_result, cfg, None)
    sys.exit(exit_code)


@cli.command()
@click.argument("project_dir", default=".")
@click.option("--include-dev", is_flag=True, help="Include dev dependencies")
@click.option("--config", default=None, help="Path to config YAML file")
@click.option("--html", is_flag=True, help="Generate HTML report")
@click.option("--json", "json_output", is_flag=True, help="Generate JSON report")
@click.option("--output-dir", default=".", help="Output directory for reports")
@click.option("--baseline", default=None, help="Path to baseline JSON report for diff comparison")
def report(project_dir, include_dev, config, html, json_output, output_dir, baseline):
    """Generate audit reports (terminal + optional HTML/JSON)."""
    cfg = ConfigLoader(config)
    deps = _parse_all(project_dir, include_dev)
    if not deps:
        console.print("[yellow]No dependencies found.[/yellow]")
        sys.exit(0)

    console.print(f"\n[bold]Found {len(deps)} dependencies[/bold]\n")

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        progress.add_task(description="Scanning vulnerabilities...", total=None)
        vuln_analyzer = VulnerabilityAnalyzer(cfg)
        vuln_results = vuln_analyzer.analyze(deps)

        progress.add_task(description="Analyzing licenses...", total=None)
        license_analyzer = LicenseAnalyzer()
        license_results = license_analyzer.analyze(deps)

        progress.add_task(description="Detecting circular deps...", total=None)
        detector = CircularDetector()
        cycles = detector.detect(deps)

        progress.add_task(description="Checking outdated deps...", total=None)
        checker = OutdatedChecker(cfg)
        outdated_results = checker.check(deps)

    policy_result = _apply_policy(cfg, vuln_results, license_results, cycles, outdated_results)

    fv = policy_result.filtered_vulns
    fl = policy_result.filtered_licenses
    fc = policy_result.filtered_cycles
    fo = policy_result.filtered_outdated

    diff = _compare_baseline(baseline, policy_result)
    if diff:
        _print_diff_summary(diff)

    dep_tree = detector.get_dependency_tree(deps, cfg.max_depth)

    reporter = TerminalReporter(console)
    reporter.report_vulnerabilities(fv)
    reporter.report_licenses(fl)
    reporter.report_circular(fc)
    reporter.report_outdated(fo)
    reporter.print_summary(fv, fl, fc, fo)

    if html:
        html_reporter = HtmlReporter()
        path = html_reporter.export(fv, fl, fc, fo, dep_tree, output_dir, policy_result, diff, cfg.to_dict())
        console.print(f"\n[green]HTML report saved: {path}[/green]")

    if json_output:
        json_exporter = JsonExporter()
        path = json_exporter.export(fv, fl, fc, fo, output_dir, policy_result, diff, cfg.to_dict())
        console.print(f"[green]JSON report saved: {path}[/green]")

    exit_code = _determine_exit_code(policy_result, cfg, diff)
    sys.exit(exit_code)


def _determine_exit_code(policy_result: PolicyResult, config: ConfigLoader, diff: BaselineDiff | None) -> int:
    violations_for_exit = policy_result.violations

    if diff is not None:
        violations_for_exit = diff.new_violations
        console.print(f"[dim]CI exit code based on {len(violations_for_exit)} new violations only[/dim]")

    high_vulns = 0
    has_copyleft = False
    has_circular = False
    has_outdated = False

    for v in violations_for_exit:
        if v.type == "vulnerability":
            sev = v.severity.lower()
            if sev in ("high", "critical"):
                high_vulns += 1
        elif v.type == "copyleft_license":
            has_copyleft = True
        elif v.type == "circular_dependency":
            has_circular = True
        elif v.type == "outdated_package":
            has_outdated = True

    if high_vulns > 0 and config.fail_on_high_vulnerability:
        return 1
    if has_circular and config.fail_on_circular_dependency:
        return 2
    if has_copyleft and config.fail_on_copyleft_license:
        return 3
    if has_outdated and config.fail_on_outdated:
        return 4

    return 0


if __name__ == "__main__":
    cli()
