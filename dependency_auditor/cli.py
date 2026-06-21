import os
import sys
from pathlib import Path

import click
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn

from dependency_auditor.parsers.python_parser import Dependency, parse as py_parse
from dependency_auditor.parsers.node_parser import parse as node_parse
from dependency_auditor.parsers.java_parser import parse as java_parse
from dependency_auditor.parsers.lockfile_parser import parse as lock_parse
from dependency_auditor.analyzers.vulnerability_analyzer import VulnerabilityAnalyzer, classify_severity
from dependency_auditor.analyzers.license_analyzer import LicenseAnalyzer
from dependency_auditor.analyzers.circular_detector import CircularDetector
from dependency_auditor.analyzers.outdated_checker import OutdatedChecker
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
def audit(project_dir, include_dev, config, no_vuln, no_license, no_circular, no_outdated, html, json_output, output_dir):
    """Full dependency audit: vulnerabilities, licenses, circular deps, outdated checks."""
    cfg = ConfigLoader(config)
    reporter = TerminalReporter(console)

    deps = _parse_all(project_dir, include_dev)
    if not deps:
        console.print("[yellow]No dependencies found to audit.[/yellow]")
        sys.exit(0)

    console.print(f"\n[bold]Found {len(deps)} dependencies[/bold]\n")

    vuln_results = []
    license_results = []
    cycles = []
    outdated_results = []

    if not no_vuln:
        console.print("[bold cyan]▸ Scanning vulnerabilities...[/bold cyan]")
        analyzer = VulnerabilityAnalyzer(cfg)
        vuln_results = analyzer.analyze(deps)
        reporter.report_vulnerabilities(vuln_results)

    if not no_license:
        console.print("[bold cyan]▸ Analyzing licenses...[/bold cyan]")
        license_analyzer = LicenseAnalyzer()
        license_results = license_analyzer.analyze(deps)
        reporter.report_licenses(license_results)

    if not no_circular:
        console.print("[bold cyan]▸ Detecting circular dependencies...[/bold cyan]")
        detector = CircularDetector()
        cycles = detector.detect(deps)
        reporter.report_circular(cycles)

    if not no_outdated:
        console.print("[bold cyan]▸ Checking outdated dependencies...[/bold cyan]")
        checker = OutdatedChecker(cfg)
        outdated_results = checker.check(deps)
        reporter.report_outdated(outdated_results)

    reporter.print_summary(vuln_results, license_results, cycles, outdated_results)

    if html:
        html_reporter = HtmlReporter()
        dep_tree = None
        if not no_circular:
            detector = CircularDetector()
            dep_tree = detector.get_dependency_tree(deps, cfg.max_depth)
        path = html_reporter.export(vuln_results, license_results, cycles, outdated_results, dep_tree, output_dir)
        console.print(f"\n[green]HTML report saved: {path}[/green]")

    if json_output:
        json_exporter = JsonExporter()
        path = json_exporter.export(vuln_results, license_results, cycles, outdated_results, output_dir)
        console.print(f"[green]JSON report saved: {path}[/green]")

    exit_code = _determine_exit_code(vuln_results, license_results, cycles, cfg)
    sys.exit(exit_code)


@cli.command()
@click.argument("project_dir", default=".")
@click.option("--include-dev", is_flag=True, help="Include dev dependencies")
@click.option("--config", default=None, help="Path to config YAML file")
def licenses(project_dir, include_dev, config):
    """Analyze dependency licenses for copyleft risks."""
    cfg = ConfigLoader(config)
    deps = _parse_all(project_dir, include_dev)
    if not deps:
        console.print("[yellow]No dependencies found.[/yellow]")
        sys.exit(0)

    analyzer = LicenseAnalyzer()
    results = analyzer.analyze(deps)

    reporter = TerminalReporter(console)
    reporter.report_licenses(results)

    has_copyleft = any(r.has_copyleft for r in results)
    if has_copyleft and cfg.fail_on_copyleft_license:
        sys.exit(3)


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

    reporter = TerminalReporter(console)
    reporter.report_circular(cycles)

    console.print("\n[bold cyan]Dependency Tree:[/bold cyan]")
    tree = detector.get_dependency_tree(deps, max_depth)
    reporter.report_dependency_tree(tree, max_depth)

    if cycles and cfg.fail_on_circular_dependency:
        sys.exit(2)


@cli.command()
@click.argument("project_dir", default=".")
@click.option("--include-dev", is_flag=True, help="Include dev dependencies")
@click.option("--config", default=None, help="Path to config YAML file")
@click.option("--html", is_flag=True, help="Generate HTML report")
@click.option("--json", "json_output", is_flag=True, help="Generate JSON report")
@click.option("--output-dir", default=".", help="Output directory for reports")
def report(project_dir, include_dev, config, html, json_output, output_dir):
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

    dep_tree = detector.get_dependency_tree(deps, cfg.max_depth)

    reporter = TerminalReporter(console)
    reporter.report_vulnerabilities(vuln_results)
    reporter.report_licenses(license_results)
    reporter.report_circular(cycles)
    reporter.report_outdated(outdated_results)
    reporter.print_summary(vuln_results, license_results, cycles, outdated_results)

    if html:
        html_reporter = HtmlReporter()
        path = html_reporter.export(vuln_results, license_results, cycles, outdated_results, dep_tree, output_dir)
        console.print(f"\n[green]HTML report saved: {path}[/green]")

    if json_output:
        json_exporter = JsonExporter()
        path = json_exporter.export(vuln_results, license_results, cycles, outdated_results, output_dir)
        console.print(f"[green]JSON report saved: {path}[/green]")

    exit_code = _determine_exit_code(vuln_results, license_results, cycles, cfg)
    sys.exit(exit_code)


def _determine_exit_code(vuln_results, license_results, cycles, config) -> int:
    high_vulns = 0
    for vr in vuln_results:
        for v in vr.vulnerabilities:
            if v.severity in ("high", "critical"):
                high_vulns += 1

    has_copyleft = any(r.has_copyleft for r in license_results)
    has_circular = len(cycles) > 0

    if high_vulns > 0 and config.fail_on_high_vulnerability:
        return 1
    if has_circular and config.fail_on_circular_dependency:
        return 2
    if has_copyleft and config.fail_on_copyleft_license:
        return 3

    return 0


if __name__ == "__main__":
    cli()
