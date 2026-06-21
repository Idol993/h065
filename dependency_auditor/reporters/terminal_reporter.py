from dependency_auditor.analyzers.vulnerability_analyzer import VulnerabilityResult, Vulnerability, classify_severity
from dependency_auditor.analyzers.license_analyzer import LicenseResult
from dependency_auditor.analyzers.circular_detector import CircularDependency
from dependency_auditor.analyzers.outdated_checker import OutdatedResult
from dependency_auditor.parsers.python_parser import Dependency
from rich.console import Console
from rich.table import Table
from rich.tree import Tree
from rich.panel import Panel
from rich import box

SEVERITY_COLORS = {
    "critical": "#800080",
    "high": "#ff0000",
    "medium": "#ffa500",
    "low": "#ffff00",
}

_SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}


class TerminalReporter:
    def __init__(self, console: Console | None = None):
        self.console = console or Console()

    def report_vulnerabilities(self, results: list[VulnerabilityResult]):
        all_vulns: list[tuple[VulnerabilityResult, Vulnerability]] = []
        for vr in results:
            for v in vr.vulnerabilities:
                all_vulns.append((vr, v))

        if not all_vulns:
            self.console.print(Panel("[green]✓ No vulnerabilities found[/green]", title="Vulnerabilities"))
            return

        counts: dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for _, v in all_vulns:
            sev = v.severity.lower()
            counts[sev] = counts.get(sev, 0) + 1

        summary_parts = []
        for sev in ("critical", "high", "medium", "low"):
            if counts.get(sev, 0) > 0:
                color = SEVERITY_COLORS[sev]
                summary_parts.append(f"[{color}]{sev.upper()}: {counts[sev]}[/{color}]")
        self.console.print(Panel("  |  ".join(summary_parts), title="Vulnerability Summary"))

        all_vulns.sort(key=lambda x: _SEVERITY_ORDER.get(x[1].severity.lower(), 99))

        table = Table(title="Vulnerabilities", box=box.ROUNDED)
        table.add_column("Package", style="cyan")
        table.add_column("Version")
        table.add_column("Severity")
        table.add_column("CVE")
        table.add_column("CVSS")
        table.add_column("Title")

        for vr, v in all_vulns:
            color = SEVERITY_COLORS.get(v.severity.lower(), "white")
            table.add_row(
                vr.dependency.name,
                vr.dependency.version_spec,
                f"[{color}]{v.severity.upper()}[/{color}]",
                v.cve_id or "-",
                f"{v.cvss_score:.1f}" if v.cvss_score else "-",
                v.title[:60] if v.title else "-",
            )

        self.console.print(table)

    def report_licenses(self, results: list[LicenseResult]):
        has_issues = any(r.has_copyleft for r in results)
        if not has_issues:
            self.console.print(Panel("[green]✓ No copyleft license issues found[/green]", title="Licenses"))
        else:
            self.console.print(Panel("[red]⚠ Copyleft licenses detected[/red]", title="Licenses"))

        table = Table(title="License Report", box=box.ROUNDED)
        table.add_column("Package", style="cyan")
        table.add_column("License")
        table.add_column("Risk Level")
        table.add_column("Copyleft")

        risk_colors = {"high": "red", "medium": "yellow", "low": "green"}

        for r in results:
            for lr in r.licenses:
                risk_color = risk_colors.get(lr.risk_level.lower(), "white")
                copyleft_str = "[red]✗ YES[/red]" if lr.is_copyleft else "[green]✓ NO[/green]"
                table.add_row(
                    r.dependency.name,
                    lr.license_name,
                    f"[{risk_color}]{lr.risk_level.upper()}[/{risk_color}]",
                    copyleft_str,
                )

        self.console.print(table)

    def report_circular(self, cycles: list[CircularDependency]):
        if not cycles:
            self.console.print(Panel("[green]✓ No circular dependencies detected[/green]", title="Circular Dependencies"))
            return

        tree = Tree("[bold red]Circular Dependencies[/bold red]")
        for cycle in cycles:
            path_str = " → ".join(cycle.cycle)
            branch = tree.add(f"[red]{path_str}[/red]")
            branch.add(f"[dim]Cycle length: {cycle.length}[/dim]")

        self.console.print(tree)

    def report_outdated(self, results: list[OutdatedResult]):
        outdated = [r for r in results if r.is_outdated]
        if not outdated:
            self.console.print(Panel("[green]✓ All packages are up to date[/green]", title="Outdated Packages"))
            return

        table = Table(title="Outdated Packages", box=box.ROUNDED)
        table.add_column("Package", style="cyan")
        table.add_column("Current")
        table.add_column("Latest", style="green")
        table.add_column("Ecosystem")

        for r in outdated:
            table.add_row(
                r.dependency.name,
                f"[red]{r.current_version}[/red]",
                r.latest_version,
                r.ecosystem,
            )

        self.console.print(table)

    def report_dependency_tree(self, tree: dict, max_depth: int = 5):
        if not tree:
            self.console.print(Panel("[dim]No dependency tree available[/dim]", title="Dependency Tree"))
            return

        root = Tree("[bold cyan]Dependency Tree[/bold cyan]")
        self._build_tree(root, tree, depth=1, max_depth=max_depth)
        self.console.print(root)

    def _build_tree(self, parent: Tree, subtree: dict, depth: int, max_depth: int):
        if depth > max_depth or not subtree:
            return
        for name, children in subtree.items():
            if name.startswith("⟳"):
                branch = parent.add(f"[red]{name}[/red]")
            elif name.startswith("↩"):
                branch = parent.add(f"[yellow]{name}[/yellow]")
            else:
                branch = parent.add(f"[cyan]{name}[/cyan]")
            if isinstance(children, dict) and children:
                self._build_tree(branch, children, depth + 1, max_depth)

    def print_summary(
        self,
        vuln_results: list[VulnerabilityResult],
        license_results: list[LicenseResult],
        cycles: list[CircularDependency],
        outdated_results: list[OutdatedResult],
    ):
        all_vulns = []
        for vr in vuln_results:
            all_vulns.extend(vr.vulnerabilities)

        counts: dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for v in all_vulns:
            sev = v.severity.lower()
            counts[sev] = counts.get(sev, 0) + 1

        copyleft_count = sum(1 for r in license_results if r.has_copyleft)
        outdated_count = sum(1 for r in outdated_results if r.is_outdated)

        lines = []
        lines.append(f"Total vulnerabilities: {len(all_vulns)}")
        for sev in ("critical", "high", "medium", "low"):
            if counts.get(sev, 0) > 0:
                color = SEVERITY_COLORS[sev]
                lines.append(f"  [{color}]{sev.capitalize()}[/{color}]: {counts[sev]}")
        lines.append(f"Copyleft licenses: {copyleft_count}")
        lines.append(f"Circular dependencies: {len(cycles)}")
        lines.append(f"Outdated packages: {outdated_count}")

        self.console.print(Panel("\n".join(lines), title="Audit Summary", border_style="bold"))
