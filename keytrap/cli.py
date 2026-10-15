"""KeyTrap command-line interface.

Secret detection system for authorized Git repositories.
Detects accidentally committed secrets using 7 parallel scanner agents.
"""

from __future__ import annotations

import dataclasses
import shutil
import json
import os
import re
import tempfile
import uuid
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.table import Table

from keytrap.engine.safe_mode import apply_safe_mode
from keytrap.engine.orchestrator import ScanJob, run_scan
from keytrap.engine.rule_importer import import_rules
from keytrap.engine.rule_loader import RuleLoader
from keytrap.reports.report_generator import generate, scan_result_from_file
from keytrap.ui import ScanDisplay, render_results

console = Console()

# Create app with custom help
app = typer.Typer(
    add_completion=False,
    no_args_is_help=True,
    help="🔓 KeyTrap — Multi-agent secret detection for Git repositories"
)


@app.callback(invoke_without_command=True)
def main(ctx: typer.Context) -> None:
    """
    KeyTrap — Multi-agent secret detection for Git repositories.
    
    Detects accidentally committed secrets using 7 parallel scanner agents:
      • GitleaksAgent — Industry-standard Gitleaks CLI tool
      • TruffleHogAgent — Provider-specific secret detection
      • CustomRegexAgent — YAML-based rule patterns
      • EntropyAgent — High-randomness token detection
      • HistoryAgent — Git commit history analysis
      • DiffAgent — Latest commit vs the previous one (or --diff-base/--diff-head)
      • ContextJudgeAgent — AI confidence scoring
    
    All 7 agents run in parallel. Secrets are reported raw (unredacted).
    
    Quick Start:
    
        # Scan local repository
        keytrap scan /path/to/repo --output findings.json
        
        # Scan remote repository (auto-cloned)
        keytrap scan https://github.com/owner/repo.git --output findings.json
        
        # View results
        cat findings.json | jq '.findings[] | {provider, risk_score, secret}'
    
    Available Commands:
    
        scan          Scan a repository for secrets (local path or remote URL)
        test-rules    Validate rule syntax and check for ReDoS vulnerabilities
        report        Generate a formatted report from scan results
        import-rules  Import community rules from external sources
        
    Use 'keytrap <command> --help' for detailed command information.
    """
    # If no command was given, show help
    if ctx.invoked_subcommand is None:
        console.print(ctx.get_help())


def _is_git_url(path_str: str) -> bool:
    """Check if string is a git repository URL."""
    return path_str.startswith(("http://", "https://", "git@")) and (".git" in path_str or "/" in path_str.replace("://", ""))


def _clone_remote_repo(url: str, quiet: bool = False) -> Path:
    """Clone a remote repository to a temporary directory."""
    try:
        import git
    except ImportError:
        console.print("[red]Error: GitPython not installed. Run: pip install gitpython[/red]")
        raise typer.Exit(code=1)
    
    # Create temp directory
    temp_dir = tempfile.mkdtemp(prefix="keytrap_")
    temp_path = Path(temp_dir)
    
    if not quiet:
        console.print(f"[cyan]Cloning repository: {url}[/cyan]")
    
    try:
        git.Repo.clone_from(url, temp_path)
        if not quiet:
            console.print(f"[green]✓ Repository cloned to {temp_path}[/green]")
        return temp_path
    except Exception as e:
        console.print(f"[red]Error cloning repository: {e}[/red]")
        # Clean up on error
        shutil.rmtree(temp_path, ignore_errors=True)
        raise typer.Exit(code=1)


def _validate_repo_path(path_str: str) -> Path:
    """Validate and resolve repository path (local or remote)."""
    if _is_git_url(path_str):
        return _clone_remote_repo(path_str)
    
    path = Path(path_str).expanduser().resolve()
    
    if not path.exists():
        console.print(f"[red]Error: Path does not exist: {path}[/red]")
        raise typer.Exit(code=1)
    
    if not path.is_dir():
        console.print(f"[red]Error: Path is not a directory: {path}[/red]")
        raise typer.Exit(code=1)
    
    if not (path / ".git").exists():
        console.print(f"[yellow]Warning: {path} does not appear to be a Git repository[/yellow]")
    
    return path


@app.command()
def scan(
    path: str = typer.Argument(..., help="Local repository path or remote Git URL (e.g., https://github.com/owner/repo.git)"),
    rules: Optional[Path] = typer.Option(None, "--rules", "-r", help="Custom rules directory"),
    output: Optional[Path] = typer.Option(None, "--output", "-o", help="Output file path (default: findings.json)"),
    safe_mode: bool = typer.Option(False, "--safe-mode", help="Don't verify secrets with provider API"),
    diff_base: Optional[str] = typer.Option(None, "--diff-base", help="Base commit for diff scan"),
    diff_head: Optional[str] = typer.Option(None, "--diff-head", help="Head commit for diff scan"),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Show detailed output"),
    keep_cloned: bool = typer.Option(False, "--keep-cloned", help="Keep cloned remote repository after scan"),
) -> None:
    """
    Scan a repository for accidentally committed secrets.
    
    Examples:
    
        # Scan local repository
        keytrap scan /path/to/repo --output findings.json
        
        # Scan with remote repository URL (auto-cloned)
        keytrap scan https://github.com/owner/repo.git --output findings.json
        
        # Scan with custom rules
        keytrap scan . --rules ./custom-rules/ --output findings.json
        
        # Scan specific commits (diff mode)
        keytrap scan . --diff-base abc123 --diff-head def456 --output findings.json
        
        # Safe mode (don't verify if keys are actually valid)
        keytrap scan /repo --safe-mode --output findings.json
        
        # Keep cloned repository for inspection
        keytrap scan https://github.com/owner/repo.git --keep-cloned --output findings.json
    """
    # Track if we cloned a remote repo
    was_remote = _is_git_url(path)
    
    # Animated display on a real terminal; plain output when piped or in CI.
    animated = console.is_terminal and not os.environ.get("KEYTRAP_PLAIN")
    display = ScanDisplay(console, repo=path) if animated else None

    # Validate and resolve path (remote clones happen inside the live display)
    repo_path = None if (animated and was_remote) else _validate_repo_path(path)
    
    if verbose and repo_path is not None:
        console.print(f"[cyan]Repository: {repo_path}[/cyan]")
        console.print(f"[cyan]Safe mode: {safe_mode}[/cyan]")
        if was_remote:
            console.print(f"[cyan]Remote repository (will {'keep' if keep_cloned else 'delete'} after scan)[/cyan]")
    
    if rules is not None:
        os.environ["KEYTRAP_RULES_DIR"] = str(rules)

    scan_id = str(uuid.uuid4())
    options = apply_safe_mode({"safe_mode": safe_mode})
    output_path = output or Path("findings.json")

    def _job(repo: Path) -> ScanJob:
        return ScanJob(
            repo_path=str(repo),
            scan_id=scan_id,
            branch=_detect_branch(repo),
            scope=None,
            options=options,
            base_commit=diff_base,
            head_commit=diff_head,
        )

    if display is not None:
        with display.live():
            if repo_path is None:
                repo_path = _clone_remote_repo(path, quiet=True)
            result = run_scan(_job(repo_path), on_event=display.handle)
        _write_findings(output_path, result)
        render_results(console, result, output_path.absolute(), display._elapsed())
    else:
        console.print("[cyan]Starting scan...[/cyan]")
        result = run_scan(_job(repo_path))
        _write_findings(output_path, result)

        # Display results
        console.print()
        console.print(f"[green]✓ Scan {result.scan_id} completed[/green]")
    
        # Summary table
        summary_table = Table(title="Scan Summary", show_header=False, box=None)
        summary_table.add_row("Total Findings", str(len(result.findings)))
        summary_table.add_row("Output File", str(output_path.absolute()))
    
        severity_counts = result.stats.get("by_severity", {})
        for severity in ["critical", "high", "medium", "low"]:
            count = severity_counts.get(severity, 0)
            if count > 0:
                color = {"critical": "red", "high": "red", "medium": "yellow", "low": "blue"}.get(severity, "white")
                summary_table.add_row(f"  {severity.capitalize()}", f"[{color}]{count}[/{color}]")
    
        console.print(summary_table)
    
        # Top findings
        if result.findings:
            console.print("\n[cyan]Top 10 Findings:[/cyan]")
            findings_table = Table(show_header=True, header_style="bold cyan")
            findings_table.add_column("Risk", style="dim", width=6)
            findings_table.add_column("Type", width=12)
            findings_table.add_column("Provider", width=12)
            findings_table.add_column("File", width=30)
            findings_table.add_column("Secret", overflow="fold")
        
            for finding in result.findings[:10]:
                risk_color = "red" if finding.risk_score >= 80 else "yellow" if finding.risk_score >= 50 else "blue"
                findings_table.add_row(
                    f"[{risk_color}]{finding.risk_score}[/{risk_color}]",
                    finding.secret_type[:12],
                    finding.provider[:12],
                    str(finding.file_path)[-30:],
                    finding.secret
                )
        
            console.print(findings_table)
        else:
            console.print("[green]No secrets found![/green]")
    
        console.print(f"\n[cyan]Output written to {output_path.absolute()}[/cyan]")
    
    # Clean up cloned repository if needed
    if was_remote:
        if keep_cloned:
            console.print(f"[yellow]Repository kept at: {repo_path}[/yellow]")
            console.print(f"[yellow]Clean up that temporary directory manually when done.[/yellow]")
        else:
            if display is None:
                console.print("[cyan]Cleaning up cloned repository...[/cyan]")
            try:
                shutil.rmtree(repo_path, ignore_errors=True)
                if display is None:
                    console.print("[green]✓ Temporary repository deleted[/green]")
            except Exception as e:
                console.print(f"[yellow]Warning: Could not delete temporary repo: {e}[/yellow]")


@app.command("test-rules")
def test_rules(
    rules_dir: Path = typer.Argument(..., help="Directory containing YAML rule files"),
    redos_timeout: int = typer.Option(100, "--redos-timeout", help="ReDoS timeout in milliseconds"),
) -> None:
    """
    Validate rule syntax and check for ReDoS vulnerabilities.
    
    Examples:
    
        # Test core rules
        keytrap test-rules rules/keytrap-core.yml
        
        # Test custom rules with longer timeout
        keytrap test-rules ./custom-rules/ --redos-timeout 200
        
        # Test imported rules
        keytrap test-rules rules/imported/
    """
    if not rules_dir.exists():
        console.print(f"[red]Error: Rules directory does not exist: {rules_dir}[/red]")
        raise typer.Exit(code=1)
    
    os.environ["KEYTRAP_REDOS_TIMEOUT_MS"] = str(redos_timeout)
    loader = RuleLoader(production=False)
    loaded, failed = loader.load(rules_dir)

    console.print()
    results_table = Table(show_header=False, box=None)
    results_table.add_row("[green]✓ Rules loaded[/green]", str(loaded))
    if failed > 0:
        results_table.add_row("[yellow]✗ Rules failed[/yellow]", str(failed))
    console.print(results_table)
    
    if failed > 0:
        raise typer.Exit(code=1)


@app.command()
def report(
    findings_file: Path = typer.Argument(Path("findings.json"), help="findings.json written by `keytrap scan`"),
    format: str = typer.Option("markdown", "--format", "-f", help="Output format: markdown, pdf, or hackerone"),
    output: Optional[Path] = typer.Option(None, "--output", "-o", help="Output file path"),
) -> None:
    """
    Generate a formatted report from scan results.
    
    Examples:
    
        # Generate Markdown report
        keytrap report findings.json --format markdown --output report.md
        
        # Generate PDF report
        keytrap report findings.json --format pdf --output report.pdf
        
        # Generate HackerOne-formatted report
        keytrap report findings.json --format hackerone --output report.zip
    """
    if format not in ["markdown", "pdf", "hackerone"]:
        console.print(f"[red]Error: Invalid format '{format}'. Choose: markdown, pdf, or hackerone[/red]")
        raise typer.Exit(code=1)
    
    console.print(f"[cyan]Generating {format.upper()} report from {findings_file}...[/cyan]")
    
    try:
        result = scan_result_from_file(findings_file)
    except Exception as e:
        console.print(f"[red]Error: Could not read {findings_file}[/red]")
        console.print(f"[yellow]Details: {e}[/yellow]")
        raise typer.Exit(code=1)
    
    generated = generate(result, format)
    final_path = _finalize_report_output(generated, output)
    console.print(f"[green]✓ Report written to {final_path.absolute()}[/green]")


@app.command("import-rules")
def import_rules_command(
    source: str = typer.Option(..., "--source", "-s", help="Community rules source: mazen160, h33tlit, or odomojuli"),
    output: Path = typer.Option(Path("./rules/imported/"), "--output", "-o", help="Output directory for imported rules"),
) -> None:
    """
    Import community regex rules into KeyTrap YAML format.
    
    Supported sources:
        - mazen160: secrets-patterns-db
        - h33tlit: secret-regex-list
        - odomojuli: regextokens
    
    Examples:
    
        # Import community rules
        keytrap import-rules --source mazen160 --output rules/imported/
        
        # Import from another supported source
        keytrap import-rules --source h33tlit --output rules/community/
    """
    console.print(f"[cyan]Importing rules from {source}...[/cyan]")
    
    try:
        result = import_rules(source, output)
        console.print()
        console.print(f"Imported {result['imported']} rules from {result['source']}")
        
        summary_table = Table(show_header=False, box=None)
        summary_table.add_row("[green]✓ Imported[/green]", str(result['imported']))
        if result['failed'] > 0:
            summary_table.add_row("[yellow]✗ Failed[/yellow]", str(result['failed']))
        console.print(summary_table)
        
        console.print(f"\n[cyan]Output directory: {output.absolute()}[/cyan]")
        for written_file in result["written_files"]:
            console.print(f"  [green]✓[/green] {Path(written_file).name}")
    
    except Exception as e:
        console.print(f"[red]Error importing rules: {e}[/red]")
        raise typer.Exit(code=1)


def _write_findings(path: Path, result) -> None:
    payload = {
        "scan_id": result.scan_id,
        "started_at": result.started_at,
        "completed_at": result.completed_at,
        "stats": result.stats,
        "findings": [dataclasses.asdict(finding) for finding in result.findings],
    }
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def _detect_branch(repo_path: Path) -> str:
    try:
        import git

        repo = git.Repo(repo_path)
        return repo.active_branch.name
    except Exception:
        return "unknown"


def _finalize_report_output(generated: Path, output: Optional[Path]) -> Path:
    if output is None:
        return generated

    target = output
    if output.exists() and output.is_dir():
        target = output / generated.name

    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(generated, target)
    return target


if __name__ == "__main__":
    app()
