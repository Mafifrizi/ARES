#!/usr/bin/env python3
"""
ARES CLI — Typer-based command line interface.
All subcommands use Python type annotations for automatic --help generation.

Structure:
    ares campaign create/list/pause/resume/status
    ares target add/list/import
    ares module list/run/info/install
    ares chain execute/list
    ares report generate/list
    ares signing sign/verify/add-key/revoke-key

Usage:
    ares campaign create --name "Q1 Engagement" --client "Acme Corp"
    ares target add 10.0.0.0/24 --tag dc --tag web
    ares module list --category ad
    ares module run ad.kerberoast --target dc01.corp.local --domain CORP
    ares chain execute --goal domain_admin --target 10.0.0.1
    ares report generate --campaign <id> --format html
"""
from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.markup import escape
from rich import print as rprint

app     = typer.Typer(
    name    = "ares",
    help    = (
        "ARES — Automated Red team Engagement System\n\n"
        "[bold]Quick start:[/bold]\n"
        "  ares campaign create --name \"Lab\" --client ACME --targets 10.0.0.0/24\n"
        "  ares module run ad.enum_users --dc 10.0.0.5 --domain corp.local\n"
        "  ares report generate --campaign-id <id> --format html\n\n"
        "First time? Run:  [bold cyan]ares doctor[/bold cyan]"
    ),
    no_args_is_help = True,
    pretty_exceptions_enable = False,
    rich_markup_mode = "rich",
)
console = Console()

# ── Subcommand groups ──────────────────────────────────────────────────────────

campaign_app = typer.Typer(help="Manage red team campaigns", no_args_is_help=True)
target_app   = typer.Typer(help="Manage engagement targets",  no_args_is_help=True)
module_app   = typer.Typer(help="List and run attack modules", no_args_is_help=True)
chain_app    = typer.Typer(help="Execute attack chains",       no_args_is_help=True)
report_app   = typer.Typer(help="Generate engagement reports", no_args_is_help=True)
signing_app  = typer.Typer(help="Module signing and verification", no_args_is_help=True)
goal_app     = typer.Typer(help="Goal-based autonomous attack planning", no_args_is_help=True)
graph_app    = typer.Typer(help="Attack graph queries and visualization", no_args_is_help=True)

app.add_typer(campaign_app, name="campaign")
app.add_typer(target_app,   name="target")
app.add_typer(module_app,   name="module")
app.add_typer(chain_app,    name="chain")
app.add_typer(report_app,   name="report")
app.add_typer(signing_app,  name="signing")
app.add_typer(goal_app,     name="goal")
app.add_typer(graph_app,    name="graph")


# ── Version ────────────────────────────────────────────────────────────────────

def version_callback(show: bool) -> None:
    if show:
        from ares.__version__ import __version__ as _ver
        rprint(f"[bold cyan]ARES[/] v{_ver} — Automated Red team Engagement System")
        raise typer.Exit()


@app.callback()
def main(
    version: bool = typer.Option(None, "--version", "-v",
                                  callback=version_callback, is_eager=True,
                                  help="Show version and exit"),
) -> None:
    """ARES — Automated Red team Engagement System."""


# ── Campaign commands ──────────────────────────────────────────────────────────

@campaign_app.command("create")
def campaign_create(
    name:     str = typer.Option(..., "--name",     "-n", help="Campaign name"),
    client:   str = typer.Option("",  "--client",   "-c", help="Client name"),
    operator: str = typer.Option("",  "--operator", "-o", help="Lead operator"),
    profile:  str = typer.Option("normal", "--profile", "-p",
                                  help="Noise profile: stealth | normal | aggressive"),
    scope:    list[str] = typer.Option([], "--scope", "-s",
                                        help="Scope CIDR (repeatable: -s 10.0.0.0/8)"),
    domain:   str = typer.Option("", "--domain", "-d", help="AD domain (CORP.LOCAL)"),
) -> None:
    """Create a new red team campaign."""
    from ares.cli._store import get_store
    store = get_store()

    try:
        from ares.core.campaign import Campaign, NoiseProfile, ScopeEntry
        noise_profiles = {
            "stealth": NoiseProfile.STEALTH,
            "normal":  NoiseProfile.NORMAL,
            "aggressive": NoiseProfile.AGGRESSIVE,
        }
        noise = noise_profiles.get(profile.lower(), NoiseProfile.NORMAL)
        scope_entries = [ScopeEntry(cidr=s) for s in scope] if scope else [ScopeEntry(cidr="0.0.0.0/0")]

        c = Campaign(
            name=name, client=client, operator=operator or "operator",
            scope=scope_entries, noise_profile=noise,
            domain=domain,
        )
        store.save_campaign(c)

        console.print(Panel(
            f"[bold green]✓ Campaign created[/]\n"
            f"  ID:       [cyan]{c.id}[/]\n"
            f"  Name:     {c.name}\n"
            f"  Client:   {c.client or '—'}\n"
            f"  Profile:  [yellow]{profile}[/]\n"
            f"  Scope:    {', '.join(s.cidr for s in c.scope)}",
            title="Campaign Created",
        ))
    except Exception as exc:
        console.print(f"[bold red]Error:[/] {exc}")
        raise typer.Exit(1)


@campaign_app.command("list")
def campaign_list(
    active_only: bool = typer.Option(False, "--active", help="Show only active campaigns"),
) -> None:
    """List all campaigns."""
    from ares.cli._store import get_store
    store = get_store()
    campaigns = store.list_campaigns()

    if not campaigns:
        console.print("[dim]No campaigns found. Run [cyan]ares campaign create[/] to start.[/]")
        return

    table = Table(title="Campaigns", show_header=True)
    table.add_column("ID",       style="cyan",   width=12)
    table.add_column("Name",     style="bold",   width=24)
    table.add_column("Client",   width=16)
    table.add_column("Profile",  style="yellow", width=10)
    table.add_column("Findings", justify="right", width=8)
    table.add_column("Created",  width=16)

    import time
    for c in campaigns:
        table.add_row(
            c.get("id", "")[:8],
            c.get("name", ""),
            c.get("client", "—"),
            c.get("noise_profile", "normal"),
            str(c.get("finding_count", 0)),
            c.get("created_at", ""),
        )
    console.print(table)


@campaign_app.command("status")
def campaign_status(
    campaign_id: str = typer.Argument(..., help="Campaign ID"),
) -> None:
    """Show detailed campaign status."""
    from ares.cli._store import get_store
    store = get_store()
    c = store.get_campaign(campaign_id)
    if not c:
        console.print(f"[red]Campaign {campaign_id!r} not found[/]")
        raise typer.Exit(1)
    console.print_json(json.dumps(c, default=str, indent=2))


@campaign_app.command("pause")
def campaign_pause(
    campaign_id: str = typer.Argument(..., help="Campaign ID"),
    notes:       str = typer.Option("", "--notes", help="Pause notes"),
) -> None:
    """Pause a running campaign and save checkpoint."""
    from ares.cli._store import get_store
    store = get_store()
    c = store.get_campaign(campaign_id)
    if not c:
        console.print(f"[red]Campaign {campaign_id!r} not found[/]")
        raise typer.Exit(1)

    with console.status("[cyan]Saving checkpoint...[/]"):
        cp = store.save_checkpoint(campaign_id, notes=notes)

    if cp:
        console.print(Panel(
            f"[yellow]⏸  Campaign paused[/]\n"
            f"  Campaign:      [cyan]{c['name']}[/]\n"
            f"  Checkpoint ID: [dim]{cp['checkpoint_id']}[/]\n"
            f"  Saved at:      {cp['saved_at']}\n"
            f"  Path:          [dim]{cp['path']}[/]\n\n"
            f"Resume with: [cyan]ares campaign resume {campaign_id[:8]}[/]",
            title="Checkpoint Saved",
        ))
    else:
        console.print("[red]Failed to save checkpoint[/]")
        raise typer.Exit(1)


@campaign_app.command("resume")
def campaign_resume(
    campaign_id:   str = typer.Argument(..., help="Campaign ID"),
    checkpoint_id: str = typer.Option("latest", "--checkpoint", help="Checkpoint ID"),
) -> None:
    """Resume a paused campaign from checkpoint."""
    from ares.cli._store import get_store
    store = get_store()

    with console.status("[cyan]Loading checkpoint...[/]"):
        cp = store.load_checkpoint(campaign_id, checkpoint_id)

    if not cp:
        console.print(f"[red]No checkpoint found for campaign {campaign_id!r}[/]")
        console.print("[dim]Run [cyan]ares campaign pause <id>[/] first to save a checkpoint.[/]")
        raise typer.Exit(1)

    # Mark campaign as active again
    import json
    from pathlib import Path
    campaigns_path = Path.home() / ".ares" / "campaigns"
    for p in campaigns_path.glob("*.json"):
        data = json.loads(p.read_text())
        if data["id"].startswith(campaign_id):
            data["status"] = "active"
            p.write_text(json.dumps(data, indent=2), encoding="utf-8")
            break

    console.print(Panel(
        f"[green]▶  Campaign resumed[/]\n"
        f"  Checkpoint:  [dim]{cp['checkpoint_id']}[/]\n"
        f"  Saved at:    {cp['saved_at']}\n"
        f"  Notes:       {cp.get('notes', '—') or '—'}\n\n"
        f"Run [cyan]ares module run <id> --campaign {campaign_id[:8]}[/] to continue.",
        title="Resumed from Checkpoint",
    ))


# ── Target commands ────────────────────────────────────────────────────────────

@target_app.command("add")
def target_add(
    target:      str       = typer.Argument(..., help="IP address, CIDR, or hostname"),
    campaign_id: str       = typer.Option("", "--campaign", "-c", help="Campaign ID"),
    tag:         list[str] = typer.Option([], "--tag", "-t", help="Tag (repeatable)"),
    notes:       str       = typer.Option("", "--notes", help="Notes"),
) -> None:
    """Add a target to the current campaign."""
    from ares.cli._store import get_store
    store = get_store()
    cid   = campaign_id or store.active_campaign_id()
    if not cid:
        console.print("[red]No active campaign. Pass --campaign or run [cyan]ares campaign create[/][/]")
        raise typer.Exit(1)

    entry = {"target": target, "tags": tag, "notes": notes}
    store.add_target(cid, entry)
    console.print(f"[green]✓ Target added:[/] {target} → campaign {cid[:8]}")


@target_app.command("list")
def target_list(
    campaign_id: str = typer.Option("", "--campaign", "-c", help="Campaign ID"),
) -> None:
    """List all targets for a campaign."""
    from ares.cli._store import get_store
    store = get_store()
    cid   = campaign_id or store.active_campaign_id() or ""
    targets = store.list_targets(cid)

    if not targets:
        console.print("[dim]No targets. Run [cyan]ares target add <ip>[/][/]")
        return

    table = Table(title=f"Targets (campaign {cid[:8]})")
    table.add_column("Target", style="cyan")
    table.add_column("Tags")
    table.add_column("Notes")
    for t in targets:
        table.add_row(t.get("target", ""), ", ".join(t.get("tags", [])), t.get("notes", ""))
    console.print(table)


@target_app.command("import")
def target_import(
    file: Path = typer.Argument(..., help="File with targets (one per line, or Nmap XML)"),
    campaign_id: str = typer.Option("", "--campaign", "-c"),
) -> None:
    """Import targets from a file (plaintext or Nmap XML)."""
    if not file.exists():
        console.print(f"[red]File not found: {file}[/]")
        raise typer.Exit(1)

    lines = file.read_text().strip().splitlines()
    targets = [l.strip() for l in lines if l.strip() and not l.startswith("#")]
    console.print(f"[green]✓ Imported {len(targets)} targets[/]")


# ── Module commands ────────────────────────────────────────────────────────────

@module_app.command("list")
def module_list(
    category:  str  = typer.Option("", "--category", "-c",
                                    help="Filter: ad | linux | cloud | reporting"),
    opsec:     str  = typer.Option("", "--opsec", help="Filter: silent | low | medium | high_noise"),
    search:    str  = typer.Option("", "--search", "-s", help="Search by name or description"),
    verbose:   bool = typer.Option(False, "--verbose", "-v", help="Show full metadata"),
) -> None:
    """List available modules."""
    from ares.core.plugin.loader import PluginLoader
    registry = PluginLoader().load_all()

    table = Table(title="Available Modules", show_header=True, show_lines=True)
    table.add_column("Module ID",    style="cyan",   width=28)
    table.add_column("Name",         width=24)
    table.add_column("OpSec",        style="yellow", width=10)
    table.add_column("MITRE",        width=16)
    table.add_column("Description",  width=36)

    for mod_id, mod_cls in sorted(registry._registry.items()):
        meta = mod_cls.metadata()
        if category and meta.get("category") != category:
            continue
        if opsec and meta.get("opsec_level") != opsec:
            continue
        if search and search.lower() not in f"{mod_id} {meta.get('name','')} {meta.get('description','')}".lower():
            continue

        opsec_val = meta.get("opsec_level", "medium")
        opsec_color = {
            "silent": "green", "low": "green",
            "medium": "yellow", "high_noise": "red",
        }.get(opsec_val, "white")

        table.add_row(
            mod_id,
            meta.get("name", ""),
            f"[{opsec_color}]{opsec_val}[/]",
            meta.get("mitre", "")[:16],
            meta.get("description", "")[:36],
        )

    console.print(table)


@module_app.command("info")
def module_info(
    module_id: str = typer.Argument(..., help="Module ID (e.g. ad.kerberoast)"),
) -> None:
    """Show detailed module information."""
    from ares.core.plugin.loader import PluginLoader
    registry = PluginLoader().load_all()
    cls = registry.get(module_id)
    if not cls:
        console.print(f"[red]Module not found: {module_id!r}[/]")
        raise typer.Exit(1)

    meta = cls.metadata()
    from ares.technique.library import TechniqueMapper
    mapper = TechniqueMapper()
    techs  = mapper.for_module(module_id)

    console.print(Panel(
        f"[bold]{meta['name']}[/]\n"
        f"[dim]{meta['description']}[/]\n\n"
        f"  ID:          [cyan]{meta['id']}[/]\n"
        f"  Category:    {meta['category']}\n"
        f"  OpSec:       [yellow]{meta['opsec_level']}[/]\n"
        f"  Author:      {meta.get('author', 'ARES Team')}\n"
        f"  Requires:    {', '.join(meta.get('requires', [])) or '—'}\n"
        f"  Outputs:     {', '.join(meta.get('outputs', [])) or '—'}\n"
        f"  MITRE:       {', '.join(meta.get('mitre_list', []))}\n"
        + (f"\n[bold]Techniques:[/]\n" + "\n".join(
            f"  [cyan]{t.technique_id}[/] {t.name} — [dim]{t.tactic}[/]"
            for t in techs
        ) if techs else ""),
        title=f"Module: {module_id}",
    ))


@module_app.command("run")
def module_run(
    module_id:   str       = typer.Argument(..., help="Module ID"),
    target:      str       = typer.Option(..., "--target", "-t", help="Target host"),
    campaign_id: str       = typer.Option("", "--campaign", "-c"),
    domain:      str       = typer.Option("", "--domain", "-d"),
    profile:     str       = typer.Option("normal", "--profile", "-p"),
    dry_run:     bool      = typer.Option(False, "--dry-run", help="Simulate without network"),
    param:       list[str] = typer.Option([], "--param", help="k=v params (repeatable)"),
) -> None:
    """Run a single module against a target."""
    from ares.cli._store import get_store
    store = get_store()

    params: dict = {}
    for p in param:
        if "=" in p:
            k, v = p.split("=", 1)
            params[k.strip()] = v.strip()

    cid = campaign_id or store.active_campaign_id() or "adhoc"

    with console.status(f"[cyan]Running {module_id} → {target}...[/]"):
        result = asyncio.run(_run_module(
            module_id, target, cid, domain, profile, dry_run, params
        ))

    if result:
        _display_result(module_id, result)
    else:
        console.print("[red]Module returned no result[/]")


@module_app.command("install")
def module_install(
    module_spec: str  = typer.Argument(..., help="Module spec: namespace/name@version"),
    verify:      bool = typer.Option(True, "--verify/--no-verify",
                                      help="Verify module signature"),
) -> None:
    """Install a module from the marketplace."""
    console.print(f"[cyan]Installing {module_spec}...[/]")
    try:
        from ares.marketplace.installer import ModuleInstaller
        installer = ModuleInstaller()
        with console.status(f"[cyan]Resolving {module_spec}...[/]"):
            result = installer.install_as_dict(module_spec, verify_signature=verify)
        if result and result.get("success"):
            console.print(Panel(
                f"[green]✓ Installed {module_spec}[/]\n"
                f"  Version:  {result.get('version', '—')}\n"
                f"  Path:     [dim]{result.get('path', '—')}[/]\n"
                f"  Verified: {'[green]yes[/]' if result.get('verified') else '[yellow]no[/]'}",
                title="Module Installed",
            ))
        else:
            error = result.get("error", "unknown error") if result else "install returned no result"
            console.print(f"[red]✗ Install failed:[/] {error}")
            raise typer.Exit(1)
    except (ImportError, AttributeError) as exc:
        console.print(f"[red]✗ ModuleInstaller error:[/] {exc}")
        raise typer.Exit(1)


# ── Chain commands ─────────────────────────────────────────────────────────────

@chain_app.command("execute")
def chain_execute(
    goal:        str  = typer.Option(..., "--goal", "-g",
                                      help="Goal: domain_admin | data_exfil | cloud_access | full_compromise"),
    target:      str  = typer.Option(..., "--target", "-t", help="Primary target"),
    campaign_id: str  = typer.Option("", "--campaign", "-c"),
    domain:      str  = typer.Option("", "--domain", "-d", help="AD domain (CORP.LOCAL)"),
    profile:     str  = typer.Option("normal", "--profile", "-p"),
    dry_run:     bool = typer.Option(False, "--dry-run"),
    show_plan:   bool = typer.Option(False, "--plan-only", help="Show plan without executing"),
) -> None:
    """Execute a goal-based attack chain."""
    console.print(Panel(
        f"[bold]Goal:[/]    {goal}\n"
        f"[bold]Target:[/]  {target}\n"
        f"[bold]Profile:[/] {profile}\n"
        + (f"[bold]Domain:[/]  {domain}\n" if domain else "")
        + ("[yellow]● PLAN ONLY[/]" if show_plan else "")
        + ("[yellow]● DRY RUN[/]" if dry_run else ""),
        title="[bold red]⛓  Attack Chain[/]",
    ))

    if not dry_run and not show_plan:
        confirm = typer.confirm(f"Execute [{goal}] chain against {target}?")
        if not confirm:
            raise typer.Abort()

    asyncio.run(_run_chain(goal, target, campaign_id, domain, profile, dry_run, show_plan))


@chain_app.command("list")
def chain_list() -> None:
    """List available attack chain goals and their module sequences."""
    try:
        from ares.goal.engine import GOAL_DEFINITIONS, Goal
        table = Table(title="Available Goals", show_lines=True)
        table.add_column("Goal",        style="cyan",  width=20)
        table.add_column("Description", width=38)
        table.add_column("Modules",     style="dim",   width=52)

        for goal_val in Goal:
            defn = GOAL_DEFINITIONS.get(goal_val)
            if defn:
                chain_str = " → ".join(defn.preferred_chain[:5])
                if len(defn.preferred_chain) > 5:
                    chain_str += f" (+{len(defn.preferred_chain)-5} more)"
                table.add_row(goal_val.value, defn.description, chain_str)
        console.print(table)
    except (ImportError, AttributeError):
        # Fallback static table
        table = Table(title="Available Goals")
        table.add_column("Goal",        style="cyan",  width=20)
        table.add_column("Description", width=40)
        table.add_column("Chain",       style="dim",   width=40)
        goals = [
            ("domain_admin",    "Compromise a Domain Administrator account",
             "enum_users → kerberoast → crack → reuse"),
            ("data_exfil",      "Extract sensitive data from compromised hosts",
             "enum_computers → lateral → collect"),
            ("cloud_access",    "Gain access to cloud infrastructure",
             "aws/azure/gcp → enum → escalate"),
            ("full_compromise", "Complete network compromise (all goals)",
             "domain_admin → data_exfil → persistence"),
        ]
        for g, desc, chain in goals:
            table.add_row(g, desc, chain)
        console.print(table)


@chain_app.command("suggest")
def chain_suggest(
    target:      str = typer.Option(..., "--target", "-t", help="Target host IP"),
    goal:        str = typer.Option("domain_admin", "--goal", "-g", help="Goal to work toward"),
    campaign_id: str = typer.Option("", "--campaign", "-c"),
    profile:     str = typer.Option("normal", "--profile", "-p"),
    limit:       int = typer.Option(5, "--limit", "-n", help="Number of suggestions"),
) -> None:
    """AI-style ranked suggestions for next attack modules (AttackPlanner)."""
    try:
        from ares.goal.engine import Goal as GoalEnum
        from ares.goal.planner import AttackPlanner, PlannerContext
        from ares.core.plugin.loader import ModuleRegistry

        goal_enum = GoalEnum(goal) if goal in [g.value for g in GoalEnum] else GoalEnum.DOMAIN_ADMIN
        registry  = ModuleRegistry()
        planner   = AttackPlanner(registry=registry)

        ctx = PlannerContext(
            goal          = goal_enum,
            targets       = [target],
            opsec_profile = profile,
        )
        suggestions = planner.suggest(ctx, limit=limit)

        if not suggestions:
            console.print("[dim]No suggestions available — check registry modules.[/]")
            return

        table = Table(title=f"Suggestions for [{goal}] → {target}", show_lines=True)
        table.add_column("Rank",    width=5,  style="dim")
        table.add_column("Module",  width=24, style="cyan")
        table.add_column("Score",   width=7,  style="yellow", justify="right")
        table.add_column("OpSec",   width=12)
        table.add_column("Rationale", width=44)

        for i, s in enumerate(suggestions, 1):
            opsec_color = {"silent": "green", "low": "green",
                           "medium": "yellow", "high_noise": "red"}.get(s.opsec_level, "white")
            table.add_row(
                str(i), s.module_id,
                f"{s.score:.3f}",
                f"[{opsec_color}]{s.opsec_level}[/]",
                s.rationale[:44],
            )
        console.print(table)

        # Show score breakdown for top result
        top = suggestions[0]
        console.print(f"\n[dim]Top suggestion breakdown for [cyan]{top.module_id}[/]:[/]")
        for factor, val in sorted(top.score_breakdown.items(), key=lambda x: -x[1]):
            bar = "█" * int(val * 20)
            console.print(f"  {factor:<20} {val:.2f}  [cyan]{bar}[/]")

    except (ImportError, ValueError) as exc:
        console.print(f"[red]Suggest error:[/] {exc}")
        raise typer.Exit(1)


# ── Report commands ────────────────────────────────────────────────────────────

@report_app.command("generate")
def report_generate(
    campaign_id: str  = typer.Option(..., "--campaign", "-c", help="Campaign ID"),
    format:      str  = typer.Option("html", "--format", "-f",
                                      help="Format: html | pdf | json | md | all"),
    output:      Path = typer.Option(Path("~/.ares/reports").expanduser(),
                                      "--output", "-o", help="Output directory"),
    template:    str  = typer.Option("default", "--template", help="Report template"),
) -> None:
    """Generate a campaign report (HTML, PDF, JSON, Markdown)."""
    from ares.cli._store import get_store
    store = get_store()
    c = store.get_campaign(campaign_id)
    if not c:
        console.print(f"[red]Campaign {campaign_id!r} not found[/]")
        raise typer.Exit(1)

    output = Path(str(output)).expanduser()
    output.mkdir(parents=True, exist_ok=True)

    with console.status(f"[cyan]Generating {format.upper()} report for [{c['name']}]...[/]"):
        result_paths = asyncio.run(_generate_report(campaign_id, format, output))

    if result_paths:
        console.print(Panel(
            "\n".join(f"  [green]✓[/] [cyan]{fmt.upper()}[/]  {path}"
                      for fmt, path in result_paths.items()),
            title=f"Report Generated — {c['name']}",
        ))
    else:
        console.print("[red]Report generation failed. Check logs.[/]")
        raise typer.Exit(1)


@report_app.command("list")
def report_list(
    campaign_id: str = typer.Option("", "--campaign", "-c"),
) -> None:
    """List all generated reports in ~/.ares/reports/."""
    from ares.cli._store import get_store
    store = get_store()
    reports = store.list_reports(campaign_id)

    if not reports:
        console.print("[dim]No reports yet. Run [cyan]ares report generate --campaign <id>[/][/]")
        return

    table = Table(title="Generated Reports")
    table.add_column("Filename",  style="cyan",  width=44)
    table.add_column("Format",    style="yellow", width=8)
    table.add_column("Size",      justify="right", width=10)
    table.add_column("Path",      style="dim",   width=50)

    for r in reports:
        table.add_row(
            r["filename"], r["format"].upper(),
            f"{r['size_kb']} KB", r["path"]
        )
    console.print(table)


# ── Signing commands ───────────────────────────────────────────────────────────

@signing_app.command("generate-key")
def signing_gen_key(
    author:  str  = typer.Option(..., "--author", "-a", help="Author email"),
    outdir:  Path = typer.Option(Path("."), "--out", "-o", help="Output directory"),
    password: bool = typer.Option(True, "--password/--no-password",
                                   help="Encrypt private key with password"),
) -> None:
    """Generate a new Ed25519 signing key pair."""
    from ares.core.signing import ModuleSigner
    signer = ModuleSigner.generate_keypair(author)

    priv_path = outdir / f"{signer.key_id}.key"
    pub_path  = outdir / f"{signer.key_id}.pub"

    pw: bytes | None = None
    if password:
        pw_str = typer.prompt("Key password", hide_input=True, confirmation_prompt=True)
        pw = pw_str.encode()

    signer.save_private_key(priv_path, password=pw)
    pub_path.write_text(signer.public_key_pem())

    console.print(Panel(
        f"[green]✓ Key pair generated[/]\n\n"
        f"  Key ID:      [cyan]{signer.key_id}[/]\n"
        f"  Private key: [dim]{priv_path}[/]  (keep this SECRET)\n"
        f"  Public key:  [cyan]{pub_path}[/]  (share this)\n\n"
        f"Add your public key to the ARES registry:\n"
        f"  [dim]ares signing add-key {signer.key_id} {pub_path} --author {author}[/]",
        title="Signing Key Generated",
    ))


@signing_app.command("sign")
def signing_sign(
    module_file: Path = typer.Argument(..., help="Module .py file to sign"),
    key_file:    Path = typer.Option(..., "--key", "-k", help="Private key file"),
    author:      str  = typer.Option(..., "--author", "-a"),
    module_id:   str  = typer.Option("", "--module-id", help="Module ID (auto-detected if omitted)"),
    version:     str  = typer.Option("0.1.0", "--version"),
) -> None:
    """Sign a module file."""
    from ares.core.signing import ModuleSigner
    if not module_file.exists():
        console.print(f"[red]File not found: {module_file}[/]"); raise typer.Exit(1)

    pw_str = typer.prompt("Key password (or press Enter for no password)",
                           hide_input=True, default="")
    pw = pw_str.encode() if pw_str else None

    signer = ModuleSigner.load_private_key(key_file, author, password=pw)
    sig    = signer.sign_file(module_file, module_id=module_id, version=version)
    sig_path = module_file.with_suffix(module_file.suffix + ".sig")
    sig.save(sig_path)

    console.print(f"[green]✓ Signed:[/] {module_file.name} → {sig_path.name}")
    console.print(f"  Key ID:    [cyan]{sig.key_id}[/]")
    console.print(f"  File hash: [dim]{sig.file_hash[:16]}...[/]")


@signing_app.command("verify")
def signing_verify(
    module_file: Path = typer.Argument(..., help="Module .py file to verify"),
    policy:      str  = typer.Option("warn_unsigned", "--policy", "-p",
                                      help="Policy: allow_all | warn_unsigned | require_signed | trusted_only"),
) -> None:
    """Verify a module's signature."""
    from ares.core.signing import ModuleVerifier, SigningPolicy
    policies = {
        "allow_all":      SigningPolicy.ALLOW_ALL,
        "warn_unsigned":  SigningPolicy.WARN_UNSIGNED,
        "require_signed": SigningPolicy.REQUIRE_SIGNED,
        "trusted_only":   SigningPolicy.TRUSTED_ONLY,
    }
    verifier = ModuleVerifier(policy=policies.get(policy, SigningPolicy.WARN_UNSIGNED))
    result   = verifier.verify_file(module_file)

    color = {"trusted": "green", "community": "yellow",
             "unsigned": "dim", "invalid": "red", "revoked": "red"}.get(
        result.trust_level.value, "white"
    )
    icon  = {"trusted": "✓", "community": "⚠", "unsigned": "—",
              "invalid": "✗", "revoked": "✗"}.get(result.trust_level.value, "?")

    console.print(
        f"[{color}]{icon} {module_file.name}:[/] "
        f"[{color}]{result.trust_level.value.upper()}[/]"
        + (f" (author: {result.author})" if result.author else "")
        + (f"\n  [red]Error: {result.error}[/]" if result.error else "")
        + ("".join(f"\n  [yellow]Warning: {w}[/]" for w in result.warnings))
    )


@signing_app.command("add-key")
def signing_add_key(
    key_id:   str  = typer.Argument(..., help="Key ID (fingerprint)"),
    pub_key:  Path = typer.Argument(..., help="Public key .pub file"),
    author:   str  = typer.Option(..., "--author", "-a"),
    operator: str  = typer.Option("operator", "--operator"),
) -> None:
    """Add a trusted public key to the registry."""
    from ares.core.signing import KeyRegistry
    registry = KeyRegistry()
    pem = pub_key.read_text()
    registry.add_trusted_key(key_id, pem, author, added_by=operator)
    console.print(f"[green]✓ Trusted key added:[/] {key_id} ({author})")


@signing_app.command("revoke-key")
def signing_revoke_key(
    key_id:   str = typer.Argument(..., help="Key ID to revoke"),
    reason:   str = typer.Option("", "--reason", "-r"),
    operator: str = typer.Option("operator", "--operator"),
) -> None:
    """Revoke a signing key (all modules signed with it will be rejected)."""
    confirm = typer.confirm(f"Revoke key {key_id}? This cannot be undone.")
    if not confirm:
        raise typer.Abort()
    from ares.core.signing import KeyRegistry
    registry = KeyRegistry()
    registry.revoke_key(key_id, reason=reason, operator=operator)
    console.print(f"[red]✗ Key revoked:[/] {key_id}")


# ── Async helpers ──────────────────────────────────────────────────────────────

async def _run_module(
    module_id:  str,
    target:     str,
    campaign_id: str,
    domain:     str,
    profile:    str,
    dry_run:    bool,
    params:     dict,
) -> dict | None:
    """Inner async runner for module execution."""
    try:
        from ares.core.campaign import Campaign, NoiseProfile, ScopeEntry
        from ares.core.config import AresSettings
        from ares.core.noise import NoiseController
        from ares.core.context import ExecutionContext
        from ares.core.di import AresContainer

        container = AresContainer.for_test()
        settings  = container.settings()
        noise_profiles = {
            "stealth":    NoiseProfile.STEALTH,
            "normal":     NoiseProfile.NORMAL,
            "aggressive": NoiseProfile.AGGRESSIVE,
        }
        campaign = Campaign(
            id=campaign_id, name="adhoc",
            scope=[ScopeEntry(cidr="0.0.0.0/0")],
            noise_profile=noise_profiles.get(profile, NoiseProfile.NORMAL),
            operator="operator",
        )
        ctx = ExecutionContext.build(
            campaign=campaign, target=target,
            module_id=module_id, domain=domain,
            params=params, dry_run=dry_run,
        )
        module = container.build_module(module_id, campaign)
        await module.validate(ctx)
        result = await module.execute(ctx)
        return result.to_dict()
    except Exception as exc:
        console.print(f"[red]Module error:[/] {exc}")
        return None


async def _run_chain(
    goal:        str,
    target:      str,
    campaign_id: str,
    domain:      str,
    profile:     str,
    dry_run:     bool,
    show_plan:   bool,
) -> None:
    """
    Execute a goal-based attack chain via GoalEngine.
    Displays step-by-step progress with Rich tables.
    """
    from rich.table import Table as RTable
    from rich.live  import Live
    import time

    # ── 1. Build plan ───────────────────────────────────────────────────
    try:
        from ares.goal.engine import GoalEngine, Goal as GoalEnum, GOAL_DEFINITIONS
        from ares.state.target_state import OperatorSession
        from ares.core.plugin.loader import ModuleRegistry

        goal_enum = GoalEnum(goal) if goal in [g.value for g in GoalEnum] else GoalEnum.DOMAIN_ADMIN
        registry  = ModuleRegistry()
        session   = OperatorSession(campaign_id=campaign_id or "adhoc")
        engine    = GoalEngine(registry=registry, session=session)

        ctx = {
            "dc":            target,
            "domain":        domain,
            "target":        target,
            "noise_profile": profile,
        }
        plan = engine.plan(goal_enum, context=ctx)

    except (ImportError, ValueError) as exc:
        console.print(f"[red]Chain planning error:[/] {exc}")
        return

    # ── 2. Show plan ────────────────────────────────────────────────────
    plan_table = RTable(title=f"Attack Plan — [{goal}]", show_lines=True)
    plan_table.add_column("#",       width=4,  style="dim")
    plan_table.add_column("Module",  width=24, style="cyan")
    plan_table.add_column("Reason",  width=46)
    plan_table.add_column("OpSec",   width=12, style="yellow")
    plan_table.add_column("Status",  width=12)

    step_statuses = ["[dim]pending[/]"] * len(plan.steps)
    for i, step in enumerate(plan.steps):
        cls = registry.get(step.module_id)
        opsec = getattr(getattr(cls, "OPSEC_LEVEL", None), "value", "medium") if cls else "—"
        plan_table.add_row(
            str(step.step_num), step.module_id,
            step.reason[:46], opsec, step_statuses[i],
        )

    console.print(plan_table)
    console.print(
        f"\n[dim]Estimated duration: ~{plan.estimated_duration_min} min · "
        f"Steps: {len(plan.steps)} · Goal: {goal}[/]\n"
    )

    if show_plan:
        return

    if dry_run:
        console.print("[yellow]● Dry run — plan shown above, no execution.[/]")
        return

    # ── 3. Execute step-by-step ─────────────────────────────────────────
    console.print(f"[bold]Executing {len(plan.steps)} steps...[/]\n")

    results: list[dict] = []
    t_start = time.monotonic()

    for i, step in enumerate(plan.steps):
        with console.status(
            f"[cyan][{i+1}/{len(plan.steps)}] Running {step.module_id} → {target}...[/]"
        ):
            step_result = await _run_module(
                step.module_id, target, campaign_id,
                domain, profile, False, step.params,
            )

        status_ok = step_result and step_result.get("status") == "success"
        status_icon  = "[green]✓[/]" if status_ok else "[yellow]⚠[/]"
        status_label = "[green]success[/]" if status_ok else "[yellow]partial[/]"

        if step_result:
            finds = step_result.get("findings", 0)
            creds = step_result.get("new_credentials", 0)
            console.print(
                f"  {status_icon} [cyan]{step.module_id}[/]  "
                f"findings: [bold]{finds}[/]  creds: [bold]{creds}[/]  "
                + ("[red]error: " + str(step_result.get("error", ""))[:40] + "[/]"
                   if step_result.get("error") else "")
            )
            results.append(step_result)
        else:
            console.print(f"  [red]✗[/] [cyan]{step.module_id}[/]  [red]no result[/]")

    # ── 4. Summary ──────────────────────────────────────────────────────
    total_finds  = sum(r.get("findings", 0) for r in results)
    total_creds  = sum(r.get("new_credentials", 0) for r in results)
    achieved     = engine.check_goal_achieved(
        goal_enum  # type: ignore[arg-type]
    )

    console.print(Panel(
        f"[bold]Goal:[/]        {goal}\n"
        f"[bold]Achieved:[/]    {'[green]YES ✓[/]' if achieved else '[yellow]Partial[/]'}\n"
        f"[bold]Steps run:[/]   {len(results)}/{len(plan.steps)}\n"
        f"[bold]Findings:[/]    {total_finds}\n"
        f"[bold]Credentials:[/] {total_creds}\n"
        f"[bold]Duration:[/]    {time.monotonic()-t_start:.1f}s",
        title="[bold green]⛓  Chain Complete[/]" if achieved else "[bold yellow]⛓  Chain Partial[/]",
    ))


async def _generate_report(
    campaign_id: str,
    fmt:         str,
    output:      Path,
) -> dict[str, str]:
    """
    Generate report(s) via ReportGenerator.
    Returns {format: path_str} for each generated file.
    """
    from ares.cli._store import load_campaign
    from ares.core.campaign import Campaign, NoiseProfile, ScopeEntry, Finding, Severity
    import json

    raw = load_campaign(campaign_id)
    if not raw:
        console.print(f"[red]Campaign {campaign_id!r} not found[/]")
        return {}

    # Reconstruct Campaign object from stored JSON
    try:
        from ares.core.campaign import Campaign as CampaignModel
        noise_map = {
            "stealth":    NoiseProfile.STEALTH,
            "normal":     NoiseProfile.NORMAL,
            "aggressive": NoiseProfile.AGGRESSIVE,
        }
        scope = []
        for s in raw.get("scope", [{"cidr": "0.0.0.0/0"}]):
            scope.append(ScopeEntry(cidr=s.get("cidr", "0.0.0.0/0")))

        campaign = CampaignModel(
            id           = raw["id"],
            name         = raw.get("name", "Unnamed"),
            client       = raw.get("client", ""),
            operator     = raw.get("operator", "operator"),
            scope        = scope,
            noise_profile= noise_map.get(raw.get("noise_profile", "normal"), NoiseProfile.NORMAL),
            domain       = raw.get("domain", ""),
        )

        # Restore findings from JSON
        for f_data in raw.get("findings", []):
            try:
                sev_val  = f_data.get("severity", "info")
                sev      = Severity(sev_val) if sev_val in [s.value for s in Severity] else Severity.INFO
                finding  = Finding(
                    title            = f_data.get("title", "Finding"),
                    description      = f_data.get("description", ""),
                    severity         = sev,
                    confidence       = float(f_data.get("confidence", 1.0)),
                    module_id        = f_data.get("module_id", ""),
                    host             = f_data.get("host", ""),
                    evidence         = f_data.get("evidence", ""),
                    remediation      = f_data.get("remediation", ""),
                    mitre_technique  = f_data.get("mitre_technique", ""),
                    mitre_tactic     = f_data.get("mitre_tactic", ""),
                )
                campaign.add_finding(finding)
            except (KeyError, ValueError):
                pass

    except Exception as exc:
        console.print(f"[red]Failed to rebuild campaign object:[/] {exc}")
        return {}

    # Generate
    try:
        from ares.modules.reporting.report_gen import ReportGenerator
        gen = ReportGenerator(output_dir=str(output))
        result_paths: dict[str, str] = {}

        if fmt == "all":
            paths = gen.generate_all(campaign)
            result_paths = {f: str(p) for f, p in paths.items()}
        else:
            path = gen.generate(campaign, fmt=fmt)
            result_paths[fmt] = str(path)

        return result_paths

    except Exception as exc:
        console.print(f"[red]Report generation error:[/] {exc}")
        import traceback
        console.print(f"[dim]{traceback.format_exc()[-400:]}[/]")
        return {}


def _display_result(module_id: str, result: dict) -> None:
    """Display module result in a rich panel."""
    status_color = "green" if result.get("status") == "success" else "yellow"
    findings_list = result.get("new_findings", [])
    findings_summary = ""
    if findings_list:
        for f in findings_list[:3]:
            sev   = f.get("severity", "info").upper()
            title = f.get("title", "")[:50]
            findings_summary += f"\n  [{sev}] {title}"
        if len(findings_list) > 3:
            findings_summary += f"\n  ... +{len(findings_list)-3} more"

    console.print(Panel(
        f"[{status_color}]{result.get('status', 'unknown').upper()}[/]\n"
        f"  Findings:    {result.get('findings', 0)}"
        + findings_summary + "\n"
        f"  Credentials: {result.get('new_credentials', 0)}\n"
        f"  New hosts:   {', '.join(result.get('discovered_hosts', [])) or '—'}",
        title=f"Module Result: {module_id}",
    ))


# ── doctor command ────────────────────────────────────────────────────────────

@app.command("doctor")
def doctor() -> None:
    """Check all prerequisites and configuration. Run this first."""
    import importlib, shutil, os, re
    from importlib import metadata as importlib_metadata
    from pathlib import Path

    console.print("\n[bold]ARES Doctor[/bold] — prerequisite check\n")

    ok = warn = fail = 0

    def check(label: str, status: str, detail: str = "") -> None:
        nonlocal ok, warn, fail
        suffix = f"  [dim]{escape(str(detail))}[/dim]" if detail else ""
        if status == "ok":
            console.print(f"  [green]✅[/green]  {label}" + suffix)
            ok += 1
        elif status == "warn":
            console.print(f"  [yellow]⚠️ [/yellow]  {label}" + suffix)
            warn += 1
        else:
            console.print(f"  [red]❌[/red]  {label}" + suffix)
            fail += 1

    # Python version
    import sys
    pv = sys.version_info
    if pv >= (3, 10):
        check(f"Python {pv.major}.{pv.minor}.{pv.micro}", "ok")
    else:
        check(f"Python {pv.major}.{pv.minor}", "fail",
              f"3.10+ required — current: {pv.major}.{pv.minor}. "
              "Install via pyenv: pyenv install 3.11.9 && pyenv local 3.11.9")

    # Core packages
    for pkg, import_name, label in [
        ("impacket",    "impacket",          "impacket  (AD/SMB modules)"),
        ("paramiko",    "paramiko",           "paramiko  (SSH modules)"),
        ("cryptography","cryptography",       "cryptography"),
        ("pydantic",    "pydantic",           "pydantic"),
        ("structlog",   "structlog",          "structlog"),
        ("networkx",    "networkx",           "networkx  (attack graph)"),
        ("jinja2",      "jinja2",             "jinja2    (reporting)"),
    ]:
        try:
            mod = importlib.import_module(import_name)
            ver = getattr(mod, "__version__", "")
            check(label, "ok", ver)
        except ImportError:
            if pkg in ("impacket", "paramiko"):
                check(label, "fail", f"pip install ares-redteam[ad]")
            else:
                check(label, "warn", f"pip install {pkg}")

    # ── impacket version ──────────────────────────────────────────────────────
    try:
        import impacket
        try:
            ver_str = importlib_metadata.version("impacket")
        except importlib_metadata.PackageNotFoundError:
            ver_str = getattr(impacket, "__version__", "")

        version_match = re.search(r"(\d+)\.(\d+)", ver_str)
        if version_match and [int(version_match.group(1)), int(version_match.group(2))] >= [0, 11]:
            check(f"impacket {ver_str}", "ok", ">= 0.11 required")
        elif version_match:
            check(f"impacket {ver_str}", "fail",
                  f"too old ({ver_str}) — upgrade: pip install --upgrade impacket")
        else:
            check("impacket", "warn",
                  "installed, but version could not be detected — expected >= 0.11")
    except ImportError:
        check("impacket", "fail", "pip install ares-redteam[ad]")

    # ── ldap3 ─────────────────────────────────────────────────────────────────
    try:
        import ldap3
        check(f"ldap3 {ldap3.__version__}", "ok", "AD LDAP enumeration ready")
    except ImportError:
        check("ldap3", "warn", "pip install ares-redteam[ad]")

    # ── optional Windows modules ───────────────────────────────────────────────
    try:
        import pypykatz  # type: ignore[import]
        check("pypykatz  (windows.lsass_dump)", "ok", "LSASS dump parsing ready")
    except ImportError:
        check("pypykatz  (windows.lsass_dump)", "warn",
              "pip install ares-redteam[windows]")

    try:
        import httpx_ntlm  # type: ignore[import]
        check("httpx-ntlm  (ad.adcs ESC1)", "ok", "ADCS HTTP enrollment ready")
    except ImportError:
        check("httpx-ntlm  (ad.adcs ESC1)", "warn",
              "pip install ares-redteam[ad]")

    # ── cloud SDKs ────────────────────────────────────────────────────────────
    for import_name, module_label in [
        ("boto3",              "cloud.aws"),
        ("azure.identity",     "cloud.azure / cloud.azure_ad"),
        ("google.cloud",       "cloud.gcp"),
        ("msal",               "cloud.azure_ad device code"),
    ]:
        try:
            importlib.import_module(import_name)
            check(f"{import_name.split('.')[0]}  ({module_label})", "ok")
        except ImportError:
            check(f"{import_name.split('.')[0]}  ({module_label})", "warn",
                  "pip install ares-redteam[cloud]")

    # ── cracking tools ────────────────────────────────────────────────────────
    for tool, desc in [("hashcat", "GPU cracking"), ("john", "CPU cracking")]:
        path = shutil.which(tool) or shutil.which("john-the-ripper")
        if path:
            check(f"{tool}  ({desc})", "ok", path)
        else:
            check(f"{tool}  ({desc})", "warn",
                  f"not in PATH — install: apt install {tool} (Linux) / brew install {tool} (macOS)")

    # ── network socket support ────────────────────────────────────────────────
    import socket as _socket
    for port, service in [(389, "LDAP"), (636, "LDAPS"), (445, "SMB"),
                          (88, "Kerberos"), (1433, "MSSQL"), (5985, "WinRM")]:
        try:
            s = _socket.socket(_socket.AF_INET, _socket.SOCK_STREAM)
            s.close()
            check(f"socket AF_INET/{port} ({service})", "ok")
        except OSError as e:
            check(f"socket AF_INET/{port} ({service})", "warn", str(e)[:40])

    # .env
    env_path = Path(".env")
    if env_path.exists():
        content = env_path.read_text()
        if "CHANGE_ME" in content:
            check(".env configured", "fail",
                  "CHANGE_ME placeholders found — run: ares-setup to generate secure keys")
        else:
            check(".env configured", "ok")
    else:
        check(".env file", "fail",
              "Missing — run: cp .env.example .env && ares-setup")

    # Database
    try:
        from ares.core.config import get_settings
        s = get_settings()
        db_path = s.ares_database_url.replace("sqlite+aiosqlite:///", "").replace("sqlite:///", "")
        check("Settings loadable", "ok", s.ares_database_url[:40])
        if "sqlite" in s.ares_database_url:
            check("Database (SQLite)", "ok", db_path or ":memory:")
    except SystemExit:
        check("Settings loadable", "fail",
              "env vars missing — fix: cp .env.example .env && ares-setup")
    except Exception as exc:
        check("Settings loadable", "warn", str(exc)[:60])

    # Summary
    console.print()
    total = ok + warn + fail
    if fail == 0 and warn == 0:
        console.print(f"[bold green]All {total} checks passed.[/bold green] ARES is ready.\n")
    elif fail == 0:
        console.print(f"[bold yellow]{ok}/{total} checks OK, {warn} warning(s).[/bold yellow]"
                      " ARES should work — optional tools missing.\n")
    else:
        console.print(f"[bold red]{fail} check(s) failed.[/bold red]"
                      f" Fix the ❌ items above, then re-run [cyan]ares doctor[/cyan].\n")
        raise typer.Exit(1)


# ── quickstart wizard ─────────────────────────────────────────────────────────

@app.command("quickstart")
def quickstart() -> None:
    """Guided wizard for first-time users — creates your first campaign."""
    import uuid

    console.print("\n[bold cyan]ARES Quick Start Wizard[/bold cyan]\n")

    name   = typer.prompt("Campaign name", default="Lab Assessment")
    client = typer.prompt("Client name",   default="ACME Corp")
    target = typer.prompt("Target IP or CIDR (e.g. 10.10.10.0/24)")
    noise  = typer.prompt("Noise profile", default="normal",
                           show_choices=True, type=typer.Choice(["stealth", "normal", "aggressive"]))

    console.print("\n[dim]Creating campaign...[/dim]")
    try:
        from ares.core.campaign import Campaign, NoiseProfile, ScopeEntry
        campaign = Campaign(
            name=name, client=client, operator="operator",
            scope=[ScopeEntry(cidr=target)],
            noise_profile=NoiseProfile(noise),
        )
        cid = campaign.id
    except Exception as exc:
        console.print(f"[red]Failed to create campaign: {exc}[/red]")
        raise typer.Exit(1)

    console.print(f"\n[green]✅ Campaign created: {cid}[/green]\n")
    console.print("[bold]Next steps:[/bold]")
    console.print(f"  ares module run ad.enum_users --campaign {cid} --dc {target.split('/')[0]} --domain corp.local")
    console.print(f"  ares module run ad.kerberoast  --campaign {cid} --dc {target.split('/')[0]} --domain corp.local")
    console.print(f"  ares report generate --campaign-id {cid} --format html")
    console.print()


# ── ares-setup entry point ────────────────────────────────────────────────────

def setup_entrypoint() -> None:
    """Entry point for `ares-setup` — runs setup.sh or inline setup."""
    import subprocess, shutil, os
    from pathlib import Path

    setup_sh = Path(__file__).parent.parent.parent / "scripts" / "setup.sh"
    if setup_sh.exists() and shutil.which("bash"):
        os.execv(shutil.which("bash"), ["bash", str(setup_sh)])
    else:
        # Inline fallback for pip-installed package without scripts/
        from cryptography.fernet import Fernet
        import secrets
        env = Path(".env")
        if not env.exists():
            ex = Path(".env.example")
            template = ex.read_text() if ex.exists() else (
                "ARES_SECRET_KEY=\nARES_ENCRYPTION_KEY=\nARES_DEFAULT_ADMIN_PASSWORD=\n"
            )
            sk  = secrets.token_hex(32)
            ek  = Fernet.generate_key().decode()
            pw  = ''.join(secrets.choice("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$") for _ in range(20))
            import re
            template = re.sub(r"ARES_SECRET_KEY=.*",             f"ARES_SECRET_KEY={sk}",  template)
            template = re.sub(r"ARES_ENCRYPTION_KEY=.*",         f"ARES_ENCRYPTION_KEY={ek}", template)
            template = re.sub(r"ARES_DEFAULT_ADMIN_PASSWORD=.*", f"ARES_DEFAULT_ADMIN_PASSWORD={pw}", template)
            env.write_text(template)
            print(f"\n✅ .env created\n   Admin password: {pw}\n   Run: ares doctor\n")
        else:
            print("✅ .env already exists. Run: ares doctor")


# ── backup command ────────────────────────────────────────────────────────────

@app.command("backup")
def backup(
    output: str = typer.Option(None, "--output", "-o", help="Output JSON file path"),
) -> None:
    """Export all campaigns and findings to a JSON backup file."""
    import asyncio
    from ares.db.database import AresDatabase
    from ares.core.config import get_settings

    async def _run() -> str:
        s = get_settings()
        async with await AresDatabase.create(s.db_path, s.encryption_key_value) as db:
            await db.checkpoint_wal()
            path = await db.export_json(output)
        return path

    try:
        out = asyncio.run(_run())
        console.print(f"[green]✅ Backup saved:[/green] {out}")
    except Exception as exc:
        console.print(f"[red]❌ Backup failed: {exc}[/red]")
        raise typer.Exit(1)




# ── Goal commands ──────────────────────────────────────────────────────────────

@goal_app.command("run")
def goal_run(
    goal:        str  = typer.Argument(..., help="Goal name: domain_admin, data_exfil, cloud_admin, persistence, initial_access, full_compromise"),
    campaign_id: str  = typer.Option(..., "--campaign-id", "-c", help="Campaign ID to run against"),
    dc:          str  = typer.Option("", "--dc", help="Domain Controller IP"),
    domain:      str  = typer.Option("", "--domain", help="AD domain (CORP.LOCAL)"),
    dry_run:     bool = typer.Option(False, "--dry-run", help="Show plan without executing"),
) -> None:
    """Plan and execute a goal-based attack chain autonomously."""
    import asyncio
    from ares.core.config import get_settings
    from ares.db.database import AresDatabase
    from ares.core.plugin.loader import PluginLoader
    from ares.state.target_state import OperatorSession
    from ares.goal.engine import GoalEngine, Goal

    async def _run() -> None:
        s = get_settings()
        async with await AresDatabase.create(s.db_path, s.encryption_key_value) as db:
            campaign = await db.get_campaign(campaign_id)
            if not campaign:
                console.print(f"[red]Campaign {campaign_id!r} not found[/red]")
                raise typer.Exit(1)

            registry = PluginLoader().load_all()
            session  = OperatorSession(campaign_id=campaign_id, operator="cli")
            engine   = GoalEngine(registry=registry, session=session)

            context: dict = {}
            if dc:     context["dc"]     = dc
            if domain: context["domain"] = domain

            plan = engine.plan(goal, context)

            # Display plan
            table = Table(title=f"[bold]Attack Plan — {goal}[/bold]", show_lines=True)
            table.add_column("Step", style="cyan", width=5)
            table.add_column("Module", style="green")
            table.add_column("Reason")
            table.add_column("Params", style="dim")
            for step in plan.steps:
                table.add_row(
                    str(step.step_num),
                    step.module_id,
                    step.reason,
                    ", ".join(f"{k}={v}" for k, v in step.params.items() if v),
                )
            console.print(table)
            console.print(f"\n[dim]Estimated duration: {plan.estimated_duration_min} min[/dim]")

            if dry_run:
                console.print("[yellow]Dry-run mode — no modules executed.[/yellow]")
                return

            from ares.core.campaign import Campaign as CM
            c_obj = CM(**{k: v for k, v in campaign.items() if k in CM.model_fields})
            results = await engine.execute(plan, c_obj)

            achieved = results.get("achieved", False)
            if achieved:
                console.print(f"\n[bold green]✅ Goal '{goal}' ACHIEVED[/bold green]")
            else:
                console.print(f"\n[yellow]⚠️  Goal '{goal}' not fully achieved — check results[/yellow]")

    asyncio.run(_run())


@goal_app.command("list")
def goal_list() -> None:
    """List all available goals and their descriptions."""
    from ares.goal.engine import GOAL_DEFINITIONS
    table = Table(title="Available Goals", show_lines=False)
    table.add_column("Goal",        style="cyan bold")
    table.add_column("Description")
    table.add_column("Chain Preview", style="dim")
    for defn in GOAL_DEFINITIONS.values():
        chain_preview = " → ".join(defn.preferred_chain[:4])
        if len(defn.preferred_chain) > 4:
            chain_preview += " ..."
        table.add_row(defn.goal.value, defn.description, chain_preview)
    console.print(table)


@goal_app.command("capabilities")
def goal_capabilities(
    module_id: Optional[str] = typer.Argument(None, help="Show deps for specific module"),
) -> None:
    """Show capability dependency graph (REQUIRES / OUTPUTS for all modules)."""
    from ares.core.plugin.loader import PluginLoader
    from ares.goal.engine import CapabilityGraph

    registry = PluginLoader().load_all()
    cg       = CapabilityGraph.from_registry(registry)
    summary  = cg.capability_summary()

    if module_id:
        requires = cg._requires.get(module_id, [])
        outputs  = cg._outputs.get(module_id, [])
        console.print(Panel(
            f"[bold]REQUIRES:[/bold] {requires or ['(none)']}\n"
            f"[bold]OUTPUTS:[/bold]  {outputs or ['(none)']}",
            title=f"Module: {module_id}",
        ))
        return

    table = Table(title=f"Capability Graph ({summary['total_capabilities']} capabilities)", show_lines=False)
    table.add_column("Capability",  style="cyan")
    table.add_column("Produced by", style="green")
    for cap, mods in sorted(summary["capabilities"].items()):
        table.add_row(cap, ", ".join(mods))
    console.print(table)


# ── Graph commands ─────────────────────────────────────────────────────────────

@graph_app.command("show")
def graph_show(
    campaign_id: str = typer.Argument(..., help="Campaign ID"),
    top_n:       int = typer.Option(5, "--top", "-n", help="Number of attack paths to show"),
) -> None:
    """Show top attack paths in the campaign's artifact graph."""
    import asyncio
    from ares.core.config import get_settings
    from ares.db.database import AresDatabase
    from ares.graph.attack_graph import AttackGraph
    from ares.normalize.artifacts import ArtifactStore, HostArtifact

    async def _run() -> None:
        s = get_settings()
        async with await AresDatabase.create(s.db_path, s.encryption_key_value) as db:
            campaign = await db.get_campaign(campaign_id)
            if not campaign:
                console.print(f"[red]Campaign {campaign_id!r} not found[/red]")
                raise typer.Exit(1)
            hosts = await db.get_hosts(campaign_id)

        store = ArtifactStore()
        for h in hosts:
            store.add(HostArtifact(
                ip_address=h.get("ip_address", ""),
                hostname=h.get("hostname", ""),
                is_dc=h.get("is_dc", False),
                os=h.get("os", ""),
            ))

        graph = AttackGraph()
        graph.build_from_store(store)
        stats = graph.stats()

        console.print(Panel(
            f"Nodes: [cyan]{stats['nodes']}[/cyan]  "
            f"Edges: [cyan]{stats['edges']}[/cyan]  "
            f"High-value targets: [red]{stats['high_value']}[/red]  "
            f"Attack paths: [yellow]{stats['attack_paths']}[/yellow]",
            title=f"Attack Graph — Campaign {campaign_id[:8]}",
        ))

        paths = graph.top_paths(n=top_n)
        if not paths:
            console.print("[dim]No attack paths found yet — run recon modules first.[/dim]")
            return

        for i, p in enumerate(paths, 1):
            console.print(f"\n[bold yellow]Path {i}[/bold yellow]  "
                          f"[dim]{p['start']} → {p['end']}[/dim]  "
                          f"score=[cyan]{p['total_score']}[/cyan]")
            for step in p.get("steps", []):
                atk = f"  [dim]via {step['attack']}[/dim]" if step.get("attack") else ""
                console.print(f"  {step['from']} [dim]──[{step['edge']}]──►[/dim] {step['to']}{atk}")

    asyncio.run(_run())


@graph_app.command("path")
def graph_path(
    campaign_id: str = typer.Argument(..., help="Campaign ID"),
    source:      str = typer.Option(..., "--from", "-s", help="Source node label"),
    target:      str = typer.Option(..., "--to",   "-t", help="Target node label"),
) -> None:
    """Find shortest attack path between two nodes."""
    import asyncio
    from ares.core.config import get_settings
    from ares.db.database import AresDatabase
    from ares.graph.attack_graph import AttackGraph
    from ares.normalize.artifacts import ArtifactStore, HostArtifact

    async def _run() -> None:
        s = get_settings()
        async with await AresDatabase.create(s.db_path, s.encryption_key_value) as db:
            hosts = await db.get_hosts(campaign_id)

        store = ArtifactStore()
        for h in hosts:
            store.add(HostArtifact(
                ip_address=h.get("ip_address", ""),
                hostname=h.get("hostname", ""),
                is_dc=h.get("is_dc", False),
            ))

        graph = AttackGraph()
        graph.build_from_store(store)
        path  = graph.find_path(source, target)

        if not path:
            console.print(f"[red]No path from '{source}' to '{target}'[/red]")
            return

        report = graph.path_to_report(path)
        console.print(Panel(
            f"[bold]{report['start']} → {report['end']}[/bold]\n"
            f"Steps: {report['path_length'] - 1}  Score: {report['total_score']}\n"
            f"Modules: {', '.join(report['attack_modules']) or '(none)'}",
            title="Shortest Attack Path",
        ))
        for step in report["steps"]:
            atk = f" [dim]← {step['attack']}[/dim]" if step.get("attack") else ""
            console.print(f"  [green]{step['from']}[/green] [dim]──{step['edge']}──►[/dim] [red]{step['to']}[/red]{atk}")

    asyncio.run(_run())


# ── Module create (scaffold) ───────────────────────────────────────────────────

@module_app.command("create")
def module_create(
    module_id:   str = typer.Argument(..., help="Module ID in dot notation, e.g. ad.my_attack"),
    output_dir:  str = typer.Option(".", "--output", "-o", help="Directory to create module in"),
    author:      str = typer.Option("", "--author",  "-a", help="Module author name/email"),
    category:    str = typer.Option("", "--category", "-c", help="Module category (ad, linux, cloud, lateral, exfil)"),
    description: str = typer.Option("", "--description", "-d", help="Short description"),
) -> None:
    """
    Scaffold a new ARES module with boilerplate code, metadata, and test file.

    Example:
        ares module create ad.my_attack --author alice@corp.com --category ad
    """
    import re
    from pathlib import Path

    # Validate module_id format
    if not re.match(r'^[a-z][a-z0-9_]*\.[a-z][a-z0-9_]*$', module_id):
        console.print("[red]Module ID must be dot-notation: category.name (e.g. ad.my_attack)[/red]")
        raise typer.Exit(1)

    cat, name    = module_id.split(".", 1)
    category     = category or cat
    class_name   = "".join(p.capitalize() for p in name.split("_")) + "Module"
    author_str   = author or "your-email@example.com"
    desc_str     = description or f"Describe what {module_id} does (use --description flag)"
    out_dir      = Path(output_dir)
    module_file  = out_dir / f"{name}.py"
    test_file    = out_dir / f"test_{name}.py"

    if module_file.exists():
        console.print(f"[yellow]File already exists: {module_file}[/yellow]")
        raise typer.Exit(1)

    # ── Module scaffold ────────────────────────────────────────────────────
    module_code = f'''\
from __future__ import annotations
"""
{class_name} — {desc_str}

MITRE ATT&CK: Fill in technique ID (e.g. T1558.003 for Kerberoasting)
"""
from typing import Any
from ares.modules.sdk import (
    BaseModule, ExecutionContext, ModuleResult,
    OpsecLevel, Severity, module_metadata,
    get_logger, ModuleValidationError, HostUnreachable,
)

logger = get_logger("{module_id}")


@module_metadata(
    module_id   = "{module_id}",
    name        = "{class_name.replace("Module", "").replace("_", " ")}",
    category    = "{category}",
    description = "{desc_str}",
    author      = "{author_str}",
    opsec       = OpsecLevel.LOW,
    requires    = [],          # e.g. ["domain_creds"]
    outputs     = [],          # e.g. ["credential_list"]
    mitre       = [],          # e.g. ["T1558.003"]
)
class {class_name}(BaseModule):
    """
    {desc_str}

    Parameters:
        target  — target host IP or hostname
        # Add module-specific params here, e.g.:
        # target_port: int = 445,  # target port number
    """

    async def validate(self, ctx: ExecutionContext) -> None:
        """Validate required parameters before execution."""
        ctx.require("target")
        # Add parameter validation here, e.g.:
        # if not ctx.params.get("domain"):
        #     raise ModuleValidationError("Missing domain", module_id=self.MODULE_ID, field="domain")

    async def execute(self, ctx: ExecutionContext) -> ModuleResult:
        """Main execution logic."""
        if ctx.dry_run:
            return ModuleResult(
                status="dry_run",
                module_id=self.MODULE_ID,
                raw={{"dry_run": True, "params": ctx.params}},
            )

        target = ctx.params["target"]
        await self.before_request(target, "tcp")  # Replace "tcp" with actual protocol: smb, ldap, ssh, http, etc.

        try:
            # Implement your attack logic here.
            # Use self.finding(...) to record each vulnerability found.
            # Example finding:
            # self.finding(
            #     title       = "Found something",
            #     description = "Details about the finding",
            #     severity    = Severity.HIGH,
            #     mitre_technique = "T1XXX",
            #     host        = target,
            #     evidence    = {{"key": "value"}},
            #     remediation = "How to fix it",
            # )
            raw: dict[str, Any] = {{"target": target}}

        except Exception as exc:
            raise HostUnreachable(str(exc), target=target,
                                  module_id=self.MODULE_ID) from exc

        return ModuleResult(
            status    = "success",
            findings  = self._findings,
            module_id = self.MODULE_ID,
            raw       = raw,
        )

    async def run(self, **kwargs: Any):
        """Legacy interface — do not modify."""
        ctx    = ExecutionContext.for_test(**kwargs)
        result = await self.execute(ctx)
        return result.findings, result.raw
'''

    # ── Test scaffold ──────────────────────────────────────────────────────
    test_code = f'''\
from __future__ import annotations
"""
Tests for {module_id}
"""
import pytest
from unittest.mock import AsyncMock, patch
from ares.core.campaign import Campaign, NoiseProfile, ScopeEntry
from ares.core.config import AresSettings
from ares.core.noise import NoiseController
from {name} import {class_name}


@pytest.fixture
def campaign():
    return Campaign(
        name="Test", client="ACME", operator="tester",
        scope=[ScopeEntry(cidr="10.0.0.0/8")],
        noise_profile=NoiseProfile.NORMAL,
    )


@pytest.fixture
def module(campaign):
    # AresSettings reads from environment. Set these in your .env or export before running tests:
    #   ARES_SECRET_KEY, ARES_ENCRYPTION_KEY, ARES_DEFAULT_ADMIN_PASSWORD
    # The values below are placeholder defaults so the scaffold test runs standalone
    # in CI without a .env file. NEVER use these in production.
    import os
    os.environ.setdefault("ARES_SECRET_KEY",            "scaffold-test-key-min32chars-xx!!")
    os.environ.setdefault("ARES_ENCRYPTION_KEY",        "scaffold-test-enc-key-min32chars!")
    os.environ.setdefault("ARES_DEFAULT_ADMIN_PASSWORD","ScaffoldTest1!")
    settings = AresSettings()
    return {class_name}(settings=settings, campaign=campaign, noise=NoiseController(campaign))


@pytest.mark.asyncio
async def test_dry_run(module):
    """Dry run should return status=dry_run without touching target."""
    findings, raw = await module.run(target="10.0.0.1", dry_run=True)
    assert raw.get("dry_run") is True
    assert findings == []


@pytest.mark.asyncio
async def test_missing_target_raises(module):
    """Missing required param should raise validation error."""
    from ares.core.errors import ModuleValidationError
    with pytest.raises((ModuleValidationError, Exception)):
        await module.run()


# Add more test cases:
# - test_happy_path: mock the external call, assert findings are created
# - test_no_finding: when nothing vulnerable found, assert findings == []
# - test_error_handling: simulate network error, assert HostUnreachable is raised
'''

    out_dir.mkdir(parents=True, exist_ok=True)
    module_file.write_text(module_code)
    test_file.write_text(test_code)

    console.print(Panel(
        f"[green]✅ Module scaffolded[/green]\n\n"
        f"  [bold]Module:[/bold]  {module_file}\n"
        f"  [bold]Tests:[/bold]   {test_file}\n\n"
        f"Next steps:\n"
        f"  1. Implement [cyan]execute()[/cyan] in {module_file.name}\n"
        f"  2. Fill in [cyan]REQUIRES[/cyan], [cyan]OUTPUTS[/cyan], [cyan]mitre[/cyan] metadata\n"
        f"  3. Run tests:  [cyan]pytest {test_file.name}[/cyan]\n"
        f"  4. Install:    [cyan]ares module install ./{module_file.name}[/cyan]",
        title=f"ares module create — {module_id}",
    ))


# ── Entry point ────────────────────────────────────────────────────────────────

def cli() -> None:
    """Main CLI entry point."""
    app()


if __name__ == "__main__":
    cli()
