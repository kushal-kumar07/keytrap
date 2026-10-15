"""Animated terminal UI for `keytrap scan`.

The scan pipeline reports progress through a plain callback, `on_event(kind, **data)`.
`ScanDisplay.handle` is that callback: it updates state under a lock, and a Rich
`Live` view redraws that state ~12 times a second.
"""

from __future__ import annotations

import logging
import math
import os
import threading
import time
from contextlib import contextmanager
from dataclasses import dataclass, field
from typing import Iterator

from rich.align import Align
from rich.console import Console, Group, RenderableType
from rich.live import Live
from rich.panel import Panel
from rich.rule import Rule
from rich.spinner import Spinner
from rich.table import Table
from rich.text import Text

# --------------------------------------------------------------------------- art

_GRADIENT = ["#38bdf8", "#4aa8f8", "#6d93f5", "#8b7df0", "#a56be8", "#c155dc"]
_NAME = "KEYTRAP"


def banner() -> RenderableType:
    """Clean wordmark with a radar sweep that moves while the display is live."""
    name = Text()
    for i, ch in enumerate(_NAME):
        name.append(ch + " ", style=f"bold {_GRADIENT[i * len(_GRADIENT) // len(_NAME)]}")
    name.rstrip()

    width = 34
    pos = int((math.sin(time.monotonic() * 2.2) + 1) / 2 * (width - 1))
    sweep = Text()
    for i in range(width):
        d = abs(i - pos)
        sweep.append("━", style="bold #38bdf8" if d == 0 else "#4aa8f8" if d < 3 else "dim")

    sub = Text("find the secrets before someone else does", style="dim italic")
    return Align.center(Group(Align.center(name), Align.center(sweep), Align.center(sub)))


# --------------------------------------------------------------------------- state

AGENTS: list[tuple[str, str]] = [
    ("GitleaksAgent", "regex + entropy engine over files"),
    ("TruffleHogAgent", "provider-aware detectors"),
    ("CustomRegexAgent", "YAML rule patterns"),
    ("EntropyAgent", "high-randomness tokens"),
    ("HistoryAgent", "walks past commits"),
    ("DiffAgent", "lines added in the latest commit"),
]

STAGES = [("clone", "Clone"), ("scan", "Scan"), ("judge", "Judge"), ("score", "Score")]


@dataclass
class AgentState:
    name: str
    blurb: str
    status: str = "idle"  # idle | queued | running | done | unavailable | failed
    count: int = 0
    seconds: float = 0.0
    started: float = 0.0
    note: str = ""


@dataclass
class ScanDisplay:
    console: Console
    repo: str
    agents: dict[str, AgentState] = field(default_factory=dict)
    stage: str = "clone"
    judge_enabled: bool = False
    t0: float = field(default_factory=time.monotonic)
    _lock: threading.Lock = field(default_factory=threading.Lock)
    _live: Live | None = None

    def __post_init__(self) -> None:
        for name, blurb in AGENTS:
            self.agents[name] = AgentState(name, blurb)

    # ---- event sink (called from worker threads) ----
    def handle(self, kind: str, **d) -> None:
        with self._lock:
            if kind == "stage":
                self.stage = d["stage"]
                if d["stage"] == "judge":
                    self.judge_enabled = bool(d.get("enabled")) and bool(os.environ.get("ANTHROPIC_API_KEY"))
                return
            agent = self.agents.get(d.get("agent", ""))
            if agent is None:
                return
            if kind == "agent_queued":
                agent.status = "queued"
            elif kind == "agent_start":
                agent.status, agent.started = "running", time.monotonic()
            elif kind == "agent_done":
                agent.status, agent.count, agent.seconds = "done", d["count"], d["seconds"]
            elif kind == "agent_unavailable":
                agent.status, agent.note = "unavailable", _short_reason(d.get("reason", ""))
            elif kind == "agent_failed":
                agent.status, agent.note = "failed", _short_reason(d.get("error", ""))

    # ---- rendering ----
    def __rich__(self) -> RenderableType:
        with self._lock:
            return Group(
                banner(),
                Text(),
                self._pipeline(),
                Text(),
                self._agent_table(),
                Text(),
                self._footer(),
            )

    def _elapsed(self) -> float:
        return time.monotonic() - self.t0

    def _pipeline(self) -> RenderableType:
        order = [k for k, _ in STAGES]
        current = order.index(self.stage) if self.stage in order else len(order)
        line = Text()
        for i, (key, label) in enumerate(STAGES):
            if i < current or self.stage == "done":
                line.append(f"● {label}", style="bold green")
            elif i == current:
                frames = "◐◓◑◒"
                line.append(f"{frames[int(time.monotonic() * 8) % 4]} {label}", style="bold cyan")
            else:
                line.append(f"○ {label}", style="dim")
            if i < len(STAGES) - 1:
                line.append("  ━━━  ", style="green" if i < current else "dim")
        target = Text.assemble(("target ", "dim"), (self.repo, "bold white"))
        return Align.center(Group(Align.center(line), Align.center(target)))

    def _bar(self, a: AgentState, width: int = 18) -> Text:
        now = time.monotonic()
        if a.status == "running":
            pos = (math.sin(now * 3 + hash(a.name) % 7) + 1) / 2 * (width - 5)
            bar = Text()
            for i in range(width):
                d = abs(i - pos)
                if d < 1.2:
                    bar.append("█", style="bold #38bdf8")
                elif d < 3:
                    bar.append("▓", style="#4aa8f8")
                elif d < 4.5:
                    bar.append("▒", style="#6d93f5")
                else:
                    bar.append("░", style="dim")
            return bar
        if a.status == "done":
            return Text("█" * width, style="green")
        if a.status in ("failed", "unavailable"):
            return Text("▒" * width, style="red" if a.status == "failed" else "dim yellow")
        return Text("░" * width, style="dim")

    def _agent_table(self) -> RenderableType:
        t = Table(
            box=None, show_header=True, header_style="bold dim", padding=(0, 1), expand=False
        )
        t.add_column("", width=2)
        t.add_column("AGENT", min_width=17)
        t.add_column("WHAT IT DOES", min_width=30, style="dim")
        t.add_column("PROGRESS", min_width=18)
        t.add_column("STATUS", min_width=22)
        t.add_column("FOUND", justify="right", min_width=5)
        for a in self.agents.values():
            t.add_row(*self._row(a))
        t.add_row(*self._judge_row())
        return Align.center(Panel(t, border_style="#4aa8f8", padding=(1, 2), title="[bold]agents[/]"))

    def _icon(self, status: str) -> RenderableType:
        if status == "running":
            return Spinner("dots", style="cyan")
        return Text(
            {"done": "✔", "failed": "✘", "unavailable": "–", "queued": "…", "idle": "·"}[status],
            style={"done": "bold green", "failed": "bold red", "unavailable": "yellow"}.get(
                status, "dim"
            ),
        )

    def _row(self, a: AgentState):
        if a.status == "running":
            status = Text(f"scanning… {time.monotonic() - a.started:4.1f}s", style="cyan")
        elif a.status == "done":
            status = Text(f"responded · {a.seconds:.1f}s", style="green")
        elif a.status == "unavailable":
            status = Text(f"skipped · {a.note}", style="yellow")
        elif a.status == "failed":
            status = Text(f"failed · {a.note}", style="red")
        elif a.status == "queued":
            status = Text("waiting for a worker", style="dim")
        else:
            status = Text("idle", style="dim")
        found = Text(str(a.count) if a.status == "done" else "–", style="bold" if a.count else "dim")
        if a.status == "done" and a.count:
            found.stylize("yellow")
        return self._icon(a.status), Text(a.name, style="bold"), a.blurb, self._bar(a), status, found

    def _judge_row(self):
        judge = AgentState("ContextJudgeAgent", "Claude false-positive triage")
        if self.stage == "judge":
            judge.status = "running" if self.judge_enabled else "unavailable"
            judge.started = self.t0
        elif self.stage in ("score", "done"):
            judge.status = "done" if self.judge_enabled else "unavailable"
        if judge.status == "unavailable":
            judge.note = "needs ANTHROPIC_API_KEY"
        row = list(self._row(judge))
        if judge.status == "done":
            row[4] = Text("responded", style="green")
            row[5] = Text("✓", style="green")
        return row

    def _footer(self) -> RenderableType:
        total = sum(a.count for a in self.agents.values())
        done = sum(a.status in ("done", "unavailable", "failed") for a in self.agents.values())
        text = Text.assemble(
            (f"{done}/{len(self.agents)} agents reported", "bold"),
            ("   ·   ", "dim"),
            (f"{total} raw hits", "bold yellow" if total else "dim"),
            ("   ·   ", "dim"),
            (f"{self._elapsed():5.1f}s elapsed", "dim"),
        )
        return Align.center(text)

    # ---- lifecycle ----
    @contextmanager
    def live(self) -> Iterator["ScanDisplay"]:
        # Agent warnings go to stderr via logging and would tear the display; the
        # events above already report them.
        quiet = logging.NullHandler()
        logger = logging.getLogger("keytrap")
        logger.addHandler(quiet)
        try:
            with Live(self, console=self.console, refresh_per_second=12, transient=False) as lv:
                self._live = lv
                yield self
        finally:
            logger.removeHandler(quiet)


def _short_reason(text: str) -> str:
    text = " ".join(str(text).split())
    for needle, short in (
        ("only one commit", "only one commit"),
        ("bad object", "bad git object"),
        ("not found", "scanner not installed"),
    ):
        if needle in text:
            return short
    return text[:28] + ("…" if len(text) > 28 else "")


# --------------------------------------------------------------------------- results

_SEV_STYLE = {"critical": "bold red", "high": "red", "medium": "yellow", "low": "blue"}


def render_results(console: Console, result, output_path, elapsed: float) -> None:
    findings = result.findings
    console.print()

    sev = result.stats.get("by_severity", {})
    chips = Text()
    for name in ("critical", "high", "medium", "low"):
        n = sev.get(name, 0)
        if n:
            chips.append(f" {name.upper()} {n} ", style=f"reverse {_SEV_STYLE[name]}")
            chips.append(" ")
    if not findings:
        chips = Text(" CLEAN · no secrets found ", style="reverse bold green")
    head = Text.assemble(
        (f"{len(findings)} unique finding{'s' if len(findings) != 1 else ''}", "bold"),
        (f"   from {result.stats.get('raw_findings', 0)} raw hits   ·   {elapsed:.1f}s", "dim"),
    )
    console.print(Align.center(Group(head, Text(), chips)))
    console.print()

    # Which agents responded with what
    by_agent = result.stats.get("by_agent", {})
    top = max(by_agent.values(), default=0)
    ag = Table(box=None, show_header=True, header_style="bold dim", padding=(0, 2))
    ag.add_column("AGENT")
    ag.add_column("HITS", justify="right")
    ag.add_column("")
    for name, _ in AGENTS:
        n = by_agent.get(name, 0)
        w = int(round(n / top * 20)) if top else 0
        ag.add_row(
            Text(name, style="bold" if n else "dim"),
            Text(str(n), style="yellow" if n else "dim"),
            Text("█" * w, style="#4aa8f8"),
        )
    console.print(Align.center(Panel(ag, title="[bold]who found what[/]", border_style="#4aa8f8", padding=(1, 2))))

    if findings:
        ft = Table(box=None, show_header=True, header_style="bold dim", padding=(0, 1))
        ft.add_column("RISK", justify="right")
        ft.add_column("SEV")
        ft.add_column("TYPE", max_width=26, overflow="ellipsis", no_wrap=True)
        ft.add_column("FILE", overflow="fold", max_width=34)
        ft.add_column("FOUND BY", style="dim", overflow="fold", max_width=26)
        ft.add_column("SECRET", overflow="fold", max_width=48)
        for f in findings[:15]:
            color = "red" if f.risk_score >= 80 else "yellow" if f.risk_score >= 50 else "cyan"
            ft.add_row(
                Text(str(f.risk_score), style=f"bold {color}"),
                Text(f.severity, style=_SEV_STYLE.get(f.severity, "white")),
                f.secret_type,
                f"{f.file_path}:{f.line_start}",
                ", ".join(a.replace("Agent", "") for a in f.agent.split(",")),
                Text(f.secret, style="bold"),
            )
        console.print(
            Align.center(
                Panel(ft, title="[bold]findings[/]", border_style="yellow", padding=(1, 2), expand=False)
            )
        )
        if len(findings) > 15:
            console.print(Align.center(Text(f"+ {len(findings) - 15} more in the output file", style="dim")))

    if findings:
        console.print()
        console.print(Rule("[bold]raw findings[/]", style="yellow"))
        for i, f in enumerate(findings, 1):
            head = Text.assemble(
                (f"#{i} ", "bold yellow"),
                (f"[{f.severity.upper()}] ", _SEV_STYLE.get(f.severity, "white")),
                (f"{f.secret_type}", "bold"),
                (f"  risk {f.risk_score}", "dim"),
            )
            console.print(head, soft_wrap=True)
            for label, value in (
                ("secret ", f.secret),
                ("file   ", f"{f.file_path}:{f.line_start}" + (f"-{f.line_end}" if f.line_end != f.line_start else "")),
                ("commit ", f.commit),
                ("agents ", f.agent.replace(",", ", ")),
                ("context", f.context_before.strip()),
            ):
                console.print(
                    Text.assemble((f"  {label} ", "dim"), (value, "bold" if label == "secret " else "")),
                    soft_wrap=True,
                    highlight=False,
                )
            console.print()

    console.print()
    console.print(
        Align.center(
            Text.assemble(("saved  ", "dim"), (str(output_path), "bold cyan"), ("   ·   ", "dim"),
                          ("output contains raw secrets, do not share", "dim red"))
        )
    )
