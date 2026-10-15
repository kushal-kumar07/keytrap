# KeyTrap

A secret scanner for Git repositories you are authorized to test. It runs
several scanners in parallel, **reports the full secret value**,
deduplicates identical secrets, scores risk, and produces Markdown, PDF and
HackerOne-style reports.

> **Warning:** findings contain the **raw secret value**: in `findings.json`, the
> API, reports and terminal output. Treat all output as sensitive, and never commit
> or share it. Only the ContextJudgeAgent masks values before sending code to Claude.

---

## How it works

```
 repo ──► clone (sandboxed temp dir)
            │
            ▼
   ┌─ Scanner agents (run in parallel) ──────────────────────┐
   │ GitleaksAgent     Gitleaks CLI wrapper                  │
   │ TruffleHogAgent   TruffleHog CLI wrapper                │
   │ CustomRegexAgent  YAML rules (core + imported)          │
   │ EntropyAgent      Shannon-entropy scan for unknown keys │
   │ HistoryAgent      every commit, incl. deleted files     │
   │ DiffAgent         added lines between two commits       │
   └──────────────────────────┬──────────────────────────────┘
                              ▼
        dedupe → ContextJudgeAgent → risk score
                              ▼
                 findings.json  /  reports
```

**ContextJudgeAgent** is the seventh agent. It sends only a masked value and
surrounding code (secrets masked) to Claude (`claude-sonnet-4-20250514`) to lower the confidence of
likely false positives. It is skipped without an `ANTHROPIC_API_KEY` or in safe mode.

A missing scanner binary or a failing agent never stops a scan. That agent is
skipped and the rest continue.

### What a finding looks like

Every agent emits exactly this schema:

```json
{
  "finding_id": "sha256(repo+commit+file+line+secret)",
  "scan_id": "uuid",
  "agent": "CustomRegexAgent,GitleaksAgent,HistoryAgent",
  "provider": "stripe",
  "secret_type": "Stripe Live Secret Key",
  "secret": "sk_live_51ExampleRawValue",
  "repo": "owner/name",
  "branch": "main",
  "commit": "sha",
  "file_path": "backend/.env",
  "line_start": 1,
  "line_end": 1,
  "context_before": "STRIPE_SECRET_KEY=sk_live_51ExampleRawValue",
  "confidence": 0.9,
  "severity": "high",
  "risk_score": 80,
  "evidence_policy": "raw",
  "created_at": "2026-10-16T00:00:00+00:00"
}
```

When several agents find the same secret, they are merged into one finding and
the `agent` field lists all of them.

### Risk score (0-100)

| Signal | Points |
|---|---|
| Provider-specific live-looking key | +30 |
| Public repo or commit | +25 |
| Production path (`.env`, `config`, `deploy`, `terraform`) | +20 |
| Multiple agents agree | +15 |
| File modified in the last 7 days | +15 |
| Found only in an old deleted commit | +10 |
| Present on multiple branches | +10 |
| Repo has more than 100 stars | +10 |
| Path under `tests/`, `docs/`, `examples/`, `fixtures/` | -25 |
| Obvious placeholder value | -25 |

---

## Quick start

**Requirements:** Python 3.11+, Git, and (optional but recommended) the
[Gitleaks](https://github.com/gitleaks/gitleaks) and
[TruffleHog](https://github.com/trufflesecurity/trufflehog) binaries.

```bash
# 1. install
pip install -r requirements.txt
./install_scanners.sh            # optional: installs gitleaks + trufflehog

# 2. configure
cp .env.example .env
# optional: add ANTHROPIC_API_KEY to enable the ContextJudgeAgent

# 3. scan
./keytrap.sh scan path/to/repo --output findings.json
```

No other setup is required.

---

## CLI

```bash
keytrap scan <path-or-git-url> [options]
keytrap report [findings.json] --format markdown|pdf|hackerone [-o file]
keytrap test-rules <rules-dir> [--redos-timeout 100]
keytrap import-rules --source mazen160|h33tlit|odomojuli [-o rules/imported/]
```

`scan` options:

| Option | Purpose |
|---|---|
| `-o, --output` | Output file (default `findings.json`) |
| `-r, --rules` | Use a custom rules directory |
| `--diff-base`, `--diff-head` | Scan only the changes between two commits |
| `--safe-mode` | One worker, no external validation, conservative limits |
| `--keep-cloned` | Keep the clone of a remote repo after scanning |
| `-v, --verbose` | Detailed output |

---

## Reports

`keytrap report findings.json` produces:

- **Markdown**: executive summary, findings table by risk, per-finding detail, methodology.
- **PDF**: the same content rendered with WeasyPrint.
- **HackerOne**: a zip with one write-up per finding.

Remediation steps come from per-provider templates (AWS, GitHub, Slack, Stripe,
generic). Reports contain the raw secret values.

PDF output needs WeasyPrint's system libraries. On macOS, `keytrap.sh` sets
`DYLD_FALLBACK_LIBRARY_PATH=/opt/homebrew/lib` for you.

---

## Configuration

Set these in `.env` (see `.env.example`).

| Variable | Purpose |
|---|---|
| `ANTHROPIC_API_KEY` | Enables ContextJudgeAgent |
| `SAFE_MODE` | `true` forces conservative scanning |
| `MAX_COMMITS_HISTORY` | How many commits HistoryAgent walks (default 1000) |
| `KEYTRAP_RULES_DIR` | Override the rules directory |
| `KEYTRAP_AGENT_MAX_WORKERS` | Parallel agent threads |
| `KEYTRAP_REPORTS_DIR` | Where reports are written |
| `ENVIRONMENT` | `production` enables stricter rule loading |

---

## Testing

```bash
pytest tests -q
```

The scanner tests run against a seeded fixture repo with fake credentials. It
is built on demand by `tests/seed_repo.py` (and by `conftest.py` at the start of
the test session), so there is nothing to check in:

```bash
python -m tests.seed_repo /tmp/seeded-repo      # build it by hand
```

The seeded history has four commits: an app skeleton, placeholder-only docs and
tests, a commit that adds the credentials, and a commit that deletes one of those
files so its token survives only in history.

Gitleaks and TruffleHog must be on your `PATH` for their agent tests to pass.

---

## Project layout

```
keytrap/
├── agents/     six scanner agents + ContextJudgeAgent, agent pool
├── engine/     schema, redactor (judge only), risk scorer, rule loader/importer, safe mode, orchestrator
├── reports/    report generator, remediation guides
└── cli.py      Typer CLI
rules/          core + imported rule files, false-positive corpus
tests/          unit + integration tests, seed_repo.py fixture builder
```

---

## Known gaps

Be aware of these before relying on it:

- **Detection breadth is modest.** Beyond Gitleaks and TruffleHog, the project adds about 10 core rules, a few imported ones and an entropy check. It does not verify that a found key is live.
- **ContextJudgeAgent and the community-rule importer** are only tested with mocks, not against the live Anthropic API or GitHub sources.

---

Use KeyTrap only on repositories you own or are explicitly authorized to test.
