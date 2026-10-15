"""Build the seeded fixture repository used by scanner tests.

Every credential below is a fake value made for scanner validation. The
repository has four commits (newest first):

    HEAD  removes backend/legacy.cfg, so its token only survives in history
    [1]   adds the secrets (backend/.env, backend/legacy.cfg, a test key)
    [2]   adds placeholder-only docs/ and tests/ files
    [3]   initial application skeleton

Usage: python -m tests.seed_repo [destination] [--seed-clone]

With --seed-clone, ``destination`` is an existing clone: the seed commits are
added on top of its history and pushed to origin (fast-forward, never forced).
"""

from __future__ import annotations

import argparse
import os
import subprocess
from pathlib import Path

STRIPE_LIVE = "sk_live_51FakeTestingKeyNotRealXXXXXXXXXX"
AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLEFAKEKEY"
AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMIK7MDENGbPxRFAKEKEYEXAMPLEONLY"
GITHUB_TOKEN = "ghp_FakeTokenForTestingOnlyXXXXXXXXXXXX"
SLACK_TOKEN = "xoxb-fake-token-testing-only-xxxx-xxxx"
STRIPE_TEST = "sk_test_FakeTestKeyNotReal9aB3xK7mQ2"

# Random-looking (but fake) values: TruffleHog's detectors skip values that look
# like obvious placeholders, so these give it something real to match.
STRIPE_LIVE_RANDOM = "sk_live_iIPzskR7GGdTYMVNda3DIP7w"
GITHUB_TOKEN_RANDOM = "ghp_yhNvFoRDItVVp1HW3VyDrihVNMCLM2ufd7eS"
SLACK_TOKEN_RANDOM = "xoxb-671911634175-624604070963-794D5z8OtU0p08vbd1GocJol"

RAW_SEEDED_VALUES = (
    STRIPE_LIVE,
    AWS_ACCESS_KEY_ID,
    AWS_SECRET_ACCESS_KEY,
    GITHUB_TOKEN,
    SLACK_TOKEN,
    STRIPE_TEST,
    STRIPE_LIVE_RANDOM,
    GITHUB_TOKEN_RANDOM,
    SLACK_TOKEN_RANDOM,
)

DEFAULT_PATH = Path(__file__).resolve().parent / "fixtures" / "seeded-repo"

_GIT_ENV = {
    "GIT_AUTHOR_NAME": "KeyTrap Fixture",
    "GIT_AUTHOR_EMAIL": "fixture@keytrap.invalid",
    "GIT_COMMITTER_NAME": "KeyTrap Fixture",
    "GIT_COMMITTER_EMAIL": "fixture@keytrap.invalid",
}


def _git(repo: Path, *args: str) -> None:
    subprocess.run(
        ["git", "-C", str(repo), *args],
        check=True,
        capture_output=True,
        env={**os.environ, **_GIT_ENV},
    )


def _write(repo: Path, relative: str, content: str) -> None:
    path = repo / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def _commit(repo: Path, message: str) -> None:
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", message)


def build_seeded_repo(destination: Path = DEFAULT_PATH) -> Path:
    """Create the fixture repository at ``destination`` and return its path."""
    destination.mkdir(parents=True, exist_ok=True)
    _git(destination, "init", "-q", "-b", "main")
    seed_commits(destination)
    return destination


def seed_commits(destination: Path) -> None:
    """Add the four seed commits on top of whatever history already exists."""
    _write(destination, "README.md", "# Payments service\n")
    _write(
        destination,
        "backend/app.py",
        "import os\n\nSTRIPE_KEY = os.environ['STRIPE_SECRET_KEY']\n",
    )
    _commit(destination, "Initial application skeleton")

    _write(
        destination,
        "docs/api.md",
        "Set `STRIPE_SECRET_KEY=sk_live_your_key_here` before starting.\n",
    )
    _write(
        destination,
        "tests/test_payments.py",
        "STRIPE_KEY = 'sk_test_example'\n\n\ndef test_placeholder():\n    assert STRIPE_KEY\n",
    )
    _commit(destination, "Add API docs and payment test stubs")

    _write(
        destination,
        "backend/.env",
        f"STRIPE_SECRET_KEY={STRIPE_LIVE}\n"
        f"AWS_ACCESS_KEY_ID={AWS_ACCESS_KEY_ID}\n"
        f"AWS_SECRET_ACCESS_KEY={AWS_SECRET_ACCESS_KEY}\n"
        f"SLACK_BOT_TOKEN={SLACK_TOKEN}\n"
        f"STRIPE_PAYOUT_KEY={STRIPE_LIVE_RANDOM}\n"
        f"SLACK_ALERTS_TOKEN={SLACK_TOKEN_RANDOM}\n",
    )
    _write(destination, "backend/legacy.cfg", f"github_token = {GITHUB_TOKEN}\nci_token = {GITHUB_TOKEN_RANDOM}\n")
    _write(
        destination,
        "tests/test_payments.py",
        f"STRIPE_KEY = '{STRIPE_TEST}'\n\n\ndef test_charge():\n    assert STRIPE_KEY\n",
    )
    _commit(destination, "Wire up production credentials")

    _git(destination, "rm", "-q", "backend/legacy.cfg")
    _commit(destination, "Remove legacy config")


def seed_remote(clone: Path) -> None:
    """Seed an existing clone and push; fast-forward only, never forced."""
    seed_commits(clone)
    _git(clone, "push", "origin", "HEAD")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("destination", nargs="?", type=Path, default=DEFAULT_PATH)
    parser.add_argument("--seed-clone", action="store_true", help="seed an existing clone and push to origin")
    args = parser.parse_args()
    if args.seed_clone:
        seed_remote(args.destination)
        print(f"seeded and pushed {args.destination}")
    else:
        print(f"seeded repo ready at {build_seeded_repo(args.destination)}")
