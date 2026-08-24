#!/usr/bin/env python3
"""Generate bounded hybrid source candidates for the Hancom integration applet.

The vendor source may combine changes from different public-history snapshots.
This tool collects unique public blobs for the three source files implicated by
DWARF and string evidence, then emits at most twelve diverse combinations.
It never declares equivalence; the independent rebuild/comparison workflow does.
"""
from __future__ import annotations

import argparse
import itertools
import json
import re
import subprocess
from dataclasses import dataclass
from pathlib import Path

FILES = {
    "applet": "src/gooroom-integration-applet.c",
    "popup": "src/popup-window.c",
    "user": "modules/user/user-module.c",
}

SIGNALS = {
    "applet": (
        ("notify::gtk-icon-theme-name", 80),
        ("gtk_widget_get_settings", 45),
        ("gtk_widget_override_background_color", 45),
        ("gtk-icon-theme-name", 30),
        ("style1.css", 24),
        ("style2.css", 24),
        ("style4", 12),
        ("style5", 12),
        ("icon-theme", 10),
    ),
    "popup": (
        ("/tmp/.cleanmode", 50),
        ("cleanmode", 30),
        ("popup_window_setup_user", 8),
        ("CONTROL_TYPE_USER", 5),
    ),
    "user": (
        ("/tmp/.cleanmode", 50),
        ("cleanmode", 30),
        ("build_control_ui", 8),
        ("user_module_control_new", 5),
    ),
}


@dataclass(frozen=True)
class Choice:
    role: str
    path: str
    blob: str
    commit: str
    timestamp: int
    subject: str
    score: int
    signals: tuple[str, ...]
    is_base: bool

    @property
    def signature(self) -> tuple[bool, ...]:
        content_signals = tuple(signal for signal, _ in SIGNALS[self.role])
        present = set(self.signals)
        return tuple(signal in present for signal in content_signals)


def git(repo: Path, *arguments: str, check: bool = True) -> str:
    process = subprocess.run(
        ["git", "-C", str(repo), *arguments],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )
    if check and process.returncode:
        raise RuntimeError(
            f"git {' '.join(arguments)} failed ({process.returncode})\n"
            f"{process.stdout}\n{process.stderr}"
        )
    return process.stdout


def resolve(repo: Path, expression: str) -> str:
    value = git(repo, "rev-parse", "--verify", expression).strip()
    if not re.fullmatch(r"[0-9a-f]{40}", value):
        raise RuntimeError(f"invalid Git object for {expression}: {value!r}")
    return value


def blob_text(repo: Path, blob: str) -> str:
    process = subprocess.run(
        ["git", "-C", str(repo), "cat-file", "blob", blob],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if process.returncode:
        raise RuntimeError(process.stderr.decode("utf-8", errors="replace"))
    return process.stdout.decode("utf-8", errors="replace")


def collect(repo: Path, role: str, base_commit: str) -> list[Choice]:
    path = FILES[role]
    base_blob = resolve(repo, f"{base_commit}:{path}")
    commits = git(repo, "log", "--all", "--format=%H", "--", path).splitlines()
    if base_commit not in commits:
        commits.insert(0, base_commit)

    by_blob: dict[str, Choice] = {}
    for commit in commits:
        commit = commit.strip()
        if not commit:
            continue
        process = subprocess.run(
            ["git", "-C", str(repo), "rev-parse", "--verify", f"{commit}:{path}"],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            check=False,
        )
        if process.returncode:
            continue
        blob = process.stdout.strip()
        if not re.fullmatch(r"[0-9a-f]{40}", blob):
            continue
        text = blob_text(repo, blob)
        found: list[str] = []
        score = 0
        for signal, weight in SIGNALS[role]:
            if signal in text:
                found.append(signal)
                score += weight

        timestamp_text = git(repo, "show", "-s", "--format=%ct", commit).strip()
        timestamp = int(timestamp_text)
        if 1_577_836_800 <= timestamp <= 1_735_689_600:  # 2020..2024
            score += 4
        subject = git(repo, "show", "-s", "--format=%s", commit).strip()
        is_base = blob == base_blob
        choice = Choice(
            role=role,
            path=path,
            blob=blob,
            commit=commit,
            timestamp=timestamp,
            subject=subject,
            score=score,
            signals=tuple(found),
            is_base=is_base,
        )
        previous = by_blob.get(blob)
        if previous is None or (choice.timestamp, choice.commit) > (
            previous.timestamp,
            previous.commit,
        ):
            by_blob[blob] = choice

    values = list(by_blob.values())
    if not any(choice.is_base for choice in values):
        raise RuntimeError(f"base blob was not collected for {path}")
    return values


def select(choices: list[Choice], limit: int) -> list[Choice]:
    base = max((choice for choice in choices if choice.is_base), key=lambda row: row.timestamp)
    ranked = sorted(
        choices,
        key=lambda row: (row.score, row.timestamp, row.blob),
        reverse=True,
    )
    selected: list[Choice] = [base]
    signatures = {base.signature}

    # First maximize behavioral diversity, then fill by score.
    for choice in ranked:
        if len(selected) >= limit:
            break
        if choice.blob == base.blob or choice.signature in signatures:
            continue
        selected.append(choice)
        signatures.add(choice.signature)
    for choice in ranked:
        if len(selected) >= limit:
            break
        if all(choice.blob != previous.blob for previous in selected):
            selected.append(choice)
    return selected


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repository", type=Path, required=True)
    parser.add_argument("--base-commit", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--limit", type=int, default=12)
    args = parser.parse_args()

    repo = args.repository.resolve()
    base_commit = resolve(repo, f"{args.base_commit}^{{commit}}")
    if not 3 <= args.limit <= 16:
        raise RuntimeError("candidate limit must be between 3 and 16")

    pools = {
        "applet": select(collect(repo, "applet", base_commit), 4),
        "popup": select(collect(repo, "popup", base_commit), 3),
        "user": select(collect(repo, "user", base_commit), 4),
    }
    base = {
        role: next(choice for choice in choices if choice.is_base)
        for role, choices in pools.items()
    }

    combinations = list(
        itertools.product(pools["applet"], pools["popup"], pools["user"])
    )

    def combo_key(combo: tuple[Choice, Choice, Choice]) -> tuple[int, int, str]:
        score = sum(choice.score for choice in combo)
        changed = sum(not choice.is_base for choice in combo)
        identity = ":".join(choice.blob for choice in combo)
        return (score, changed, identity)

    chosen: list[tuple[Choice, Choice, Choice]] = []
    seen: set[tuple[str, str, str]] = set()

    def add(combo: tuple[Choice, Choice, Choice]) -> None:
        identity = tuple(choice.blob for choice in combo)
        if identity not in seen and len(chosen) < args.limit:
            seen.add(identity)
            chosen.append(combo)

    baseline = (base["applet"], base["popup"], base["user"])
    add(baseline)
    for role, choices in pools.items():
        for choice in choices:
            row = dict(base)
            row[role] = choice
            add((row["applet"], row["popup"], row["user"]))
    for combo in sorted(combinations, key=combo_key, reverse=True):
        add(combo)

    matrix: list[dict[str, object]] = []
    reports: list[dict[str, object]] = []
    for index, combo in enumerate(chosen, start=1):
        applet, popup, user = combo
        label = (
            f"h{index:02d}-a{applet.blob[:7]}-p{popup.blob[:7]}-u{user.blob[:7]}"
        )
        compact = {
            "label": label,
            "base_commit": base_commit,
            "applet_blob": applet.blob,
            "popup_blob": popup.blob,
            "user_blob": user.blob,
            "discovery_score": sum(choice.score for choice in combo),
        }
        matrix.append(compact)
        reports.append(
            {
                **compact,
                "changed_from_base": {
                    choice.role: not choice.is_base for choice in combo
                },
                "choices": {
                    choice.role: {
                        "path": choice.path,
                        "blob": choice.blob,
                        "representative_commit": choice.commit,
                        "timestamp": choice.timestamp,
                        "subject": choice.subject,
                        "score": choice.score,
                        "signals": list(choice.signals),
                    }
                    for choice in combo
                },
            }
        )

    document = {
        "schema": 1,
        "source": "gooroom-integration-applet",
        "version": "0.3.1+grm3u1+han3u3",
        "base_commit": base_commit,
        "selection_policy": (
            "unique-public-file-blobs;behavior-signature-diversity;"
            "baseline-and-single-file-controls;bounded-ranked-combinations"
        ),
        "candidate_count": len(matrix),
        "pool_sizes": {role: len(choices) for role, choices in pools.items()},
        "matrix": {"include": matrix},
        "candidates": reports,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(document, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(json.dumps(document["matrix"], separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
