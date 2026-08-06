#!/usr/bin/env python3
"""Run the exact source resolver with anonymous Git transport.

The source organizations used by this project are public. GitHub Actions' app
token is retained for the REST API and raw-content requests, but must not be
injected into `git fetch`: an invalid extraHeader can make Git fall back to an
interactive username prompt and falsely mark every public source unresolved.
"""

from __future__ import annotations

import os

import resolve_source_git as resolver


def public_git_environment(self: resolver.RepositoryProbe) -> dict[str, str]:
    environment = os.environ.copy()
    # Explicitly remove any inherited one-shot Git config from the runner.
    for key in list(environment):
        if key.startswith("GIT_CONFIG_KEY_") or key.startswith("GIT_CONFIG_VALUE_"):
            environment.pop(key, None)
    environment.pop("GIT_CONFIG_COUNT", None)
    environment["GIT_TERMINAL_PROMPT"] = "0"
    return environment


resolver.RepositoryProbe.git_environment = public_git_environment

if __name__ == "__main__":
    raise SystemExit(resolver.main())
