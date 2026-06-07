#!/usr/bin/env python3
"""Helm chart dependency supply-chain check (Workstream 9, Task 4).

Dependabot has no `helm` ecosystem and its `docker` ecosystem only parses
Dockerfiles, so neither the external sub-charts pinned in a chart's
`dependencies:` block nor the versions recorded in `Chart.lock` are reachable
from `.github/dependabot.yml`. This script closes that gap for the chart(s)
under `deployments/helm/`.

Three classes of finding, with deliberately different severities:

  INTEGRITY (hard failure, exit 1) — a genuine, locally-verifiable defect:
    * `Chart.lock`, when present, disagrees with `Chart.yaml` about a
      dependency's pinned version (the chart was edited without re-running
      `helm dependency update`, so a deploy resolves a different version than
      the manifest claims). This check is fully OFFLINE, so it always gates.
    * a pinned `version:` that the upstream index was successfully fetched for
      does not exist there (typo / yanked / hallucinated pin).

  NETWORK (warning only, exit 0) — could not reach the upstream index after
    retries. We deliberately do NOT fail closed on a transient upstream outage:
    that would block every chart-touching PR on flakiness, and the real
    tamper-detection signal (the offline Chart.yaml<->Chart.lock consistency
    check above) still gates regardless. Existence/freshness are simply skipped
    for that dependency and surfaced as a warning.

  FRESHNESS (warning only, exit 0) — a newer stable version exists upstream.
    Mirrors what a Dependabot bump PR would surface; never a hard failure, so a
    stale pin can't red-wall an unrelated PR. The weekly scheduled run is the
    signal to act.

Pass --fail-on-drift to turn freshness drift into a hard failure too (not used
by the PR gate; available for ad-hoc audits).

Pure standard library + PyYAML — no `helm` binary required, because resolution
only needs the repo's `index.yaml`, never a chart build.
"""
from __future__ import annotations

import argparse
import os
import re
import sys
import time
import urllib.request
from pathlib import Path

import yaml

# Full SemVer 2.0.0 grammar: x.y.z with optional -prerelease and +build.
_SEMVER = re.compile(
    r"^(\d+)\.(\d+)\.(\d+)"           # core
    r"(?:-([0-9A-Za-z.-]+))?"          # optional -prerelease
    r"(?:\+[0-9A-Za-z.-]+)?$"          # optional +build (ignored for ordering)
)


def _parse(version: str) -> tuple[tuple[int, int, int], str | None] | None:
    """Return ((major, minor, patch), prerelease_or_None) or None if unparseable."""
    m = _SEMVER.match(version)
    if not m:
        return None
    core = (int(m.group(1)), int(m.group(2)), int(m.group(3)))
    return core, m.group(4)


def _is_stable(version: str) -> bool:
    parsed = _parse(version)
    return parsed is not None and parsed[1] is None


# Index cache keyed by repository URL so several dependencies sharing one repo
# (e.g. multiple bitnami charts) fetch index.yaml at most once per run.
_INDEX_CACHE: dict[str, dict] = {}


def _fetch_index(repo_url: str, retries: int = 3, backoff: float = 2.0) -> dict:
    """Fetch+parse a Helm repo index.yaml, with caching and bounded retries.

    Retries are what make it safe to treat a final failure as a transient
    NETWORK warning rather than an integrity failure: a genuine outage is
    distinguished from a one-off blip by having survived `retries` attempts.
    """
    if repo_url in _INDEX_CACHE:
        return _INDEX_CACHE[repo_url]
    url = repo_url.rstrip("/") + "/index.yaml"
    last_exc: Exception | None = None
    for attempt in range(1, retries + 1):
        try:
            with urllib.request.urlopen(url, timeout=30) as resp:  # noqa: S310 - https helm repo
                index = yaml.safe_load(resp.read())
            # A 200 with an empty/non-mapping body (CDN maintenance page,
            # rate-limit notice, truncated response) parses to None or a
            # scalar. That is a broken upstream, not a valid empty index, so
            # raise here: it is retried like any other failure and, if it
            # persists, the caller classifies it as a NETWORK warning. Coercing
            # it to {} instead would be wrong — every pinned dep would then look
            # "not found upstream" and hard-fail the PR on a transient outage.
            if not isinstance(index, dict):
                raise ValueError(
                    f"upstream index at {url} is not a YAML mapping "
                    f"(got {type(index).__name__})"
                )
            _INDEX_CACHE[repo_url] = index
            return index
        except Exception as exc:  # noqa: BLE001 - retried; see caller's classification
            last_exc = exc
            if attempt < retries:
                time.sleep(backoff * attempt)
    assert last_exc is not None
    raise last_exc


def _upstream_versions(index: dict, name: str) -> list[str]:
    # str()-coerce: a YAML index that records e.g. `version: 1.0` parses it as a
    # float, which would never `==` the string `pinned` from Chart.yaml and would
    # surface as a spurious integrity failure. Mirrors the str() on the Chart.yaml
    # side in check_chart().
    return [str(e["version"]) for e in index.get("entries", {}).get(name, [])]


def _newest_stable(versions: list[str]) -> str | None:
    stable = [v for v in versions if _is_stable(v)]
    return max(stable, key=lambda v: _parse(v)[0]) if stable else None  # type: ignore[index]


def _annotate(level: str, msg: str) -> None:
    """Emit a GitHub Actions annotation when running in CI; else plain text.

    Workflow commands are newline-delimited, so a stray CR/LF in an interpolated
    chart name/version could split the line and forge a second `::command::`.
    The values come from a committed, reviewed Chart.yaml (so the practical risk
    is low), but a single-line annotation should never contain raw newlines
    regardless — collapse them so the message can't break out of its command.
    """
    safe = msg.replace("\r", " ").replace("\n", " ")
    if os.environ.get("GITHUB_ACTIONS") == "true":
        print(f"::{level}::{safe}")
    else:
        print(f"[{level}] {safe}")


def _summary(lines: list[str]) -> None:
    path = os.environ.get("GITHUB_STEP_SUMMARY")
    if not path:
        return
    with open(path, "a", encoding="utf-8") as fh:
        fh.write("\n".join(lines) + "\n")


def _load_lock_versions(chart_dir: Path) -> dict[str, str]:
    """name -> version recorded in Chart.lock, or {} if absent."""
    lock = chart_dir / "Chart.lock"
    if not lock.is_file():
        return {}
    data = yaml.safe_load(lock.read_text()) or {}
    # `data.get("dependencies", [])` is not enough: an explicit `dependencies:`
    # with no value parses to None (the key exists, so the default is skipped),
    # and iterating None raises TypeError. `or []` collapses both the missing
    # and the explicit-null case, matching the guard in check_chart().
    #
    # str()-coerce the version for the same reason the Chart.yaml side does
    # (check_chart, `pinned = str(dep["version"])`): a Chart.lock recording
    # `version: 1.0` parses it as a float, so the `locked != pinned` integrity
    # check would compare float 1.0 against the string "1.0" — always unequal —
    # and raise a spurious integrity failure. Coercing both sides keeps the
    # comparison string-vs-string. This is the third and last of the float-hazard
    # sites (the other two are _upstream_versions and check_chart).
    return {d["name"]: str(d["version"]) for d in (data.get("dependencies") or [])}


class Counts:
    __slots__ = ("integrity", "network", "drift")

    def __init__(self) -> None:
        self.integrity = 0
        self.network = 0
        self.drift = 0


def _check_drift(rel: str, name: str, pinned: str, versions: list[str],
                 fail_on_drift: bool, counts: Counts, summary: list[str]) -> None:
    """Freshness comparison that never raises on odd pinned strings."""
    newest = _newest_stable(versions)
    pinned_parsed = _parse(pinned)
    if newest is None or pinned_parsed is None:
        # Either no stable upstream release, or the pin isn't plain semver
        # (e.g. a digest or an exotic range) — can't rank it, so don't guess.
        summary.append(f"- ℹ️ `{name}`: `{pinned}` present upstream; not semver-comparable")
        return

    newest_core = _parse(newest)[0]  # type: ignore[index]
    pinned_core, pinned_pre = pinned_parsed
    # Drift if a newer stable core exists, or the pin is a pre-release of the
    # newest core (a stable release of what you're testing is now available).
    drift = newest_core > pinned_core or (newest_core == pinned_core and pinned_pre is not None)
    if not drift:
        summary.append(f"- ✅ `{name}`: `{pinned}` is current")
        return

    counts.drift += 1
    level = "error" if fail_on_drift else "warning"
    _annotate(level, f"{rel}: dependency '{name}' is {pinned}; newest stable upstream is {newest}.")
    flag = "❌" if fail_on_drift else "⚠️"
    summary.append(f"- {flag} `{name}`: `{pinned}` → newest stable `{newest}`")


def check_chart(chart_yaml: Path, fail_on_drift: bool, counts: Counts) -> list[str]:
    """Append findings for one chart; mutate `counts`. Returns summary lines."""
    chart = yaml.safe_load(chart_yaml.read_text()) or {}
    deps = chart.get("dependencies", []) or []
    rel = chart_yaml.parent.as_posix()
    lock_versions = _load_lock_versions(chart_yaml.parent)

    http_deps = [d for d in deps if str(d.get("repository", "")).startswith(("http://", "https://"))]
    if not http_deps:
        return []

    summary: list[str] = [f"### `{rel}`"]

    for dep in http_deps:
        name = dep["name"]
        pinned = str(dep["version"])
        repo_url = dep["repository"]

        # (1) Chart.lock vs Chart.yaml — fully offline, always an integrity gate.
        locked = lock_versions.get(name)
        if locked is not None and locked != pinned:
            counts.integrity += 1
            _annotate(
                "error",
                f"{rel}: dependency '{name}' pinned to {pinned} in Chart.yaml but "
                f"Chart.lock records {locked} — run `helm dependency update`.",
            )
            summary.append(f"- ❌ `{name}`: Chart.yaml `{pinned}` ≠ Chart.lock `{locked}`")

        # (2) Upstream existence + (3) freshness — require the network.
        try:
            index = _fetch_index(repo_url)
        except Exception as exc:  # noqa: BLE001 - transient outage, classified as a warning
            counts.network += 1
            _annotate(
                "warning",
                f"{rel}: upstream index for '{name}' unreachable after retries ({repo_url}: {exc}). "
                f"Skipping existence/freshness; offline Chart.lock check still enforced.",
            )
            summary.append(f"- ⚠️ `{name}`: upstream index unreachable ({exc}) — existence/freshness skipped")
            continue

        versions = _upstream_versions(index, name)
        if pinned not in versions:
            counts.integrity += 1
            _annotate(
                "error",
                f"{rel}: dependency '{name}' pinned to {pinned}, which does not exist "
                f"in {repo_url} (yanked or typo).",
            )
            summary.append(f"- ❌ `{name}`: pinned `{pinned}` not found upstream")
            continue

        _check_drift(rel, name, pinned, versions, fail_on_drift, counts, summary)

    return summary


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument(
        "--charts-dir",
        default="deployments/helm",
        help="Root directory to scan for Chart.yaml files (default: deployments/helm)",
    )
    ap.add_argument(
        "--fail-on-drift",
        action="store_true",
        help="Treat a newer-version-available drift as a hard failure (default: warn only).",
    )
    args = ap.parse_args()

    root = Path(args.charts_dir)
    if not root.exists():
        print(f"no charts directory at {root}; nothing to check")
        return 0

    # Top-level charts only; skip vendored sub-charts pulled into a `charts/`
    # subdirectory. Match on the path *relative to root* so an absolute
    # --charts-dir that happens to contain a `charts` component (e.g.
    # /home/user/charts/proj/helm) doesn't filter out every chart.
    chart_files = [
        p for p in root.rglob("Chart.yaml")
        if "charts" not in p.relative_to(root).parts
    ]
    if not chart_files:
        print(f"no Chart.yaml under {root}; nothing to check")
        return 0

    counts = Counts()
    summary_lines = ["## Helm chart dependency supply-chain check"]
    for cf in sorted(chart_files):
        summary_lines.extend(check_chart(cf, args.fail_on_drift, counts))

    if counts.integrity == 0 and counts.network == 0 and counts.drift == 0:
        summary_lines.append("\nAll external chart dependencies are pinned to existing, current versions.")
    _summary(summary_lines)

    print(
        f"\nintegrity failures: {counts.integrity}, "
        f"freshness drift: {counts.drift}, network warnings: {counts.network}"
    )
    if counts.integrity:
        print("FAILED: integrity problem(s) in chart dependencies (see annotations above).")
        return 1
    if counts.drift and args.fail_on_drift:
        print("FAILED: chart dependency drift (--fail-on-drift).")
        return 1
    notes = []
    if counts.drift:
        notes.append("newer versions available upstream")
    if counts.network:
        notes.append("some upstream indexes unreachable (checked offline only)")
    if notes:
        print(f"OK (with warnings): integrity verified; {', '.join(notes)}.")
    else:
        print("OK: chart dependencies pinned to existing, current versions.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
