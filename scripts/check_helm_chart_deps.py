#!/usr/bin/env python3
"""Helm chart dependency supply-chain check (Workstream 9, Task 4).

Dependabot has no `helm` ecosystem and its `docker` ecosystem only parses
Dockerfiles, so neither the external sub-charts pinned in a chart's
`dependencies:` block nor the versions recorded in `Chart.lock` are reachable
from `.github/dependabot.yml`. This script closes that gap for the chart(s)
under `deployments/helm/`.

It runs two independent kinds of check per dependency that has an HTTP(S)
`repository:` (i.e. a real upstream Helm repo, not a `file://` first-party
sub-chart):

  INTEGRITY (hard failure, exit 1) — a genuine supply-chain problem:
    * the pinned `version:` does not exist in the upstream repo index
      (typo, yanked, or hallucinated pin); and
    * `Chart.lock`, when present, disagrees with `Chart.yaml` about a
      dependency's pinned version (the chart was edited without re-running
      `helm dependency update`, so deploys would resolve a different version
      than the manifest claims).

  FRESHNESS (warning only, exit 0) — informational drift:
    * a newer stable version exists upstream. This mirrors what a Dependabot
      bump PR would surface; it is deliberately NOT a hard failure, so it never
      blocks an unrelated PR. The weekly scheduled run is the signal to act.

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
import urllib.request
from pathlib import Path

import yaml

# A stable SemVer "x.y.z" (no pre-release / build metadata). Used to pick the
# newest *stable* upstream version — pre-releases (1.3.0-beta.1) are ignored.
_STABLE_SEMVER = re.compile(r"^\d+\.\d+\.\d+$")


def _key(version: str) -> tuple[int, int, int]:
    major, minor, patch = (int(p) for p in version.split("."))
    return major, minor, patch


def _fetch_index(repo_url: str) -> dict:
    """Fetch and parse a Helm repository index.yaml."""
    url = repo_url.rstrip("/") + "/index.yaml"
    with urllib.request.urlopen(url, timeout=30) as resp:  # noqa: S310 - https helm repo
        return yaml.safe_load(resp.read())


def _upstream_versions(index: dict, name: str) -> list[str]:
    return [e["version"] for e in index.get("entries", {}).get(name, [])]


def _newest_stable(versions: list[str]) -> str | None:
    stable = [v for v in versions if _STABLE_SEMVER.match(v)]
    return max(stable, key=_key) if stable else None


def _annotate(level: str, msg: str) -> None:
    """Emit a GitHub Actions annotation when running in CI; else plain text."""
    if os.environ.get("GITHUB_ACTIONS") == "true":
        print(f"::{level}::{msg}")
    else:
        print(f"[{level}] {msg}")


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
    return {d["name"]: d["version"] for d in data.get("dependencies", [])}


def check_chart(chart_yaml: Path, fail_on_drift: bool) -> tuple[int, int, list[str]]:
    """Return (integrity_failures, drift_warnings, summary_lines) for one chart."""
    chart = yaml.safe_load(chart_yaml.read_text()) or {}
    deps = chart.get("dependencies", []) or []
    rel = chart_yaml.parent.as_posix()
    lock_versions = _load_lock_versions(chart_yaml.parent)

    integrity = 0
    drift = 0
    summary: list[str] = []

    http_deps = [d for d in deps if str(d.get("repository", "")).startswith(("http://", "https://"))]
    if not http_deps:
        return 0, 0, []

    summary.append(f"### `{rel}`")

    for dep in http_deps:
        name = dep["name"]
        pinned = str(dep["version"])
        repo_url = dep["repository"]

        # Chart.lock vs Chart.yaml integrity (offline).
        locked = lock_versions.get(name)
        if locked is not None and locked != pinned:
            integrity += 1
            _annotate(
                "error",
                f"{rel}: dependency '{name}' pinned to {pinned} in Chart.yaml but "
                f"Chart.lock records {locked} — run `helm dependency update`.",
            )
            summary.append(f"- ❌ `{name}`: Chart.yaml `{pinned}` ≠ Chart.lock `{locked}`")

        try:
            index = _fetch_index(repo_url)
        except Exception as exc:  # noqa: BLE001 - network/parse failure is a check error
            integrity += 1
            _annotate("error", f"{rel}: could not fetch index for '{name}' from {repo_url}: {exc}")
            summary.append(f"- ❌ `{name}`: failed to fetch upstream index ({exc})")
            continue

        versions = _upstream_versions(index, name)
        if pinned not in versions:
            integrity += 1
            _annotate(
                "error",
                f"{rel}: dependency '{name}' pinned to {pinned}, which does not exist "
                f"in {repo_url} (yanked or typo).",
            )
            summary.append(f"- ❌ `{name}`: pinned `{pinned}` not found upstream")
            continue

        newest = _newest_stable(versions)
        if newest and newest != pinned and _key(newest) > _key(pinned):
            drift += 1
            level = "error" if fail_on_drift else "warning"
            _annotate(
                level,
                f"{rel}: dependency '{name}' is {pinned}; newest stable upstream is {newest}.",
            )
            flag = "❌" if fail_on_drift else "⚠️"
            summary.append(f"- {flag} `{name}`: `{pinned}` → newest stable `{newest}`")
        else:
            summary.append(f"- ✅ `{name}`: `{pinned}` is current")

    return integrity, drift, summary


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

    # Top-level charts only; skip vendored sub-charts pulled into charts/.
    chart_files = [p for p in root.rglob("Chart.yaml") if "/charts/" not in p.as_posix()]
    if not chart_files:
        print(f"no Chart.yaml under {root}; nothing to check")
        return 0

    total_integrity = 0
    total_drift = 0
    summary_lines = ["## Helm chart dependency supply-chain check"]

    for cf in sorted(chart_files):
        integrity, drift, lines = check_chart(cf, args.fail_on_drift)
        total_integrity += integrity
        total_drift += drift
        summary_lines.extend(lines)

    if total_integrity == 0 and total_drift == 0:
        summary_lines.append("\nAll external chart dependencies are pinned to existing, current versions.")
    _summary(summary_lines)

    print(f"\nintegrity failures: {total_integrity}, freshness drift: {total_drift}")
    if total_integrity:
        print("FAILED: integrity problem(s) in chart dependencies (see annotations above).")
        return 1
    if total_drift and args.fail_on_drift:
        print("FAILED: chart dependency drift (--fail-on-drift).")
        return 1
    if total_drift:
        print("OK (with freshness warnings): integrity verified; newer versions available upstream.")
    else:
        print("OK: chart dependencies pinned to existing, current versions.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
