#!/usr/bin/env python3
"""
gh_advisory_scraper.py

Scrapes GitHub Security Advisories (repository-level, i.e. GHSA advisories
published against each repo) for every repo in a GitHub org.

Ranking:
    1. Published date (most recent first)          -- PRIMARY sort key
    2. Patch available (yes ranks above no)         -- tiebreak
    3. Credit count (more credited researchers      -- tiebreak
       ranks higher)

Checkpointing:
    A JSON checkpoint file (default: .checkpoint.json) tracks how many
    repos (in the org's repo list, sorted by name) have already been
    scanned. Every run with the same --org picks up where the last run
    left off, scanning the next --limit repos. Use --reset to start over.

Speed:
    Repos are fetched concurrently with a thread pool (--workers, default
    10) since advisory lookups are I/O bound HTTP calls. Rate-limit /
    transient errors are retried with backoff.

Usage:
    python scraper.py --org myorg --limit 50
    python scraper.py --org myorg --limit 50 --reset
    python scraper.py --org myorg --limit 50 --csv out.csv
"""

import argparse
import csv
import json
import os
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone

import requests
from dotenv import load_dotenv
from tabulate import tabulate

API_ROOT = "https://api.github.com"
CHECKPOINT_FILE_DEFAULT = ".checkpoint.json"


# --------------------------------------------------------------------------- #
# HTTP helpers
# --------------------------------------------------------------------------- #

def make_session(token: str) -> requests.Session:
    s = requests.Session()
    s.headers.update({
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "gh-advisory-scraper",
    })
    return s


def request_with_retry(session: requests.Session, url: str, params=None,
                        max_retries: int = 5) -> requests.Response:
    """GET with exponential backoff on rate limit (403/429) or 5xx errors."""
    backoff = 1.0
    for attempt in range(max_retries):
        resp = session.get(url, params=params, timeout=30)

        if resp.status_code == 200:
            return resp

        # Secondary rate limit / primary rate limit exhausted
        if resp.status_code in (403, 429):
            reset = resp.headers.get("X-RateLimit-Reset")
            remaining = resp.headers.get("X-RateLimit-Remaining")
            if remaining == "0" and reset:
                sleep_for = max(int(reset) - time.time(), 1) + 1
                sleep_for = min(sleep_for, 120)  # don't sleep forever
                time.sleep(sleep_for)
            else:
                time.sleep(backoff)
                backoff *= 2
            continue

        # Repo has advisories disabled / no access -> just treat as empty
        if resp.status_code in (404, 400):
            return resp

        if resp.status_code >= 500:
            time.sleep(backoff)
            backoff *= 2
            continue

        # Anything else, return as-is; caller decides
        return resp

    return resp  # last attempt result, even if not 200


def paginate(session: requests.Session, url: str, params: dict):
    """Yield JSON items across all pages of a paginated GitHub endpoint."""
    params = dict(params or {})
    params.setdefault("per_page", 100)
    next_url = url
    while next_url:
        resp = request_with_retry(session, next_url, params=params)
        if resp.status_code != 200:
            break
        data = resp.json()
        if isinstance(data, list):
            for item in data:
                yield item
        else:
            break

        next_url = None
        params = None  # params already baked into "next" link
        link = resp.headers.get("Link", "")
        for part in link.split(","):
            part = part.strip()
            if part.endswith('rel="next"'):
                next_url = part[part.index("<") + 1: part.index(">")]
                break


# --------------------------------------------------------------------------- #
# GitHub data fetchers
# --------------------------------------------------------------------------- #

def list_org_repos(session: requests.Session, org: str):
    """Return sorted list of repo full_names ('org/repo') for the org."""
    repos = []
    for repo in paginate(session, f"{API_ROOT}/orgs/{org}/repos",
                          params={"type": "all"}):
        repos.append(repo["full_name"])
    repos.sort()
    return repos


def fetch_repo_advisories(session: requests.Session, full_name: str):
    """
    Fetch security advisories for a single repo.
    Returns a list of normalized advisory dicts.
    """
    owner, repo = full_name.split("/", 1)
    url = f"{API_ROOT}/repos/{owner}/{repo}/security-advisories"
    results = []

    try:
        for adv in paginate(session, url, params={}):
            if adv.get("state") == "draft":
                continue  # skip unpublished drafts

            vulns = adv.get("vulnerabilities") or []
            patch_available = any(
                v.get("patched_versions") for v in vulns
            )
            credits = adv.get("credits") or []
            credit_count = len(credits)

            published_at = adv.get("published_at") or adv.get("created_at")

            results.append({
                "repo": full_name,
                "published_at": published_at,
                "patch_available": patch_available,
                "credit_count": credit_count,
                "url": adv.get("html_url"),
                "ghsa_id": adv.get("ghsa_id"),
                "summary": adv.get("summary"),
                "severity": adv.get("severity"),
            })
    except requests.RequestException:
        pass

    return results


# --------------------------------------------------------------------------- #
# Checkpoint handling
# --------------------------------------------------------------------------- #

def load_checkpoint(path: str, org: str) -> int:
    if not os.path.exists(path):
        return 0
    try:
        with open(path, "r") as f:
            data = json.load(f)
    except (json.JSONDecodeError, OSError):
        return 0
    if data.get("org") != org:
        return 0
    return int(data.get("last_index", 0))


def save_checkpoint(path: str, org: str, last_index: int, total_repos: int):
    data = {
        "org": org,
        "last_index": last_index,
        "total_repos": total_repos,
        "updated_at": datetime.now(timezone.utc).isoformat(),
    }
    with open(path, "w") as f:
        json.dump(data, f, indent=2)


# --------------------------------------------------------------------------- #
# Ranking / output
# --------------------------------------------------------------------------- #

def parse_ts(iso_str):
    if not iso_str:
        return datetime.min.replace(tzinfo=timezone.utc)
    try:
        return datetime.fromisoformat(iso_str.replace("Z", "+00:00"))
    except ValueError:
        return datetime.min.replace(tzinfo=timezone.utc)


def rank_advisories(advisories: list) -> list:
    """
    Sort by:
      1. published_at DESC (most recent first)
      2. patch_available DESC (patched ranks above unpatched)
      3. credit_count DESC (more credits ranks higher)
    """
    return sorted(
        advisories,
        key=lambda a: (
            parse_ts(a["published_at"]),
            a["patch_available"],
            a["credit_count"],
        ),
        reverse=True,
    )


def format_table(advisories: list) -> str:
    rows = []
    for a in advisories:
        pub = a["published_at"]
        pub_fmt = pub[:10] if pub else "N/A"  # YYYY-MM-DD
        patch = "Yes" if a["patch_available"] else "No"
        rows.append([pub_fmt, patch, a["url"], a["repo"]])
    return tabulate(
        rows,
        headers=["Published Date", "Patch", "Advisory Link", "Repository"],
        tablefmt="github",
    )


def write_csv(advisories: list, path: str):
    with open(path, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["Published Date", "Patch", "Advisory Link", "Repository"])
        for a in advisories:
            pub = a["published_at"]
            pub_fmt = pub[:10] if pub else "N/A"
            writer.writerow([
                pub_fmt,
                "Yes" if a["patch_available"] else "No",
                a["url"],
                a["repo"],
            ])


# --------------------------------------------------------------------------- #
# Main
# --------------------------------------------------------------------------- #

def main():
    parser = argparse.ArgumentParser(
        description="Scrape GitHub Security Advisories for repos in an org."
    )
    parser.add_argument("--org", required=True, help="GitHub org login/slug")
    parser.add_argument("--limit", type=int, default=25,
                         help="Number of repos to scan this run (default: 25)")
    parser.add_argument("--workers", type=int, default=10,
                         help="Concurrent threads for fetching (default: 10)")
    parser.add_argument("--checkpoint-file", default=CHECKPOINT_FILE_DEFAULT,
                         help="Path to checkpoint JSON file")
    parser.add_argument("--reset", action="store_true",
                         help="Ignore/reset existing checkpoint, start from repo 0")
    parser.add_argument("--csv", default=None,
                         help="Optional path to also write results as CSV")
    parser.add_argument("--env-file", default=".env",
                         help="Path to .env file containing GITHUB_TOKEN")
    args = parser.parse_args()

    load_dotenv(args.env_file)
    token = os.getenv("GITHUB_TOKEN")
    if not token:
        print("ERROR: GITHUB_TOKEN not found. Put it in your .env file as "
              "GITHUB_TOKEN=ghp_xxx", file=sys.stderr)
        sys.exit(1)

    session = make_session(token)

    print(f"Fetching repo list for org '{args.org}'...")
    all_repos = list_org_repos(session, args.org)
    total_repos = len(all_repos)
    if total_repos == 0:
        print("No repos found (check org name / token permissions).")
        sys.exit(0)

    start_index = 0 if args.reset else load_checkpoint(args.checkpoint_file, args.org)
    if start_index >= total_repos:
        print(f"All {total_repos} repos already scanned for org '{args.org}'. "
              f"Use --reset to start over.")
        sys.exit(0)

    end_index = min(start_index + args.limit, total_repos)
    batch = all_repos[start_index:end_index]

    print(f"Scanning repos {start_index + 1}-{end_index} of {total_repos} "
          f"({len(batch)} repos this run)...")

    all_advisories = []
    t0 = time.time()
    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        futures = {pool.submit(fetch_repo_advisories, session, r): r for r in batch}
        done_count = 0
        for future in as_completed(futures):
            repo_name = futures[future]
            try:
                advisories = future.result()
                all_advisories.extend(advisories)
            except Exception as e:
                print(f"  [warn] failed to fetch {repo_name}: {e}", file=sys.stderr)
            done_count += 1
            print(f"  scanned {done_count}/{len(batch)} repos", end="\r")

    elapsed = time.time() - t0
    print(f"\nDone in {elapsed:.1f}s. Found {len(all_advisories)} advisories "
          f"across {len(batch)} repos.")

    save_checkpoint(args.checkpoint_file, args.org, end_index, total_repos)
    print(f"Checkpoint updated: {end_index}/{total_repos} repos scanned "
          f"(saved to {args.checkpoint_file}).")

    if not all_advisories:
        print("No advisories found in this batch.")
        sys.exit(0)

    ranked = rank_advisories(all_advisories)

    print()
    print(format_table(ranked))

    if args.csv:
        write_csv(ranked, args.csv)
        print(f"\nCSV written to {args.csv}")


if __name__ == "__main__":
    main()
