## Advise

This tool will fetch us all the github advisaries of a particular org and their repos

# GitHub Org Security Advisory Scraper

Scans all repos in a GitHub org for **repository security advisories**
(GHSA advisories), ranks them, and prints a table. Supports checkpointing
so repeated runs continue from where the previous run left off.

## Setup

```bash
pip install -r requirements.txt
cp .env.example .env
# edit .env and set GITHUB_TOKEN=ghp_xxxxxxxx
```

Your token needs read access to the repos (and `security_events` scope /
"Security events" permission if the repos are private) to see advisories.

## Usage

```bash
# First run: scans the first 30 repos (alphabetically) in the org
python scraper.py --org my-org --limit 30

# Next run: automatically continues from repo 31 onward
python scraper.py --org my-org --limit 30

# Start completely over
python scraper.py --org my-org --limit 30 --reset

# Also save results to CSV
python scraper.py --org my-org --limit 30 --csv advisories.csv

# Tune concurrency (default 10 threads)
python scraper.py --org my-org --limit 50 --workers 20
```

## How ranking works

Advisories are sorted by:

1. **Published date** — most recent first (primary key)
2. **Patch available** — advisories with a documented patched version rank
   above those without, as a tiebreaker
3. **Credit count** — among same-date/same-patch-status advisories, ones
   with more credited researchers rank higher

## Output columns

| Published Date | Patch | Advisory Link | Repository |
|---|---|---|---|

- **Published Date** — the date GitHub shows as the advisory's publish date (`YYYY-MM-DD`)
- **Patch** — `Yes` if any affected package in the advisory lists patched versions, else `No`
- **Advisory Link** — the `html_url` GitHub gives the advisory (GHSA page)
- **Repository** — `org/repo` the advisory belongs to

## Checkpointing

A `.checkpoint.json` file (path configurable via `--checkpoint-file`) stores:

```json
{
  "org": "my-org",
  "last_index": 30,
  "total_repos": 214,
  "updated_at": "2026-07-29T12:00:00+00:00"
}
```

Each run scans repos `[last_index, last_index + limit)` from the
alphabetically sorted repo list, then updates `last_index`. Use `--reset`
to start from index 0 again. Once `last_index` reaches `total_repos`,
subsequent runs report that everything has been scanned.

## Performance

Repo advisory lookups are fetched concurrently (`--workers`, default 10)
using a thread pool since each call is a short I/O-bound HTTP request.
The tool also respects GitHub's rate-limit headers and backs off/retries
automatically on `403`/`429`/`5xx` responses.
