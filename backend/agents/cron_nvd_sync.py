#!/usr/bin/env python3
"""
nvd_sync.py — Production-grade NVD CVE → PostgreSQL synchronization script.

Syncs NVD CVE data into the `vulnerabilities` table:
    vuln_id, title, description, cvss_score, cvss_vector, fix_version, published_date

Behaviour:
  - Every run     : fetch ALL CVEs from INITIAL_YEAR (2002) through the current year
                    and upsert them into the vulnerabilities table.
  - fix_version   : only overwrite if the incoming value is non-NULL;
                    if NVD sends NULL and we already have a value, keep the old one.
  - Failed batches: collected during the run, retried ONCE at the end;
                    if they still fail they are logged with vuln_ids and abandoned.

Usage:
    python3 cron_nvd_sync.py

Environment variables:
    NVD_API_KEY   (optional but strongly recommended — higher rate limits)
    DB_HOST       (default: localhost)
    DB_PORT       (default: 5432)
    DB_NAME       (required)
    DB_USER       (required)
    DB_PASSWORD   (required)
"""

import logging
import os
import sys
import time
from datetime import datetime, timezone
from typing import Any, Optional

import psycopg2
import psycopg2.extras
import requests
from dotenv import load_dotenv

load_dotenv()
# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%SZ",
    handlers=[logging.StreamHandler(sys.stdout)],
)
log = logging.getLogger("nvd_sync")

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

NVD_BASE_URL            = "https://services.nvd.nist.gov/rest/json/cves/2.0"
RESULTS_PER_PAGE        = 2000
BATCH_SIZE              = 10_000
ADVISORY_LOCK_ID        = 123456
MAX_RETRIES             = 5
INITIAL_YEAR            = 2002

# NVD rate limits: 5 req/30s without key, 50 req/30s with key.
REQUEST_DELAY_NO_KEY    = 6.0   # seconds between API pages
REQUEST_DELAY_WITH_KEY  = 0.7

# NVD datetime format used in all API query parameters
NVD_DT_FMT = "%Y-%m-%dT%H:%M:%S.000"

# ---------------------------------------------------------------------------
# Configuration (from environment)
# ---------------------------------------------------------------------------

NVD_API_KEY: Optional[str] = os.environ.get("NVD_API_KEY")

DB_CONFIG: dict[str, Any] = {
    "host":     os.environ["DB_HOST"],
    "port":     int(os.environ["DB_PORT"]),
    "dbname":   os.environ["DB_NAME"],
    "user":     os.environ["DB_USER"],
    "password": os.environ["DB_PASSWORD"],
    "sslmode":  os.environ["DB_SSLMODE"],
}

REQUEST_DELAY = REQUEST_DELAY_WITH_KEY if NVD_API_KEY else REQUEST_DELAY_NO_KEY

# ---------------------------------------------------------------------------
# Database helpers
# ---------------------------------------------------------------------------


def get_db_connection() -> psycopg2.extensions.connection:
    """
    Open and return a psycopg2 connection.
    autocommit=False so every upsert batch is an explicit transaction.
    """
    conn = psycopg2.connect(**DB_CONFIG)
    conn.autocommit = False
    log.info(
        "DB connection established (host=%s db=%s)",
        DB_CONFIG["host"],
        DB_CONFIG["dbname"],
    )
    return conn


def acquire_lock(conn: psycopg2.extensions.connection) -> bool:
    """
    Try to grab a PostgreSQL advisory lock so only one instance runs at a time.
    Returns True if acquired, False if another process already holds it.
    """
    with conn.cursor() as cur:
        cur.execute("SELECT pg_try_advisory_lock(%s);", (ADVISORY_LOCK_ID,))
        acquired: bool = cur.fetchone()[0]

    if acquired:
        log.info("Advisory lock acquired (id=%s).", ADVISORY_LOCK_ID)
    else:
        log.warning("Advisory lock busy — another instance is likely running. Exiting.")
    return acquired


def release_lock(conn: psycopg2.extensions.connection) -> None:
    """Release the advisory lock acquired by this session."""
    with conn.cursor() as cur:
        cur.execute("SELECT pg_advisory_unlock(%s);", (ADVISORY_LOCK_ID,))
    log.info("Advisory lock released.")


# ---------------------------------------------------------------------------
# NVD API helpers
# ---------------------------------------------------------------------------


def _build_headers() -> dict[str, str]:
    headers: dict[str, str] = {"Accept": "application/json"}
    if NVD_API_KEY:
        headers["apiKey"] = NVD_API_KEY
    return headers


def fetch_cves_page(params: dict[str, Any]) -> dict[str, Any]:
    """
    GET a single page from NVD with retry + exponential back-off.

    Retries on: 429, 500, 502, 503, ConnectionError, Timeout.
    Raises RuntimeError after MAX_RETRIES exhausted.
    """
    for attempt in range(MAX_RETRIES):
        try:
            resp = requests.get(
                NVD_BASE_URL,
                params=params,
                headers=_build_headers(),
                timeout=180,
            )

            if resp.status_code == 200:
                return resp.json()

            if resp.status_code in (429, 500, 502, 503):
                wait = min(60, 2 ** attempt)
                log.warning(
                    "HTTP %s — retry %d/%d in %ds …",
                    resp.status_code, attempt + 1, MAX_RETRIES, wait,
                )
                time.sleep(wait)
                continue

            resp.raise_for_status()

        except (requests.ConnectionError, requests.Timeout) as exc:
            wait = 2 ** attempt
            log.warning(
                "Network error (%s) — retry %d/%d in %ds …",
                exc, attempt + 1, MAX_RETRIES, wait,
            )
            time.sleep(wait)

    raise RuntimeError(f"NVD API failed after {MAX_RETRIES} retries (params={params})")


def _paginate(params: dict[str, Any], context: str) -> list[dict[str, Any]]:
    """
    Shared pagination loop. Fetches pages until startIndex >= totalResults.
    Returns a flat list of raw CVE item dicts.
    """
    all_items: list[dict[str, Any]] = []
    start_index   = 0
    total_results: Optional[int] = None
    received      = 0

    while True:
        params["startIndex"] = start_index
        data = fetch_cves_page(params)

        if total_results is None:
            total_results = data.get("totalResults", 0)
            log.info("%s — totalResults: %d", context, total_results)

        page_items: list[dict] = data.get("vulnerabilities", [])
        all_items.extend(page_items)
        received += len(page_items)

        page_num = start_index // RESULTS_PER_PAGE + 1
        log.info("%s — page %d: +%d items (cumulative %d/%d)",
                 context, page_num, len(page_items), received, total_results)

        start_index += RESULTS_PER_PAGE
        if start_index >= (total_results or 0):
            break

        time.sleep(REQUEST_DELAY)

    if total_results is not None and received != total_results:
        log.warning("%s — count mismatch: expected %d got %d", context, total_results, received)

    return all_items


def fetch_year(year: int) -> list[dict[str, Any]]:
    """
    Fetch all CVEs published in *year*, splitting into ≤120-day windows.

    NVD enforces a hard 120-day maximum on pubStartDate/pubEndDate ranges;
    requests spanning a full year are rejected with HTTP 404. Each year is
    therefore split into three ~121-day chunks (Jan–Apr, May–Aug, Sep–Dec)
    which all comfortably fall within the limit.
    """
    log.info("Fetching year %d …", year)

    # Three fixed windows that together cover every day of the year and each
    # stay well under the 120-day NVD limit.
    windows = [
        (f"{year}-01-01T00:00:00.000", f"{year}-03-31T23:59:59.999"),
        (f"{year}-04-01T00:00:00.000", f"{year}-06-30T23:59:59.999"),
        (f"{year}-07-01T00:00:00.000", f"{year}-09-30T23:59:59.999"),
        (f"{year}-10-01T00:00:00.000", f"{year}-11-30T23:59:59.999"),
        (f"{year}-12-01T00:00:00.000", f"{year}-12-31T23:59:59.999"),
    ]

    all_items: list[dict[str, Any]] = []
    for idx, (start, end) in enumerate(windows, start=1):
        log.info("Year %d — window %d/%d: %s → %s", year, idx, len(windows), start, end,)
        params: dict[str, Any] = {
            "pubStartDate":   start,
            "pubEndDate":     end,
            "resultsPerPage": RESULTS_PER_PAGE,
        }
        all_items.extend(_paginate(params, context=f"Year {year} W{idx}"))
        if idx < len(windows):
            time.sleep(REQUEST_DELAY)  # polite pause between windows

    log.info("Year %d — total items fetched: %d", year, len(all_items))
    return all_items




# ---------------------------------------------------------------------------
# CVE parsing
# ---------------------------------------------------------------------------

def _extract_fix_version(cve_block: dict) -> Optional[str]:
    """
    Extract fix version from the NVD affected/versions structure.

    NVD embeds fix info inside version strings as:
        "Upto Version 1.2.103 [fixed: There's no fix yet]"
        "Upto Version 1.2.103 [fixed: 1.2.104]"

    Also checks for versions where versionEndExcluding exists on a
    non-affected entry, which implies that version is the fix boundary.

    Returns the first non-trivial fix version string found, or None.
    """
    NO_FIX_PHRASES = {"there's no fix yet", "no fix yet", "none", "n/a", ""}

    for affected_entry in cve_block.get("affected", []):
        for affected_data in affected_entry.get("affectedData", []):
            for ver in affected_data.get("versions", []):
                version_str: str = ver.get("version", "")

                # Pattern 1: inline [fixed: X] tag inside the version string
                if "[fixed:" in version_str.lower():
                    # Extract content between [fixed: and ]
                    start = version_str.lower().find("[fixed:") + len("[fixed:")
                    end   = version_str.find("]", start)
                    if end != -1:
                        fix_val = version_str[start:end].strip()
                        if fix_val.lower() not in NO_FIX_PHRASES:
                            return fix_val

                # Pattern 2: a versionEndExcluding on an affected entry
                # means "fixed at this boundary version"
                if (
                    ver.get("status") == "affected"
                    and ver.get("versionEndExcluding")
                ):
                    return ver["versionEndExcluding"]

    return None

def parse_cve(item: dict[str, Any]) -> Optional[tuple]:
    """
    Map a single raw NVD CVE item to a DB row tuple:

        (vuln_id, title, description, cvss_score, cvss_vector, fix_version, published_date)

    fix_version is always None — the upsert SQL handles the
    "keep existing value if incoming is NULL" logic at the database layer.

    Returns None and logs a warning on any parsing failure; never raises.
    """
    cve_id: Optional[str] = None
    try:
        cve_block: dict = item.get("cve", {})
        cve_id = cve_block.get("id", "UNKNOWN")

        # English description
        descriptions: list[dict] = cve_block.get("descriptions", [])
        description: Optional[str] = next(
            (d["value"] for d in descriptions if d.get("lang") == "en"),
            None,
        )

        # Title — NVD 2.0 has no free-form title field; use the CVE ID
        title: str = cve_id

        # CVSS score + vector (prefer v3.1 → v3.0 → v2.0)
        cvss_score:  Optional[float] = None
        cvss_vector: Optional[str]   = None
        metrics: dict = cve_block.get("metrics", {})

        for metric_key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            metric_list: list[dict] = metrics.get(metric_key, [])
            if metric_list:
                cvss_data   = metric_list[0].get("cvssData", {})
                cvss_score  = cvss_data.get("baseScore")
                cvss_vector = cvss_data.get("vectorString")
                break

        # Published date → DATE column (YYYY-MM-DD)
        published_str: Optional[str] = cve_block.get("published")
        published_date: Optional[str] = published_str[:10] if published_str else None

        # fix_version: NVD feed doesn't carry this — always None.
        # COALESCE in the upsert SQL preserves any existing DB value.
        fix_version: Optional[str] = _extract_fix_version(cve_block)

        return (
            cve_id,         # vuln_id         VARCHAR(100)
            title,          # title           VARCHAR(500)
            description,    # description     TEXT
            cvss_score,     # cvss_score      NUMERIC(4,2)
            cvss_vector,    # cvss_vector     VARCHAR(255)
            fix_version,    # fix_version     VARCHAR(100)  — preserved by COALESCE
            published_date, # published_date  DATE
        )

    except Exception as exc:
        log.error("Skipping malformed CVE (id=%s): %s", cve_id or "?", exc)
        return None


# ---------------------------------------------------------------------------
# Upsert logic
# ---------------------------------------------------------------------------

# fix_version rule encoded in SQL:
#   COALESCE(EXCLUDED.fix_version, vulnerabilities.fix_version)
#   • Incoming non-NULL → overwrite (new info from NVD or an external enricher)
#   • Incoming NULL     → keep the existing stored value
#   Result: a fix_version once recorded is never silently erased.
_UPSERT_SQL = """
    INSERT INTO vulnerabilities (
        vuln_id, title, description, cvss_score,
        cvss_vector, fix_version, published_date
    )
    VALUES %s
    ON CONFLICT (vuln_id)
    DO UPDATE SET
        title          = EXCLUDED.title,
        description    = EXCLUDED.description,
        cvss_score     = EXCLUDED.cvss_score,
        cvss_vector    = EXCLUDED.cvss_vector,
        fix_version    = COALESCE(EXCLUDED.fix_version, vulnerabilities.fix_version),
        published_date = EXCLUDED.published_date;
"""


def upsert_batch(
    conn: psycopg2.extensions.connection,
    rows: list[tuple],
    batch_label: str,
) -> bool:
    """
    Upsert one batch inside an explicit transaction.
    Returns True on success, False on failure (after rollback).
    """
    if not rows:
        return True

    try:
        with conn.cursor() as cur:
            psycopg2.extras.execute_values(cur, _UPSERT_SQL, rows, page_size=BATCH_SIZE)
        conn.commit()
        log.info("Batch [%s] — upserted %d rows. ✓", batch_label, len(rows))
        return True

    except Exception as exc:
        conn.rollback()
        log.error("Batch [%s] — FAILED (%s). Rolled back.", batch_label, exc)
        return False


def process_and_upsert(
    conn: psycopg2.extensions.connection,
    raw_items: list[dict[str, Any]],
    context: str = "",
) -> tuple[int, int]:
    """
    Parse all raw NVD items, chunk into BATCH_SIZE, upsert each chunk.

    Two-pass failure handling:
      Pass 1 — run every batch; collect failures into failed_batches.
      Pass 2 — retry each failed batch exactly once.
               Batches still failing after retry are logged with their full
               vuln_id lists (groups of 50) so nothing is silently lost.

    Returns (total_parsed, total_upserted).
    """
    # --- Parse stage ---
    parsed_rows: list[tuple] = []
    skipped = 0
    for item in raw_items:
        row = parse_cve(item)
        if row is None:
            skipped += 1
        else:
            parsed_rows.append(row)

    if skipped:
        log.warning("%s — skipped %d malformed CVE(s).", context, skipped)
    log.info("%s — %d rows ready for upsert.", context, len(parsed_rows))

    # --- First pass ---
    failed_batches: list[tuple[str, list[tuple]]] = []
    total_upserted = 0

    for batch_num, offset in enumerate(range(0, len(parsed_rows), BATCH_SIZE), start=1):
        chunk = parsed_rows[offset : offset + BATCH_SIZE]
        label = f"{context}:batch{batch_num}"
        if upsert_batch(conn, chunk, label):
            total_upserted += len(chunk)
        else:
            failed_batches.append((label, chunk))

    # --- Retry pass ---
    if failed_batches:
        log.warning(
            "%s — %d batch(es) failed; retrying once …",
            context, len(failed_batches),
        )
        still_failed: list[tuple[str, list[tuple]]] = []

        for label, chunk in failed_batches:
            if upsert_batch(conn, chunk, f"{label}:retry"):
                total_upserted += len(chunk)
                log.info("Retry succeeded for batch [%s].", label)
            else:
                still_failed.append((label, chunk))

        # --- Permanently failed: log every vuln_id so ops can investigate ---
        if still_failed:
            total_lost = sum(len(c) for _, c in still_failed)
            log.error(
                "%s — %d batch(es) (%d rows) PERMANENTLY FAILED after retry.",
                context, len(still_failed), total_lost,
            )
            for label, chunk in still_failed:
                failed_ids = [row[0] for row in chunk]
                for i in range(0, len(failed_ids), 50):
                    log.error(
                        "  Permanently failed [%s] vuln_ids: %s",
                        label, failed_ids[i : i + 50],
                    )

    return len(parsed_rows), total_upserted


# ---------------------------------------------------------------------------
# Sync orchestration
# ---------------------------------------------------------------------------


def initial_sync(conn: psycopg2.extensions.connection) -> None:
    """
    Full historical import: 2002 → current year, one year at a time.
    Each year is independent — a crash only means re-fetching the incomplete year.
    """
    current_year = datetime.now(timezone.utc).year
    log.info("=== INITIAL SYNC: %d → %d ===", INITIAL_YEAR, current_year)

    grand_parsed   = 0
    grand_upserted = 0

    for year in range(INITIAL_YEAR, current_year + 1):
        raw_items = fetch_year(year)
        parsed, upserted = process_and_upsert(conn, raw_items, context=f"Year-{year}")
        grand_parsed   += parsed
        grand_upserted += upserted
        log.info("Year %d done — parsed=%d upserted=%d", year, parsed, upserted)
        time.sleep(REQUEST_DELAY)  # polite pause between years

    log.info(
        "=== INITIAL SYNC COMPLETE — parsed=%d upserted=%d ===",
        grand_parsed, grand_upserted,
    )



# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def main() -> None:
    log.info("nvd_sync.py starting — %s", datetime.now(timezone.utc).isoformat())

    conn: Optional[psycopg2.extensions.connection] = None
    lock_held = False

    try:
        conn = get_db_connection()

        if not acquire_lock(conn):
            sys.exit(0)
        lock_held = True

        initial_sync(conn)

        log.info("nvd_sync.py finished successfully — %s", datetime.now(timezone.utc).isoformat())

    except EnvironmentError as exc:
        log.error("Configuration error: %s", exc)
        sys.exit(1)

    except Exception as exc:
        log.exception("Unhandled exception: %s", exc)
        sys.exit(1)

    finally:
        if conn and not conn.closed:
            if lock_held:
                try:
                    release_lock(conn)
                except Exception:
                    pass
            conn.close()
            log.info("Database connection closed.")


if __name__ == "__main__":
    main()