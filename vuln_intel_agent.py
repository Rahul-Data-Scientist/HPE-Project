import os
import gzip
import io
import math
import time
import requests
import re
import pandas as pd
from datetime import datetime
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from sqlalchemy import Table, Column, String, Float, Integer, DateTime, MetaData
from sqlalchemy.dialects.postgresql import insert as pg_insert
from db_connection import get_db_session, engine
from vulnerability_agent import fetch_nvd_cve_data, NVD_API_KEY


# =========================
# TABLE SCHEMA
# =========================

metadata = MetaData()
vulnerability_intel_table = Table(
    "vulnerability_intel", metadata,
    Column("vuln_id", String(255), primary_key=True),
    Column("epss_score", Float, nullable=False, default=0.0),
    Column("kev_flag", Integer, nullable=False, default=0),
    Column("exploit_exists", Integer, nullable=False, default=0),
    Column("exploit_count", Integer, nullable=False, default=0),
    Column("last_updated", DateTime, nullable=False, default=datetime.utcnow)
)


# =========================
# HTTP SESSION (with retries)
# =========================

def _build_session(
    total_retries: int = 5,
    backoff_factor: float = 1.5,
    status_forcelist: tuple = (403, 429, 500, 502, 503, 504)
) -> requests.Session:
    """
    Creates a requests.Session with automatic retry logic.
    Covers transient DNS failures, rate limits, and server errors.
    backoff_factor=1.5 means waits: 0s, 1.5s, 3s, 6s, 12s between retries.
    """
    session = requests.Session()
    session.headers.update({
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36"
    })
    retry = Retry(
        total=total_retries,
        backoff_factor=backoff_factor,
        status_forcelist=status_forcelist,
        allowed_methods=["GET"],
        raise_on_status=False
    )
    adapter = HTTPAdapter(max_retries=retry)
    session.mount("https://", adapter)
    session.mount("http://", adapter)
    return session


# =========================
# EPSS BULK DOWNLOAD
# Primary: FIRST gzip file (entire catalog, ~270 KB compressed)
# Fallback 1: FIRST EPSS JSON API in batches of 10000 (still a full bulk pull)
# Fallback 2: Per-CVE FIRST EPSS API (rare last resort)
# =========================

# Alternative mirror URLs for the EPSS gzip catalog
_EPSS_GZIP_URLS = [
    "https://epss.cyentia.com/epss_scores-current.csv.gz",
    "https://api.first.org/data/v1/epss?format=csv.gz",   # API gateway alternate
]

def _download_epss_gzip(session: requests.Session) -> dict:
    """
    Tries each known EPSS gzip URL in order.
    Returns dict {cve_id: epss_score} or empty dict on all failures.
    """
    for url in _EPSS_GZIP_URLS:
        try:
            print(f"  Trying EPSS gzip URL: {url}")
            resp = session.get(url, timeout=60, stream=True)
            if resp.status_code == 200:
                raw = resp.content
                with gzip.open(io.BytesIO(raw), "rt") as f:
                    epss_df = pd.read_csv(f, comment="#")
                if "cve" in epss_df.columns and "epss" in epss_df.columns:
                    result = dict(zip(epss_df["cve"], epss_df["epss"].astype(float)))
                    print(f"  EPSS gzip success: {len(result):,} scores downloaded.")
                    return result
                else:
                    print(f"  Unexpected columns in EPSS gzip: {list(epss_df.columns)}")
            else:
                print(f"  EPSS gzip URL returned HTTP {resp.status_code}")
        except Exception as exc:
            print(f"  EPSS gzip URL failed: {exc}")
    return {}

def _download_epss_json_bulk(session: requests.Session, page_size: int = 10000) -> dict:
    """
    Fallback bulk method: pages through the FIRST EPSS JSON API.
    Returns dict {cve_id: epss_score} or empty dict on failure.
    """
    print("  Falling back to EPSS JSON bulk API (paginated)...")
    base_url = "https://api.first.org/data/v1/epss"
    result = {}
    offset = 0

    try:
        # First request to get total count
        resp = session.get(base_url, params={"limit": 1, "offset": 0}, timeout=15)
        if resp.status_code != 200:
            print(f"  EPSS JSON API returned HTTP {resp.status_code}")
            return {}
        total = int(resp.json().get("total", 0))
        if total == 0:
            print("  EPSS JSON API reported 0 total records.")
            return {}

        pages = math.ceil(total / page_size)
        print(f"  EPSS JSON API total={total:,} records, fetching {pages} page(s)...")

        for page in range(pages):
            resp = session.get(
                base_url,
                params={"limit": page_size, "offset": offset},
                timeout=30
            )
            if resp.status_code != 200:
                print(f"  EPSS JSON page {page+1} failed with HTTP {resp.status_code}")
                break
            data = resp.json().get("data", [])
            for item in data:
                cve = item.get("cve")
                score = item.get("epss")
                if cve and score is not None:
                    result[cve] = float(score)
            offset += page_size
            time.sleep(0.5)   # be polite to the API

        print(f"  EPSS JSON bulk done: {len(result):,} scores fetched.")
    except Exception as exc:
        print(f"  EPSS JSON bulk error: {exc}")
    return result

def _fetch_single_epss_score(cve_id: str, session: requests.Session):
    """
    Last-resort fallback: single CVE lookup via FIRST EPSS API.
    Used only when all bulk methods have failed AND this specific CVE is not in the dict.
    """
    url = f"https://api.first.org/data/v1/epss?cve={cve_id}"
    try:
        resp = session.get(url, timeout=10)
        if resp.status_code == 200:
            items = resp.json().get("data", [])
            if items:
                return float(items[0].get("epss", 0.0))
    except Exception as exc:
        print(f"  Single EPSS lookup failed for {cve_id}: {exc}")
    return None

def download_epss_scores() -> dict:
    """
    Master EPSS downloader.

    Priority order:
      1. Bulk gzip download from epss.first.org (primary, fastest, single request)
      2. Batched JSON API (secondary, still a full bulk pull)
      3. Per-CVE API at lookup time (last resort, rare)

    Returns dict {cve_id: epss_score (float)}.
    An empty dict signals that per-CVE fallback will be used during row processing.
    """
    print("Downloading EPSS scores (bulk priority)...")
    session = _build_session()

    # ---- Primary: gzip bulk ----
    scores = _download_epss_gzip(session)
    if scores:
        return scores

    # ---- Secondary: JSON bulk ----
    print("  Primary gzip failed. Trying JSON bulk API...")
    scores = _download_epss_json_bulk(session)
    if scores:
        return scores

    # ---- All bulk methods failed ----
    print("  WARNING: Both bulk EPSS methods failed. Per-CVE fallback will be used.")
    return {}


# =========================
# CISA KEV BULK DOWNLOAD
# =========================

def download_cisa_kev_cves() -> set:
    """
    Downloads the CISA KEV JSON feed and returns a set of CVE IDs.
    """
    print("Downloading CISA KEV feed...")
    url = "https://cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    session = _build_session()
    try:
        resp = session.get(url, timeout=30)
        if resp.status_code == 200:
            data = resp.json()
            kev_cves = {item["cveID"] for item in data.get("vulnerabilities", [])}
            print(f"Downloaded {len(kev_cves):,} CISA KEV CVEs.")
            return kev_cves
        else:
            print(f"CISA KEV feed returned HTTP {resp.status_code}")
    except Exception as exc:
        print(f"Error downloading CISA KEV feed: {exc}")
    return set()


# =========================
# EXPLOIT-DB BULK DOWNLOAD
# =========================

def download_exploit_db_cves() -> dict:
    """
    Downloads Exploit-DB files_exploits.csv from GitLab.
    Returns dict {CVE_ID: exploit_count}.
    """
    print("Downloading Exploit-DB feed from GitLab...")
    url = "https://gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv"
    session = _build_session()
    try:
        resp = session.get(url, timeout=45)
        if resp.status_code == 200:
            exploit_db_df = pd.read_csv(io.StringIO(resp.text))
            exploit_db_map: dict = {}
            for _, row in exploit_db_df.iterrows():
                codes = str(row.get("codes", ""))
                cves = re.findall(r"CVE-\d{4}-\d{4,7}", codes, re.IGNORECASE)
                for cve in cves:
                    key = cve.upper()
                    exploit_db_map[key] = exploit_db_map.get(key, 0) + 1
            print(f"Exploit-DB: {len(exploit_db_map):,} CVEs mapped to exploits.")
            return exploit_db_map
        else:
            print(f"Exploit-DB feed returned HTTP {resp.status_code}")
    except Exception as exc:
        print(f"Error downloading Exploit-DB feed: {exc}")
    return {}


# =========================
# EXPLOIT AGGREGATOR
# =========================

def check_exploit_info(
    cve_id: str,
    is_kev: bool,
    exploit_db_map: dict
) -> tuple:
    """
    Aggregates exploit evidence from bulk open sources.
    Returns (exploit_exists: int, exploit_count: int).

    Sources (all combined, max count wins):
      1. CISA KEV membership — guaranteed exploit in the wild
      2. Exploit-DB CVE codes — public exploit available
    """
    exploit_count = 0

    # 1. CISA KEV
    if is_kev:
        exploit_count = max(exploit_count, 1)

    # 2. Exploit-DB
    if exploit_db_map and cve_id in exploit_db_map:
        exploit_count = max(exploit_count, exploit_db_map[cve_id])

    exploit_exists = 1 if exploit_count > 0 else 0
    return exploit_exists, exploit_count


# =========================
# MAIN AGENT FUNCTION
# =========================

def run_vuln_intel_agent(csv_file_path: str):
    """
    Vuln Intel Agent main entry point.

    Reads the CSV produced by the Vulnerability Agent, enriches each row with:
      - epss_score   (FIRST EPSS)
      - kev_flag     (CISA KEV)
      - exploit_exists / exploit_count  (KEV + Exploit-DB + NVD refs)

    Saves enriched data back to the same CSV path and performs a batch
    upsert into the vulnerability_intel table on AWS RDS PostgreSQL.
    """
    print(f"\n--- Vuln Intel Agent: {csv_file_path} ---")
    if not os.path.exists(csv_file_path):
        raise FileNotFoundError(f"CSV not found: {csv_file_path}")

    df = pd.read_csv(csv_file_path)

    if "vuln_id" not in df.columns:
        print("No 'vuln_id' column in CSV. Skipping Vuln Intel Agent.")
        return

    vuln_ids = df["vuln_id"].dropna().unique().tolist()
    if not vuln_ids:
        print("No vulnerability IDs to process.")
        return

    # ------ Bulk downloads (all done once before row iteration) ------
    kev_cves      = download_cisa_kev_cves()
    epss_scores   = download_epss_scores()
    exploit_db_map = download_exploit_db_cves()

    # Build a re-usable session for per-CVE fallback (rare)
    fallback_session = _build_session()

    # Ensure intel columns exist in the DataFrame
    for col in ["epss_score", "kev_flag", "exploit_exists", "exploit_count"]:
        if col not in df.columns:
            df[col] = 0.0 if col == "epss_score" else 0

    # ------ Fetch Database Fallback ------
    db_intel_fallback = {}
    try:
        session = get_db_session()
        query_result = session.execute(
            vulnerability_intel_table.select().where(vulnerability_intel_table.c.vuln_id.in_(vuln_ids))
        ).fetchall()
        for row in query_result:
            db_intel_fallback[row.vuln_id] = {
                "epss_score": row.epss_score,
                "kev_flag": row.kev_flag,
                "exploit_exists": row.exploit_exists,
                "exploit_count": row.exploit_count
            }
    except Exception as exc:
        print(f"Database fallback query error: {exc}")
    finally:
        session.close()

    records_to_upsert = []
    current_time = datetime.utcnow()

    # ------ Row-level enrichment ------
    for index, row in df.iterrows():
        vuln_id = row["vuln_id"]
        if pd.isna(vuln_id):
            continue

        # EPSS: bulk dict first, per-CVE API only if CVE not in bulk data
        epss_score = epss_scores.get(vuln_id)
        if epss_score is None:
            print(f"  EPSS bulk failed or missing. Trying per-CVE API for {vuln_id}...")
            epss_score = _fetch_single_epss_score(vuln_id, fallback_session)

        # If per-CVE API failed (or timed out), fallback to DB
        if epss_score is None:
            if vuln_id in db_intel_fallback:
                print(f"  EPSS API completely failed. Falling back to DB cache for {vuln_id}...")
                epss_score = db_intel_fallback[vuln_id]["epss_score"]
            else:
                epss_score = 0.0

        # KEV and ExploitDB: If bulk lists are completely empty, we assume APIs failed
        if not kev_cves and vuln_id in db_intel_fallback:
            kev_flag = db_intel_fallback[vuln_id]["kev_flag"]
        else:
            kev_flag = 1 if vuln_id in kev_cves else 0

        if not exploit_db_map and vuln_id in db_intel_fallback:
            exploit_exists = db_intel_fallback[vuln_id]["exploit_exists"]
            exploit_count = db_intel_fallback[vuln_id]["exploit_count"]
        else:
            exploit_exists, exploit_count = check_exploit_info(vuln_id, bool(kev_flag), exploit_db_map)

        df.at[index, "epss_score"]    = epss_score
        df.at[index, "kev_flag"]      = kev_flag
        df.at[index, "exploit_exists"] = exploit_exists
        df.at[index, "exploit_count"]  = exploit_count

        records_to_upsert.append({
            "vuln_id":       vuln_id,
            "epss_score":    float(epss_score),
            "kev_flag":      int(kev_flag),
            "exploit_exists": int(exploit_exists),
            "exploit_count":  int(exploit_count),
            "last_updated":   current_time
        })

    # Persist enriched CSV
    df.to_csv(csv_file_path, index=False)
    print(f"Saved enriched intel data to {csv_file_path}")

    # ------ Batch DB upsert (deduplicated by vuln_id) ------
    if records_to_upsert:
        unique_records = list({r["vuln_id"]: r for r in records_to_upsert}.values())
        print(f"Batch upserting {len(unique_records)} intel records to DB...")
        session = get_db_session()
        try:
            stmt = pg_insert(vulnerability_intel_table)
            update_cols = {
                col.name: stmt.excluded[col.name]
                for col in vulnerability_intel_table.columns
                if col.name != "vuln_id"
            }
            stmt = stmt.on_conflict_do_update(
                index_elements=["vuln_id"],
                set_=update_cols
            )
            session.execute(stmt, unique_records)
            session.commit()
            print("Batch upsert completed successfully.")
        except Exception as exc:
            session.rollback()
            print(f"DB upsert error: {exc}")
        finally:
            session.close()
    else:
        print("No records to upsert.")
