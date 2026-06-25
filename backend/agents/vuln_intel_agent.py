import os
import gzip
import io
import math
import time
import asyncio
import aiohttp
import re
import pandas as pd
from datetime import datetime
from sqlalchemy import Table, Column, String, Float, Integer, DateTime, MetaData
from sqlalchemy.dialects.postgresql import insert as pg_insert
from .db_connection import get_async_db_session, engine
from .vulnerability_agent import fetch_nvd_cve_data, NVD_API_KEY

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
# ASYNC HTTP SESSION LOGIC
# =========================

def _build_headers() -> dict:
    """Returns standard headers for HTTP requests."""
    return {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36"
    }

async def _fetch_with_retry(
    session: aiohttp.ClientSession, 
    url: str, 
    response_type: str = "json", 
    total_retries: int = 5, 
    backoff_factor: float = 1.5, 
    **kwargs
) -> tuple:
    """
    Executes an async request with automatic retry logic.
    Covers transient DNS failures, rate limits, and server errors.
    Returns (status_code, content).
    """
    status_forcelist = (403, 429, 500, 502, 503, 504)
    for attempt in range(total_retries + 1):
        try:
            async with session.get(url, **kwargs) as resp:
                if resp.status in status_forcelist and attempt < total_retries:
                    sleep_time = backoff_factor * (2 ** attempt)
                    await asyncio.sleep(sleep_time)
                    continue
                
                if response_type == "json":
                    content = await resp.json()
                elif response_type == "text":
                    content = await resp.text()
                elif response_type == "raw":
                    content = await resp.read()
                else:
                    content = None
                    
                return resp.status, content
        except (aiohttp.ClientError, asyncio.TimeoutError) as e:
            if attempt < total_retries:
                sleep_time = backoff_factor * (2 ** attempt)
                await asyncio.sleep(sleep_time)
                continue
            return None, None
        except Exception as e:
            return None, None
            
    return None, None


# =========================
# EPSS BULK DOWNLOAD
# =========================

_EPSS_GZIP_URLS = [
    "https://epss.cyentia.com/epss_scores-current.csv.gz",
    "https://api.first.org/data/v1/epss?format=csv.gz",
]

def _parse_epss_gzip(raw_data: bytes) -> dict:
    """Helper to parse EPSS gzip payload off the main thread."""
    with gzip.open(io.BytesIO(raw_data), "rt") as f:
        epss_df = pd.read_csv(f, comment="#")
    if "cve" in epss_df.columns and "epss" in epss_df.columns:
        return dict(zip(epss_df["cve"], epss_df["epss"].astype(float)))
    else:
        print(f"  Unexpected columns in EPSS gzip: {list(epss_df.columns)}")
        return None

async def _download_epss_gzip(session: aiohttp.ClientSession) -> dict:
    """
    Tries each known EPSS gzip URL in order asynchronously.
    """
    for url in _EPSS_GZIP_URLS:
        try:
            print(f"  Trying EPSS gzip URL: {url}")
            status, raw = await _fetch_with_retry(session, url, response_type="raw", timeout=60)
            if status == 200 and raw:
                result = await asyncio.to_thread(_parse_epss_gzip, raw)
                if result is not None:
                    print(f"  EPSS gzip success: {len(result):,} scores downloaded.")
                    return result
            else:
                print(f"  EPSS gzip URL returned HTTP {status}")
        except Exception as exc:
            print(f"  EPSS gzip URL failed: {exc}")
    return {}

async def _download_epss_json_bulk(session: aiohttp.ClientSession, page_size: int = 10000) -> dict:
    """
    Fallback bulk method: pages through the FIRST EPSS JSON API asynchronously.
    """
    print("  Falling back to EPSS JSON bulk API (paginated)...")
    base_url = "https://api.first.org/data/v1/epss"
    result = {}
    offset = 0

    try:
        status, init_data = await _fetch_with_retry(session, base_url, response_type="json", params={"limit": 1, "offset": 0}, timeout=15)
        if status != 200 or not init_data:
            print(f"  EPSS JSON API returned HTTP {status}")
            return {}
            
        total = int(init_data.get("total", 0))
        if total == 0:
            print("  EPSS JSON API reported 0 total records.")
            return {}

        pages = math.ceil(total / page_size)
        print(f"  EPSS JSON API total={total:,} records, fetching {pages} page(s)...")

        for page in range(pages):
            status, page_data = await _fetch_with_retry(
                session, 
                base_url, 
                response_type="json", 
                params={"limit": page_size, "offset": offset}, 
                timeout=30
            )
            if status != 200 or not page_data:
                print(f"  EPSS JSON page {page+1} failed with HTTP {status}")
                break
                
            data = page_data.get("data", [])
            for item in data:
                cve = item.get("cve")
                score = item.get("epss")
                if cve and score is not None:
                    result[cve] = float(score)
                    
            offset += page_size
            await asyncio.sleep(0.5)

        print(f"  EPSS JSON bulk done: {len(result):,} scores fetched.")
    except Exception as exc:
        print(f"  EPSS JSON bulk error: {exc}")
    return result

async def _fetch_single_epss_score(cve_id: str, session: aiohttp.ClientSession) -> float:
    """
    Last-resort fallback: single CVE lookup via FIRST EPSS API asynchronously.
    """
    url = f"https://api.first.org/data/v1/epss?cve={cve_id}"
    try:
        status, data = await _fetch_with_retry(session, url, response_type="json", timeout=10)
        if status == 200 and data:
            items = data.get("data", [])
            if items:
                return float(items[0].get("epss", 0.0))
    except Exception as exc:
        print(f"  Single EPSS lookup failed for {cve_id}: {exc}")
    return 0.0

async def download_epss_scores() -> dict:
    """
    Master EPSS async downloader.
    """
    print("Downloading EPSS scores (bulk priority)...")
    async with aiohttp.ClientSession(headers=_build_headers()) as session:
        scores = await _download_epss_gzip(session)
        if scores:
            return scores

        print("  Primary gzip failed. Trying JSON bulk API...")
        scores = await _download_epss_json_bulk(session)
        if scores:
            return scores

    print("  WARNING: Both bulk EPSS methods failed. Per-CVE fallback will be used.")
    return {}


# =========================
# CISA KEV BULK DOWNLOAD
# =========================

async def download_cisa_kev_cves() -> set:
    """
    Downloads the CISA KEV JSON feed asynchronously.
    """
    print("Downloading CISA KEV feed...")
    url = "https://cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    
    async with aiohttp.ClientSession(headers=_build_headers()) as session:
        try:
            status, data = await _fetch_with_retry(session, url, response_type="json", timeout=30)
            if status == 200 and data:
                kev_cves = {item["cveID"] for item in data.get("vulnerabilities", [])}
                print(f"Downloaded {len(kev_cves):,} CISA KEV CVEs.")
                return kev_cves
            else:
                print(f"CISA KEV feed returned HTTP {status}")
        except Exception as exc:
            print(f"Error downloading CISA KEV feed: {exc}")
    return set()


# =========================
# EXPLOIT-DB BULK DOWNLOAD
# =========================

def _parse_exploit_db_csv(text_data: str) -> dict:
    """Helper to parse Exploit-DB CSV payload off the main thread."""
    exploit_db_df = pd.read_csv(io.StringIO(text_data))
    exploit_db_map: dict = {}
    for _, row in exploit_db_df.iterrows():
        codes = str(row.get("codes", ""))
        cves = re.findall(r"CVE-\d{4}-\d{4,7}", codes, re.IGNORECASE)
        for cve in cves:
            key = cve.upper()
            exploit_db_map[key] = exploit_db_map.get(key, 0) + 1
    return exploit_db_map

async def download_exploit_db_cves() -> dict:
    """
    Downloads Exploit-DB files_exploits.csv asynchronously.
    """
    print("Downloading Exploit-DB feed from GitLab...")
    url = "https://gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv"
    
    async with aiohttp.ClientSession(headers=_build_headers()) as session:
        try:
            status, text_data = await _fetch_with_retry(session, url, response_type="text", timeout=45)
            if status == 200 and text_data:
                exploit_db_map = await asyncio.to_thread(_parse_exploit_db_csv, text_data)
                print(f"Exploit-DB: {len(exploit_db_map):,} CVEs mapped to exploits.")
                return exploit_db_map
            else:
                print(f"Exploit-DB feed returned HTTP {status}")
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
    """
    exploit_count = 0

    if is_kev:
        exploit_count = max(exploit_count, 1)

    if exploit_db_map and cve_id in exploit_db_map:
        exploit_count = max(exploit_count, exploit_db_map[cve_id])

    exploit_exists = 1 if exploit_count > 0 else 0
    return exploit_exists, exploit_count


# =========================
# DATABASE BATCH UPSERT
# =========================

async def _db_batch_upsert(unique_records: list):
    """Helper for wrapping sync DB operations off the main loop."""
    session = await get_async_db_session()
    try:
        stmt = pg_insert(vulnerability_intel_table).values(unique_records)
        update_cols = {
            col.name: stmt.excluded[col.name]
            for col in vulnerability_intel_table.columns
            if col.name != "vuln_id"
        }
        stmt = stmt.on_conflict_do_update(
            index_elements=["vuln_id"],
            set_=update_cols
        )
        session.execute(stmt)
        session.commit()
        print("Batch upsert completed successfully.")
    except Exception as exc:
        session.rollback()
        print(f"DB upsert error: {exc}")
    finally:
        session.close()


# =========================
# MAIN AGENT FUNCTION
# =========================

async def run_vuln_intel_agent(csv_file_path: str):
    """
    Vuln Intel Agent main entry point (Async Version).
    """
    print(f"\n--- Vuln Intel Agent: {csv_file_path} ---")
    if not os.path.exists(csv_file_path):
        raise FileNotFoundError(f"CSV not found: {csv_file_path}")

    # Use to_thread for file I/O to avoid blocking the event loop
    df = await asyncio.to_thread(pd.read_csv, csv_file_path)

    if "vuln_id" not in df.columns:
        print("No 'vuln_id' column in CSV. Skipping Vuln Intel Agent.")
        return

    vuln_ids = df["vuln_id"].dropna().unique().tolist()
    if not vuln_ids:
        print("No vulnerability IDs to process.")
        return

    # ------ Bulk downloads ------
    kev_cves      = await download_cisa_kev_cves()
    epss_scores   = await download_epss_scores()
    exploit_db_map = await download_exploit_db_cves()

    # Ensure intel columns exist in the DataFrame
    for col in ["epss_score", "kev_flag", "exploit_exists", "exploit_count"]:
        if col not in df.columns:
            df[col] = 0.0 if col == "epss_score" else 0

    records_to_upsert = []
    current_time = datetime.utcnow()

    # ------ Row-level enrichment ------
    # Build a re-usable session for per-CVE fallback (rare)
    async with aiohttp.ClientSession(headers=_build_headers()) as fallback_session:
        for index, row in df.iterrows():
            vuln_id = row["vuln_id"]
            if pd.isna(vuln_id):
                continue

            # EPSS: bulk dict first, per-CVE API only if CVE not in bulk data
            epss_score = epss_scores.get(vuln_id)
            if epss_score is None:
                print(f"  EPSS fallback (per-CVE) for {vuln_id}...")
                epss_score = await _fetch_single_epss_score(vuln_id, fallback_session)

            kev_flag = 1 if vuln_id in kev_cves else 0
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

    # Persist enriched CSV using to_thread
    await asyncio.to_thread(df.to_csv, csv_file_path, index=False)
    print(f"Saved enriched intel data to {csv_file_path}")

    # ------ Batch DB upsert (deduplicated by vuln_id) ------
    if records_to_upsert:
        unique_records = list({r["vuln_id"]: r for r in records_to_upsert}.values())
        print(f"Batch upserting {len(unique_records)} intel records to DB...")
        await asyncio.to_thread(_db_batch_upsert, unique_records)
    else:
        print("No records to upsert.")