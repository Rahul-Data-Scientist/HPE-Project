import os
import gzip
import io
import math
import aiohttp
import re
import pandas as pd
import asyncio
import time
from datetime import datetime
from sqlalchemy import Table, Column, String, Float, Integer, DateTime, MetaData, select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from db_connection import get_async_db_session

metadata = MetaData()

vulnerabilities_table = Table(
    "vulnerabilities", metadata,
    Column("vuln_id", String(255), primary_key=True)
)

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

async def _get_with_retry(session: aiohttp.ClientSession, url: str, params=None, timeout=30, total_retries=5, backoff_factor=1.5):
    """
    Async equivalent of urllib3 Retry logic.
    """
    status_forcelist = (403, 429, 500, 502, 503, 504)
    for attempt in range(total_retries):
        try:
            async with session.get(url, params=params, timeout=timeout) as resp:
                if resp.status not in status_forcelist:
                    await resp.read()
                    return resp
                else:
                    print(f"  HTTP {resp.status} for {url}. Retrying...")
                    await asyncio.sleep(backoff_factor * (2 ** attempt))
        except Exception as e:
            print(f"  Network error {e} for {url}. Retrying...")
            await asyncio.sleep(backoff_factor * (2 ** attempt))
    return None

def _build_session() -> aiohttp.ClientSession:
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36"
    }
    return aiohttp.ClientSession(headers=headers)


# =========================
# EPSS BULK DOWNLOAD
# =========================

_EPSS_GZIP_URLS = [
    "https://epss.cyentia.com/epss_scores-current.csv.gz",
    "https://api.first.org/data/v1/epss?format=csv.gz",
]

async def _download_epss_gzip(session: aiohttp.ClientSession) -> dict:
    for url in _EPSS_GZIP_URLS:
        try:
            print(f"  Trying EPSS gzip URL: {url}")
            resp = await _get_with_retry(session, url, timeout=60)
            if resp and resp.status == 200:
                raw = await resp.read()
                def parse_csv(raw_data):
                    with gzip.open(io.BytesIO(raw_data), "rt") as f:
                        epss_df = pd.read_csv(f, comment="#")
                    if "cve" in epss_df.columns and "epss" in epss_df.columns:
                        return dict(zip(epss_df["cve"], epss_df["epss"].astype(float)))
                    return {}
                result = await asyncio.to_thread(parse_csv, raw)
                if result:
                    print(f"  EPSS gzip success: {len(result):,} scores downloaded.")
                    return result
            else:
                print(f"  EPSS gzip URL failed or returned bad HTTP status")
        except Exception as exc:
            print(f"  EPSS gzip URL failed: {exc}")
    return {}

async def _download_epss_json_bulk(session: aiohttp.ClientSession, page_size: int = 10000) -> dict:
    print("  Falling back to EPSS JSON bulk API (paginated)...")
    base_url = "https://api.first.org/data/v1/epss"
    result = {}
    offset = 0

    try:
        resp = await _get_with_retry(session, base_url, params={"limit": 1, "offset": 0}, timeout=15)
        if not resp or resp.status != 200:
            print(f"  EPSS JSON API returned bad HTTP status")
            return {}
            
        data = await resp.json()
        total = int(data.get("total", 0))
        if total == 0:
            print("  EPSS JSON API reported 0 total records.")
            return {}

        pages = math.ceil(total / page_size)
        print(f"  EPSS JSON API total={total:,} records, fetching {pages} page(s)...")

        for page in range(pages):
            resp = await _get_with_retry(session, base_url, params={"limit": page_size, "offset": offset}, timeout=30)
            if not resp or resp.status != 200:
                print(f"  EPSS JSON page {page+1} failed")
                break
                
            page_data = await resp.json()
            items = page_data.get("data", [])
            for item in items:
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

async def download_epss_scores() -> dict:
    print("Downloading EPSS scores (bulk priority)...")
    async with _build_session() as session:
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
    print("Downloading CISA KEV feed...")
    url = "https://cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    async with _build_session() as session:
        try:
            resp = await _get_with_retry(session, url, timeout=30)
            if resp and resp.status == 200:
                data = await resp.json()
                kev_cves = {item["cveID"] for item in data.get("vulnerabilities", [])}
                print(f"Downloaded {len(kev_cves):,} CISA KEV CVEs.")
                return kev_cves
            else:
                print(f"CISA KEV feed returned bad HTTP status")
        except Exception as exc:
            print(f"Error downloading CISA KEV feed: {exc}")
    return set()


# =========================
# EXPLOIT-DB BULK DOWNLOAD
# =========================

async def download_exploit_db_cves() -> dict:
    print("Downloading Exploit-DB feed from GitLab...")
    url = "https://gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv"
    async with _build_session() as session:
        try:
            resp = await _get_with_retry(session, url, timeout=45)
            if resp and resp.status == 200:
                text_data = await resp.text()
                def parse_exploit_db(text):
                    exploit_db_df = pd.read_csv(io.StringIO(text))
                    exploit_db_map: dict = {}
                    for _, row in exploit_db_df.iterrows():
                        codes = str(row.get("codes", ""))
                        cves = re.findall(r"CVE-\d{4}-\d{4,7}", codes, re.IGNORECASE)
                        for cve in cves:
                            key = cve.upper()
                            exploit_db_map[key] = exploit_db_map.get(key, 0) + 1
                    return exploit_db_map
                exploit_db_map = await asyncio.to_thread(parse_exploit_db, text_data)
                print(f"Exploit-DB: {len(exploit_db_map):,} CVEs mapped to exploits.")
                return exploit_db_map
            else:
                print(f"Exploit-DB feed returned bad HTTP status")
        except Exception as exc:
            print(f"Error downloading Exploit-DB feed: {exc}")
    return {}


# =========================
# CRON JOB EXECUTION
# =========================

async def run_cron_sync():
    print("Starting Standalone Async Vulnerability Intel Cron Sync...")
    
    # Run bulk downloads concurrently
    epss_task = asyncio.create_task(download_epss_scores())
    kev_task = asyncio.create_task(download_cisa_kev_cves())
    edb_task = asyncio.create_task(download_exploit_db_cves())
    
    epss_scores, kev_cves, exploit_db_map = await asyncio.gather(epss_task, kev_task, edb_task)
    
    # Consolidate ALL unique CVEs
    all_cves = set(epss_scores.keys()).union(kev_cves).union(exploit_db_map.keys())
    print(f"Total unique CVEs globally: {len(all_cves):,}")

    if not all_cves:
        print("No CVEs found across any intelligence source. Exiting.")
        return

    # Filter against existing vulnerabilities in the database to prevent Foreign Key violations
    db_session = await get_async_db_session()
    try:
        existing_vulns_query = await db_session.execute(select(vulnerabilities_table.c.vuln_id))
        existing_vulns = {row[0] for row in existing_vulns_query.fetchall()}
        all_cves = all_cves.intersection(existing_vulns)
        print(f"Filtered to {len(all_cves):,} CVEs that exist in the local database.")
    except Exception as e:
        print(f"Error fetching existing vulnerabilities: {e}")
        await db_session.close()
        return

    # Build Records
    records = []
    current_time = datetime.utcnow()
    for cve in all_cves:
        epss = epss_scores.get(cve, 0.0)
        kev = 1 if cve in kev_cves else 0
        exp_count = max(kev, exploit_db_map.get(cve, 0))
        exp_exists = 1 if exp_count > 0 else 0
        
        records.append({
            "vuln_id": cve,
            "epss_score": float(epss),
            "kev_flag": kev,
            "exploit_exists": exp_exists,
            "exploit_count": exp_count,
            "last_updated": current_time
        })

    # Batch Upsert to DB
    if not all_cves:
        print("No intersecting CVEs to upsert. Exiting.")
        await db_session.close()
        return

    batch_size = 500
    try:
        total = len(records)
        
        # Prepare the UPSERT statement
        stmt = pg_insert(vulnerability_intel_table)
        update_cols = {
            col.name: stmt.excluded[col.name]
            for col in vulnerability_intel_table.columns
            if col.name != "vuln_id"
        }
        upsert_stmt = stmt.on_conflict_do_update(
            index_elements=["vuln_id"],
            set_=update_cols
        )
        
        for i in range(0, total, batch_size):
            batch = records[i:i+batch_size]
            max_retries = 3
            for attempt in range(max_retries):
                try:
                    await db_session.execute(upsert_stmt, batch)
                    await db_session.commit()
                    print(f"  Upserted batch {(i//batch_size) + 1}/{(total + batch_size - 1)//batch_size}")
                    break
                except Exception as e:
                    await db_session.rollback()
                    print(f"  Batch upsert error on attempt {attempt + 1}/{max_retries}: {e}")
                    if attempt < max_retries - 1:
                        await asyncio.sleep(2)
                    else:
                        print("  Max retries reached for this batch.")
        print("Successfully synced all vulnerability intelligence to database!")
    except Exception as e:
        print(f"Database setup error during cron sync: {e}")
    finally:
        await db_session.close()

if __name__ == "__main__":
    asyncio.run(run_cron_sync())
