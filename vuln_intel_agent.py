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
from db_connection import get_db_session, engine
from vulnerability_agent import NVD_API_KEY


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

async def _fetch_single_epss_score(cve_id: str, session: aiohttp.ClientSession):
    url = f"https://api.first.org/data/v1/epss?cve={cve_id}"
    try:
        resp = await _get_with_retry(session, url, timeout=10)
        if resp and resp.status == 200:
            data = await resp.json()
            items = data.get("data", [])
            if items:
                return float(items[0].get("epss", 0.0))
    except Exception as exc:
        print(f"  Single EPSS lookup failed for {cve_id}: {exc}")
    return None

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
# EXPLOIT AGGREGATOR
# =========================

def check_exploit_info(
    cve_id: str,
    is_kev: bool,
    exploit_db_map: dict
) -> tuple:
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

async def run_vuln_intel_agent(csv_file_path: str):
    print(f"\n--- Vuln Intel Agent: {csv_file_path} ---")
    if not os.path.exists(csv_file_path):
        raise FileNotFoundError(f"CSV not found: {csv_file_path}")

    df = await asyncio.to_thread(pd.read_csv, csv_file_path)

    if "vuln_id" not in df.columns:
        print("No 'vuln_id' column in CSV. Skipping Vuln Intel Agent.")
        return

    vuln_ids = df["vuln_id"].dropna().unique().tolist()
    if not vuln_ids:
        print("No vulnerability IDs to process.")
        return

    # ------ Bulk downloads (all done once before row iteration) ------
    kev_task = asyncio.create_task(download_cisa_kev_cves())
    epss_task = asyncio.create_task(download_epss_scores())
    exploit_db_task = asyncio.create_task(download_exploit_db_cves())

    kev_cves, epss_scores, exploit_db_map = await asyncio.gather(kev_task, epss_task, exploit_db_task)

    # Ensure intel columns exist in the DataFrame
    for col in ["epss_score", "kev_flag", "exploit_exists", "exploit_count"]:
        if col not in df.columns:
            df[col] = 0.0 if col == "epss_score" else 0

    # ------ Fetch Database Fallback ------
    db_intel_fallback = {}
    max_retries = 3
    for attempt in range(max_retries):
        session_db = get_db_session()
        try:
            query_result = await session_db.execute(
                vulnerability_intel_table.select().where(vulnerability_intel_table.c.vuln_id.in_(vuln_ids))
            )
            rows = query_result.fetchall()
            for row in rows:
                db_intel_fallback[row.vuln_id] = {
                    "epss_score": row.epss_score,
                    "kev_flag": row.kev_flag,
                    "exploit_exists": row.exploit_exists,
                    "exploit_count": row.exploit_count
                }
            break
        except Exception as exc:
            print(f"Error fetching DB fallback on attempt {attempt + 1}/{max_retries}: {exc}")
            if attempt < max_retries - 1:
                await asyncio.sleep(2)
            else:
                print("Max DB retries reached for fallback.")
        finally:
            await session_db.close()

    records_to_upsert = []
    current_time = datetime.utcnow()

    # ------ Row-level enrichment ------
    async with _build_session() as fallback_session:
        for index, row in df.iterrows():
            vuln_id = row["vuln_id"]
            if pd.isna(vuln_id):
                continue

            # EPSS: bulk dict first, per-CVE API only if CVE not in bulk data
            epss_score = epss_scores.get(vuln_id)
            if epss_score is None:
                print(f"  EPSS bulk failed or missing. Trying per-CVE API for {vuln_id}...")
                epss_score = await _fetch_single_epss_score(vuln_id, fallback_session)

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
    await asyncio.to_thread(df.to_csv, csv_file_path, index=False)
    print(f"Saved enriched intel data to {csv_file_path}")

    # ------ Batch DB upsert (deduplicated by vuln_id) ------
    if records_to_upsert:
        unique_records = list({r["vuln_id"]: r for r in records_to_upsert}.values())
        print(f"Batch upserting {len(unique_records)} intel records to DB...")
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
        
        max_retries = 3
        for attempt in range(max_retries):
            session_db = get_db_session()
            try:
                await session_db.execute(upsert_stmt, unique_records)
                await session_db.commit()
                print("Batch upsert completed successfully.")
                break
            except Exception as exc:
                await session_db.rollback()
                print(f"DB upsert error on attempt {attempt + 1}/{max_retries}: {exc}")
                if attempt < max_retries - 1:
                    print("Retrying in 2 seconds...")
                    await asyncio.sleep(2)
                else:
                    print("Max DB retries reached. Upsert failed.")
            finally:
                await session_db.close()
    else:
        print("No records to upsert.")

if __name__ == "__main__":
    asyncio.run(run_vuln_intel_agent("final_working.csv"))
