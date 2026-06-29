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
from .vulnerability_agent import NVD_API_KEY


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
# TARGETED EPSS API DOWNLOAD
# =========================

async def fetch_epss_batch(session: aiohttp.ClientSession, cve_ids: list) -> dict:
    """Fetches EPSS scores for multiple specific CVEs using a single batched API call."""
    print(f"Fetching EPSS scores for {len(cve_ids)} missing vulnerabilities via API...")
    results = {}
    chunk_size = 100 # FIRST.org API supports multiple CVEs separated by comma
    
    for i in range(0, len(cve_ids), chunk_size):
        chunk = cve_ids[i:i+chunk_size]
        cve_param = ",".join(chunk)
        url = f"https://api.first.org/data/v1/epss?cve={cve_param}"
        try:
            resp = await _get_with_retry(session, url, timeout=15)
            if resp and resp.status == 200:
                data = await resp.json()
                for item in data.get("data", []):
                    cve = item.get("cve")
                    score = item.get("epss")
                    if cve and score is not None:
                        results[cve] = float(score)
        except Exception as exc:
            print(f"  EPSS batch API error for chunk: {exc}")
    
    print(f"Retrieved {len(results)} EPSS scores via batched API fallback.")
    return results


# =========================
# CISA KEV BULK DOWNLOAD
# =========================

async def download_cisa_kev_cves(session: aiohttp.ClientSession) -> set:
    print("Downloading CISA KEV feed for missing vulnerabilities...")
    url = "https://cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
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

async def download_exploit_db_cves(session: aiohttp.ClientSession) -> dict:
    print("Downloading Exploit-DB feed for missing vulnerabilities...")
    url = "https://gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv"
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

    # Ensure intel columns exist in the DataFrame
    for col in ["epss_score", "kev_flag", "exploit_exists", "exploit_count"]:
        if col not in df.columns:
            df[col] = 0.0 if col == "epss_score" else 0

    # ------ 1. DB First Strategy ------
    db_intel_cache = {}
    print(f"Querying database cache as primary source of truth for {len(vuln_ids)} vulnerabilities...")
    
    max_retries = 3
    for attempt in range(max_retries):
        session_db = await get_async_db_session()
        try:
            query_result = await session_db.execute(
                vulnerability_intel_table.select().where(vulnerability_intel_table.c.vuln_id.in_(vuln_ids))
            )
            rows = query_result.fetchall()
            for row in rows:
                db_intel_cache[row.vuln_id] = {
                    "epss_score": row.epss_score,
                    "kev_flag": row.kev_flag,
                    "exploit_exists": row.exploit_exists,
                    "exploit_count": row.exploit_count
                }
            break
        except Exception as exc:
            print(f"Error fetching DB on attempt {attempt + 1}/{max_retries}: {exc}")
            if attempt < max_retries - 1:
                await asyncio.sleep(2)
            else:
                print("Max DB retries reached. Database fetch failed.")
        finally:
            await session_db.close()

    print(f"Found {len(db_intel_cache)} vulnerabilities in local database cache.")

    # ------ 2. Identify Missing Vulnerabilities ------
    missing_cves = [vid for vid in vuln_ids if vid not in db_intel_cache]
    
    kev_cves = set()
    exploit_db_map = {}
    epss_results = {}
    
    if missing_cves:
        print(f"Missing intel for {len(missing_cves)} vulnerabilities. Initiating API fallbacks...")
        async with _build_session() as http_session:
            # Concurrently run the EPSS API batch fetch and the two bulk downloads
            epss_task = asyncio.create_task(fetch_epss_batch(http_session, missing_cves))
            kev_task = asyncio.create_task(download_cisa_kev_cves(http_session))
            exploit_db_task = asyncio.create_task(download_exploit_db_cves(http_session))
            
            results = await asyncio.gather(epss_task, kev_task, exploit_db_task)
            epss_results, kev_cves, exploit_db_map = results
    else:
        print("All vulnerabilities found in database! Bypassing all external API calls.")

    records_to_upsert = []
    current_time = datetime.utcnow()

    # ------ 3. Row-level assignment & Merging ------
    for index, row in df.iterrows():
        vuln_id = row["vuln_id"]
        if pd.isna(vuln_id):
            continue

        if vuln_id in db_intel_cache:
            # 100% DB Cache Hit
            cache_hit = db_intel_cache[vuln_id]
            df.at[index, "epss_score"]    = cache_hit["epss_score"]
            df.at[index, "kev_flag"]      = cache_hit["kev_flag"]
            df.at[index, "exploit_exists"] = cache_hit["exploit_exists"]
            df.at[index, "exploit_count"]  = cache_hit["exploit_count"]
        else:
            # Newly Fetched API Data
            epss_score = epss_results.get(vuln_id, 0.0)
            kev_flag = 1 if vuln_id in kev_cves else 0
            exploit_exists, exploit_count = check_exploit_info(vuln_id, bool(kev_flag), exploit_db_map)
            
            df.at[index, "epss_score"]    = epss_score
            df.at[index, "kev_flag"]      = kev_flag
            df.at[index, "exploit_exists"] = exploit_exists
            df.at[index, "exploit_count"]  = exploit_count
            
            # Stage for DB Update
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

    # ------ 4. Batch DB upsert for missing records only ------
    if records_to_upsert:
        unique_records = list({r["vuln_id"]: r for r in records_to_upsert}.values())
        print(f"Batch upserting {len(unique_records)} new intel records to database cache...")
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
            session_db = await get_async_db_session()
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
        print("No new records to upsert to database.")

if __name__ == "__main__":
    asyncio.run(run_vuln_intel_agent("final_working.csv"))
