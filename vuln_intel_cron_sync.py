import os
import gzip
import io
import re
import time
import requests
import pandas as pd
from datetime import datetime
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from sqlalchemy import Table, Column, String, Float, Integer, DateTime, MetaData
from sqlalchemy.dialects.postgresql import insert as pg_insert
from db_connection import get_db_session

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

def _build_session():
    session = requests.Session()
    session.headers.update({
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36"
    })
    retry = Retry(
        total=5,
        backoff_factor=1.5,
        status_forcelist=(403, 429, 500, 502, 503, 504),
        allowed_methods=["GET"],
        raise_on_status=False
    )
    adapter = HTTPAdapter(max_retries=retry)
    session.mount("https://", adapter)
    session.mount("http://", adapter)
    return session

def run_cron_sync():
    print("Starting Standalone Vulnerability Intel Cron Sync...")
    session = _build_session()
    
    # 1. Download EPSS
    print("Downloading EPSS GZIP Catalog...")
    epss_scores = {}
    epss_url = "https://epss.cyentia.com/epss_scores-current.csv.gz"
    try:
        resp = session.get(epss_url, timeout=60, stream=True)
        if resp.status_code == 200:
            with gzip.open(io.BytesIO(resp.content), "rt") as f:
                epss_df = pd.read_csv(f, comment="#")
            if "cve" in epss_df.columns and "epss" in epss_df.columns:
                epss_scores = dict(zip(epss_df["cve"], epss_df["epss"].astype(float)))
                print(f"Loaded {len(epss_scores):,} EPSS scores.")
    except Exception as e:
        print(f"Error fetching EPSS: {e}")

    # 2. Download KEV
    print("Downloading CISA KEV Feed...")
    kev_cves = set()
    kev_url = "https://cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    try:
        resp = session.get(kev_url, timeout=30)
        if resp.status_code == 200:
            kev_cves = {item["cveID"] for item in resp.json().get("vulnerabilities", [])}
            print(f"Loaded {len(kev_cves):,} KEV CVEs.")
    except Exception as e:
        print(f"Error fetching KEV: {e}")

    # 3. Download Exploit-DB
    print("Downloading Exploit-DB Feed...")
    exploit_db_map = {}
    edb_url = "https://gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv"
    try:
        resp = session.get(edb_url, timeout=45)
        if resp.status_code == 200:
            edb_df = pd.read_csv(io.StringIO(resp.text))
            for _, row in edb_df.iterrows():
                codes = str(row.get("codes", ""))
                cves = re.findall(r"CVE-\d{4}-\d{4,7}", codes, re.IGNORECASE)
                for cve in cves:
                    key = cve.upper()
                    exploit_db_map[key] = exploit_db_map.get(key, 0) + 1
            print(f"Loaded {len(exploit_db_map):,} Exploit-DB mappings.")
    except Exception as e:
        print(f"Error fetching Exploit-DB: {e}")

    # 4. Consolidate ALL unique CVEs
    all_cves = set(epss_scores.keys()).union(kev_cves).union(exploit_db_map.keys())
    print(f"Total unique CVEs to upsert: {len(all_cves):,}")

    if not all_cves:
        print("No CVEs found across any intelligence source. Exiting.")
        return

    # 5. Build Records
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

    # 6. Batch Upsert to DB
    batch_size = 500
    db_session = get_db_session()
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
                    db_session.execute(upsert_stmt, batch)
                    db_session.commit()
                    print(f"  Upserted batch {(i//batch_size) + 1}/{(total + batch_size - 1)//batch_size}")
                    break
                except Exception as e:
                    db_session.rollback()
                    print(f"  Batch upsert error on attempt {attempt + 1}/{max_retries}: {e}")
                    if attempt < max_retries - 1:
                        time.sleep(2)
                    else:
                        print("  Max retries reached for this batch.")
        print("Successfully synced all vulnerability intelligence to database!")
    except Exception as e:
        print(f"Database setup error during cron sync: {e}")
    finally:
        db_session.close()

if __name__ == "__main__":
    run_cron_sync()
