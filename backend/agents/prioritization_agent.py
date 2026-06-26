import os
import time
import asyncio
import pandas as pd
from datetime import datetime
from sqlalchemy import Table, Column, String, Float, Integer, MetaData, text, DateTime
from sqlalchemy.dialects.postgresql import insert as pg_insert
from .db_connection import get_async_db_session, engine

# =========================
# TABLE SCHEMA
# =========================

metadata = MetaData()
asset_vulnerabilities_table = Table(
    "asset_vulnerabilities", metadata,
    Column("asset_id", String(255), primary_key=True),
    Column("vuln_id", String(255), primary_key=True),
    Column("fix_available", Integer, nullable=False, default=0),
    Column("first_seen", DateTime),
    Column("last_seen", DateTime),
    Column("priority_score", Float),
    Column("priority_level", String(10))
)

# =========================
# HELPER FUNCTIONS
# =========================

def determine_priority_level(score: float) -> str:
    """Map the priority score to an industry-standard level."""
    if score < 4.0:
        return "LOW"
    elif score < 7.0:
        return "MEDIUM"
    elif score < 9.0:
        return "HIGH"
    else:
        return "CRITICAL"

def parse_date(date_str) -> datetime:
    """Safely parse mixed date strings into datetime objects."""
    if pd.isna(date_str) or not date_str:
        return None
    try:
        # Use pandas to loosely parse, returning python datetime
        return pd.to_datetime(date_str, format="mixed", utc=True).to_pydatetime()
    except Exception:
        return None

# =========================
# MAIN AGENT FUNCTION
# =========================

async def run_prioritization_agent(csv_file_path: str):
    print(f"\n--- Prioritization Agent: {csv_file_path} ---")
    if not os.path.exists(csv_file_path):
        raise FileNotFoundError(f"CSV not found: {csv_file_path}")

    df = await asyncio.to_thread(pd.read_csv, csv_file_path)

    required_cols = ["vuln_id", "asset_id"]
    for col in required_cols:
        if col not in df.columns:
            print(f"Missing required column: {col}. Skipping Prioritization Agent.")
            return

    # Ensure output columns exist
    for col in ["priority_score", "priority_level", "fix_available"]:
        if col not in df.columns:
            if col == "priority_level":
                df[col] = pd.NA
            elif col == "fix_available":
                df[col] = 0
            else:
                df[col] = pd.NA

    # Convert UUIDs/IDs to strings for cache matching
    df["asset_id"] = df["asset_id"].astype(str)
    df["vuln_id"] = df["vuln_id"].astype(str)

    # 1. Gather all unique pairs to query the cache
    unique_pairs = df[["asset_id", "vuln_id"]].drop_duplicates()
    asset_ids = unique_pairs["asset_id"].unique().tolist()
    vuln_ids = unique_pairs["vuln_id"].unique().tolist()

    if not asset_ids or not vuln_ids:
        print("No valid asset-vulnerability pairs found.")
        return

    # 2. Build Database Cache
    print(f"Checking database cache for existing priority scores...")
    cache = {}
    query = text('''
        SELECT asset_id::text as asset_id, vuln_id, fix_available, priority_score, priority_level, first_seen, last_seen
        FROM asset_vulnerabilities
        WHERE asset_id::text = ANY(:a_ids) AND vuln_id = ANY(:v_ids)
    ''')
    
    max_retries = 3
    for attempt in range(max_retries):
        session = await get_async_db_session()
        try:
            result = await session.execute(query, {"a_ids": asset_ids, "v_ids": vuln_ids})
            rows = result.fetchall()
            for r in rows:
                cache[(str(r.asset_id), str(r.vuln_id))] = {
                    "fix_available": r.fix_available,
                    "priority_score": r.priority_score,
                    "priority_level": r.priority_level,
                    "first_seen": r.first_seen,
                    "last_seen": r.last_seen
                }
            break
        except Exception as e:
            print(f"Error querying cache on attempt {attempt + 1}/{max_retries}: {e}")
            if attempt < max_retries - 1:
                await asyncio.sleep(2)
            else:
                print("Max retries reached. Cache query failed.")
        finally:
            await session.close()

    print(f"Loaded {len(cache)} existing records from cache.")

    records_to_upsert = []

    # 3. Process Rows
    for index, row in df.iterrows():
        asset_id = str(row["asset_id"])
        vuln_id = str(row["vuln_id"])

        if asset_id == "nan" or vuln_id == "nan":
            continue

        cache_hit = cache.get((asset_id, vuln_id))

        # IF SCORES ALREADY EXIST IN DB CACHE
        if cache_hit and pd.notna(cache_hit["priority_score"]):
            # Bring existing values to CSV
            df.at[index, "priority_score"] = cache_hit["priority_score"]
            df.at[index, "priority_level"] = cache_hit["priority_level"]
            df.at[index, "fix_available"] = cache_hit.get("fix_available", 0)
            continue

        # ELSE CALCULATE SCORE
        # --- A. Determine Fix Availability (Now sourced purely from Vulnerability Agent) ---
        fix_version = str(row.get("fix_version", ""))
        fix_available = 0
        if fix_version and fix_version.upper() not in ["NAN", "NONE", "UNKNOWN", ""]:
            fix_available = 1
        elif cache_hit and cache_hit.get("fix_available") == 1:
            fix_available = 1

        # --- B. Gather & Normalize Factors ---
        cvss_raw = row.get("cvss_score")
        cvss_norm = (float(cvss_raw) / 10.0) if pd.notna(cvss_raw) else 0.0

        epss_raw = row.get("epss_score")
        epss_norm = float(epss_raw) if pd.notna(epss_raw) else 0.0

        kev_raw = row.get("kev_flag")
        kev_norm = float(kev_raw) if pd.notna(kev_raw) else 0.0

        asset_crit_raw = row.get("asset_criticality_score")
        asset_crit_norm = float(asset_crit_raw) if pd.notna(asset_crit_raw) else 0.0

        # Vulnerability Age Normalization
        first_seen_str = row.get("first_seen")
        last_seen_str = row.get("last_seen")
        age_norm = 0.0
        
        fs_date = parse_date(first_seen_str)
        ls_date = parse_date(last_seen_str)
        
        if fs_date and ls_date:
            age_days = (ls_date - fs_date).days
            if age_days < 0:
                age_days = 0
            age_norm = min(age_days / 365.0, 1.0)
        else:
            age_norm = 0.0

        # --- C. Calculate Custom Priority Score ---
        base_score = (
            (cvss_norm * 0.25) +
            (epss_norm * 0.20) +
            (kev_norm * 0.20) +
            (asset_crit_norm * 0.25) +
            (fix_available * 0.05) +
            (age_norm * 0.05)
        )
        
        priority_score = round(base_score * 10.0, 2)
        
        # Hard cap just in case
        if priority_score > 10.0:
            priority_score = 10.0
            
        priority_level = determine_priority_level(priority_score)

        # --- D. Update DataFrame ---
        df.at[index, "priority_score"] = priority_score
        df.at[index, "priority_level"] = priority_level
        df.at[index, "fix_available"] = fix_available

        # Add to upsert batch
        records_to_upsert.append({
            "asset_id": asset_id,
            "vuln_id": vuln_id,
            "fix_available": int(fix_available),
            "first_seen": fs_date,
            "last_seen": ls_date,
            "priority_score": float(priority_score),
            "priority_level": str(priority_level)
        })

    # 5. Persist to CSV
    await asyncio.to_thread(df.to_csv, csv_file_path, index=False)
    print(f"Saved prioritized data to {csv_file_path}")

    # 6. Batch Upsert to DB
    if records_to_upsert:
        unique_records = list({(r["asset_id"], r["vuln_id"]): r for r in records_to_upsert}.values())
        print(f"Batch upserting {len(unique_records)} prioritized records in DB...")
        
        stmt = pg_insert(asset_vulnerabilities_table)
        update_dict = {
            "fix_available": stmt.excluded.fix_available,
            "last_seen": stmt.excluded.last_seen,
            "priority_score": stmt.excluded.priority_score,
            "priority_level": stmt.excluded.priority_level
        }
        upsert_stmt = stmt.on_conflict_do_update(
            constraint="asset_vulnerabilities_pkey",
            set_=update_dict
        )
        
        max_retries = 3
        for attempt in range(max_retries):
            session = await get_async_db_session()
            try:
                await session.execute(upsert_stmt, unique_records)
                await session.commit()
                print("Batch upsert completed successfully.")
                break
            except Exception as exc:
                await session.rollback()
                print(f"DB update error on attempt {attempt + 1}/{max_retries}: {exc}")
                if attempt < max_retries - 1:
                    print("Retrying in 2 seconds...")
                    await asyncio.sleep(2)
                else:
                    print("Max DB retries reached. Update failed.")
            finally:
                await session.close()
    else:
        print("No new priority records to update.")

if __name__ == "__main__":
    # For standalone testing
    asyncio.run(run_prioritization_agent("final_working.csv"))
