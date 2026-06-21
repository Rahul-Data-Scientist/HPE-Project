# %% [markdown]
# # Agent 1 — Asset Lookup Agent
# 
# **Role in pipeline:** Sits right after Normalization. Receives `working.csv`, resolves every asset against the DB using priority-ordered matching (instance_id → hostname → IP), enriches the CSV with existing asset data, generates UUIDs for new ones, and hands off to Agent 2 (Asset Criticality).
# 
# ### What this agent does
# 1. Read `working.csv` → extract unique assets
# 2. Priority DB lookup: instance_id first, then hostname, then IP
# 3. For **existing** assets → fetch all fields, write into CSV
# 4. For **new** assets → generate UUID, insert skeleton row (`ON CONFLICT DO NOTHING`)
# 5. Batch upsert `last_seen` (+ `first_seen` for new) at the end
# 6. Save enriched CSV → hand `state` to Agent 2

# ============================================================================
# Integration Notes
#
# Import:
#
#     from backend.agents.asset_lookup_agent import asset_lookup_graph
#
# Running:
#
#     asset_lookup_graph.invoke(initial_state)
#
# Asset Lookup Agent internally invokes Asset Criticality Agent.
#
# Therefore importing/running Asset Lookup Agent automatically executes:
#
#     Asset Lookup
#         ↓
#     Asset Criticality
#
# No additional node for Asset Criticality is required in the parent flow.
#
# To append another agent, add a new node after call_criticality_agent:
#
#     call_criticality_agent
#             ↓
#     call_next_agent
#             ↓
#            END
#
# ============================================================================

# %%
# ── Imports ───────────────────────────────────────────────────────────────
import os, uuid, json, logging, time
from datetime import datetime, timezone
from typing import TypedDict, Optional

import pandas as pd
import psycopg2
import psycopg2.extras
from dotenv import load_dotenv

from langgraph.graph import StateGraph, END
from .asset_criticality_agent import criticality_graph

load_dotenv(override=True)   # reads .env in cwd

logging.basicConfig(level=logging.INFO, format="%(levelname)s | %(message)s")
log = logging.getLogger("asset_lookup")


# %%
# ── Retry helper ──────────────────────────────────────────────────────────
_RETRY_ATTEMPTS = 3
_RETRY_DELAY    = 5  # seconds

_TRANSIENT_ERRORS = (psycopg2.OperationalError, ConnectionError, TimeoutError)


def retry(fn, *args, **kwargs):
    """
    Call fn(*args, **kwargs) up to _RETRY_ATTEMPTS times.
    Retries only on transient infrastructure errors.
    Raises on the last failure.
    """
    last_exc = None
    for attempt in range(1, _RETRY_ATTEMPTS + 1):
        try:
            return fn(*args, **kwargs)
        except _TRANSIENT_ERRORS as e:
            last_exc = e
            if attempt < _RETRY_ATTEMPTS:
                log.warning("[retry] Attempt %d/%d failed: %s — retrying in %ds",
                            attempt, _RETRY_ATTEMPTS, e, _RETRY_DELAY)
                time.sleep(_RETRY_DELAY)
            else:
                log.error("[retry] All %d attempts failed: %s", _RETRY_ATTEMPTS, e)
    raise last_exc


# ── DB connection ─────────────────────────────────────────────────────────

def _connect():
    return psycopg2.connect(
        host     = os.environ["DB_HOST"],
        port     = int(os.environ.get("DB_PORT", 5432)),
        dbname   = os.environ["DB_NAME"],
        user     = os.environ["DB_USER"],
        password = os.environ["DB_PASSWORD"],
        sslmode  = os.environ.get("DB_SSLMODE", "require"),
        connect_timeout = 10,
    )


def get_conn():
    """ a DB connection with retry on transient failures."""
    return retry(_connect)


# %%
# ── LangGraph state ───────────────────────────────────────────────────────
class AssetLookupState(TypedDict):
    working_csv: str          # path to working.csv
    status:      str          # running | done | error
    error:       Optional[str]
    new_count:   int          # how many new assets were created
    existing_count: int       # how many existing assets were found

# %%
# ═══════════════════════════════════════════════════════════════════════════
# DB REPOSITORY  –  all SQL lives here, nowhere else
# ═══════════════════════════════════════════════════════════════════════════

# Asset columns we want to pull back from the DB
_ASSET_COLS = [
    "asset_id", "ip_address", "hostname", "instance_id",
    "inferred_role", "exposure_score", "environment", "cloud_type",
    "dependency_level", "dependency_score", "asset_criticality_score",
    "first_seen", "last_seen",
]


def _rows_to_dicts(cursor) -> list[dict]:
    cols = [d[0] for d in cursor.description]
    return [dict(zip(cols, row)) for row in cursor.fetchall()]


# ── Priority lookup functions ───────────────────────────────────

def lookup_by_instance_ids(conn, ids: list[str]) -> list[dict]:
    """Fetch assets whose instance_id matches any in *ids*."""
    if not ids:
        return []
    with conn.cursor() as cur:
        cur.execute(
            f"SELECT {', '.join(_ASSET_COLS)} FROM assets "
            "WHERE instance_id = ANY(%s)",
            (ids,)
        )
        return _rows_to_dicts(cur)


def lookup_by_hostnames(conn, hostnames: list[str]) -> list[dict]:
    """Fetch assets whose hostname matches any in *hostnames*."""
    if not hostnames:
        return []
    with conn.cursor() as cur:
        cur.execute(
            f"SELECT {', '.join(_ASSET_COLS)} FROM assets "
            "WHERE hostname = ANY(%s)",
            (hostnames,)
        )
        return _rows_to_dicts(cur)


def lookup_by_ips(conn, ips: list[str]) -> list[dict]:
    """Fetch assets whose ip_address matches any in *ips*."""
    if not ips:
        return []
    with conn.cursor() as cur:
        cur.execute(
            f"SELECT {', '.join(_ASSET_COLS)} FROM assets "
            "WHERE host(ip_address) = ANY(%s)",
            (ips,)
        )
        return _rows_to_dicts(cur)


# ── Skeleton insert───────────────────

def insert_skeleton_assets(conn, rows: list[dict]) -> None:
    """
    Insert one at a time so each row hits the right conflict index.
    ON CONFLICT DO NOTHING fires if instance_id, hostname, OR ip already exists.
    """
    if not rows:
        return
    sql = """
        INSERT INTO assets
            (asset_id, ip_address, hostname, instance_id, first_seen, last_seen)
        VALUES
            (%(asset_id)s, %(ip_address)s, %(hostname)s,
             %(instance_id)s, %(first_seen)s, %(last_seen)s)
        ON CONFLICT DO NOTHING
    """
    with conn.cursor() as cur:
        psycopg2.extras.execute_batch(cur, sql, rows)
    conn.commit()


# fetch actual asset ids from db
def fetch_actual_asset_ids(conn, skeleton_rows: list[dict]) -> dict:
    actual_map = {}
    with conn.cursor() as cur:
        for row in skeleton_rows:
            iid = row.get("instance_id")
            hn  = row.get("hostname")
            ip  = row.get("ip_address")
            
            if iid:
                cur.execute("SELECT asset_id FROM assets WHERE instance_id = %s LIMIT 1", (iid,))
            elif hn:
                cur.execute("SELECT asset_id FROM assets WHERE hostname = %s LIMIT 1", (hn,))
            elif ip:
                cur.execute("SELECT asset_id FROM assets WHERE host(ip_address) = %s LIMIT 1", (ip.split("/")[0],))
            else:
                log.warning("[fetch_actual_asset_ids] Skeleton row has no identity fields — skipping")
                continue
                
            result = cur.fetchone()
            if result:
                # Key must match what _row_key() produces in assign_uuids_to_new
                key = (iid or "", hn or "", ip or "")
                actual_map[key] = str(result[0])
    return actual_map

# ── Batch upsert last_seen / first_seen ────────────────────────

def batch_update_seen_timestamps(conn, rows: list[dict]) -> None:
    """
    Upsert last_seen for all assets.
    For existing assets only last_seen is touched.
    For new assets both first_seen and last_seen were already set on insert,
    but we still run DO UPDATE to keep the call uniform.
    """
    if not rows:
        return
    sql = """
        INSERT INTO assets (asset_id, last_seen)
        VALUES (%(asset_id)s, %(last_seen)s)
        ON CONFLICT (asset_id)
        DO UPDATE SET last_seen = EXCLUDED.last_seen
    """
    with conn.cursor() as cur:
        psycopg2.extras.execute_batch(cur, sql, rows)
    conn.commit()

# %%
# ═══════════════════════════════════════════════════════════════════════════
# HELPER  –  priority-ordered resolution
# ═══════════════════════════════════════════════════════════════════════════

def _normalize_ip(ip_str: str) -> str:
    """Strip prefix notation e.g. '1.2.3.4/32' → '1.2.3.4'"""
    return ip_str.split("/")[0].strip() if ip_str else ip_str

def resolve_assets_from_db(conn, unique_assets: pd.DataFrame) -> dict:
    """
    Given a dataframe of unique assets (one row per asset),
    return a dict keyed by a stable CSV-side identifier mapping to
    the DB row (or None if not found).

    Priority: instance_id → hostname → ip_address

    Returns
    -------
    dict of { csv_key -> db_row_dict or None }
    where csv_key is a tuple (instance_id, hostname, ip) from the CSV.
    """

    def _val(row, col):
        v = row.get(col, None)
        return str(v).strip() if v and str(v).strip().lower() not in ("", "none", "nan", "null") else None

    # --- collect lookup lists ---
    instance_ids = [_val(r, "instance_id") for _, r in unique_assets.iterrows() if _val(r, "instance_id")]
    hostnames    = [_val(r, "hostname")    for _, r in unique_assets.iterrows() if _val(r, "hostname")]
    ips = [_normalize_ip(_val(r, "ip")) for _, r in unique_assets.iterrows() if _val(r, "ip")]

    # --- batch fetch ---
    by_instance = {r["instance_id"]: r for r in lookup_by_instance_ids(conn, instance_ids) if r.get("instance_id")}
    by_hostname  = {r["hostname"]   : r for r in lookup_by_hostnames(conn, hostnames)       if r.get("hostname")}
    by_ip        = {r["ip_address"].split("/")[0].strip() : r for r in lookup_by_ips(conn, ips)                   if r.get("ip_address")}

    # --- per-row resolution (priority order) ---
    resolution = {}   # csv_index -> db_row or None
    for idx, row in unique_assets.iterrows():
        iid = _val(row, "instance_id")
        hn  = _val(row, "hostname")
        ip  = _val(row, "ip")

        if iid and iid in by_instance:
            resolution[idx] = by_instance[iid]
        elif hn and hn in by_hostname:
            resolution[idx] = by_hostname[hn]
        elif ip and ip in by_ip:
            resolution[idx] = by_ip[ip]
        else:
            resolution[idx] = None   # brand-new asset

    return resolution

# %%
# Helper Cleaner
def clean(v):
    if pd.isna(v):
        return None

    v = str(v).strip()

    if v.lower() in ("", "nan", "none", "null"):
        return None

    return v

# %%
# ═══════════════════════════════════════════════════════════════════════════
# NODE 1 — load_csv
# Read working.csv and do basic validation
# ═══════════════════════════════════════════════════════════════════════════

def load_csv(state: AssetLookupState) -> AssetLookupState:
    _csv_cache.clear()
    log.info("[load_csv] Reading %s", state["working_csv"])
    try:
        df = pd.read_csv(state["working_csv"])
        log.info("  → %d rows, %d columns", len(df), len(df.columns))

        # Normalise column names to lowercase stripped
        df.columns = [c.strip().lower() for c in df.columns]
        
         # ==========================================================
        # Remove rows with NO asset identity
        # ==========================================================

        for col in ["instance_id", "hostname", "ip"]:
            if col not in df.columns:
                df[col] = pd.NA

        before_count = len(df)

        invalid_assets = df[
            df["instance_id"].isna()
            & df["hostname"].isna()
            & df["ip"].isna()
        ].copy()

        if not invalid_assets.empty:
            invalid_assets["rejection_reason"] = "NO_IDENTIFIER"
            os.makedirs("backend/rejected_records", exist_ok=True)

            invalid_assets.to_csv(
                "backend/rejected_records/rejected_asset_records.csv",
                mode="a",
                header=not os.path.exists("backend/rejected_records/rejected_asset_records.csv"),
                index=False
            )

            log.warning(
                "[load_csv] Removed %d rows with no asset identifiers",
                len(invalid_assets)
            )

        df = df[
            ~(
                df["instance_id"].isna()
                & df["hostname"].isna()
                & df["ip"].isna()
            )
        ].copy()

        log.info(
            "[load_csv] %d valid rows remain",
            len(df)
        )

        # The CSV must have at least one of these three identity columns
        id_cols = ["instance_id", "hostname", "ip"]
        if not any(c in df.columns for c in id_cols):
            raise ValueError(f"CSV has none of the required identity columns: {id_cols}")

        # Persist df in state via a side-channel (module-level cache)
        _csv_cache["df"] = df
        return {**state, "status": "running"}

    except Exception as e:
        log.error("[load_csv] %s", e)
        return {**state, "status": "error", "error": str(e)}


_csv_cache: dict = {}  # lightweight in-process cache shared across nodes

# %%
# ═══════════════════════════════════════════════════════════════════════════
# NODE 2 — db_lookup_and_split
# Priority-ordered DB lookup → split into existing vs new
# ═══════════════════════════════════════════════════════════════════════════

def db_lookup_and_split(state: AssetLookupState) -> AssetLookupState:
    if state["status"] == "error":
        return state

    log.info("[db_lookup_and_split] Starting priority-ordered DB lookup")
    df = _csv_cache["df"]

    # Build unique-asset slice
    id_cols_present = [c for c in ["instance_id", "hostname", "ip"] if c in df.columns]
    unique_assets = df[id_cols_present].drop_duplicates().reset_index(drop=True)

    # ── VALIDATION: skip assets with no identifiers ───────────────────────
    valid_rows = []
    for idx, row in unique_assets.iterrows():
        hostname    = clean(row.get("hostname"))
        ip          = clean(row.get("ip"))
        instance_id = clean(row.get("instance_id"))
        if not hostname and not ip and not instance_id:
            log.warning("[db_lookup_and_split] Skipping asset with no identifiers (row %d)", idx)
            continue
        valid_rows.append(idx)
    unique_assets = unique_assets.loc[valid_rows].reset_index(drop=True)
    # ─────────────────────────────────────────────────────────────────────

    log.info("  → %d unique assets from %d rows", len(unique_assets), len(df))

    try:
        conn = get_conn()   # retry wrapper handles transient failures
        resolution = resolve_assets_from_db(conn, unique_assets)
        conn.close()
    except Exception as e:
        log.error("[db_lookup_and_split] DB error: %s", e)
        return {**state, "status": "error", "error": str(e)}

    existing, new_assets = [], []
    for idx, db_row in resolution.items():
        csv_row = unique_assets.iloc[idx].to_dict()
        if db_row:
            existing.append({"csv": csv_row, "db": db_row})
        else:
            new_assets.append({"csv": csv_row})

    log.info("  → %d existing, %d new", len(existing), len(new_assets))
    _csv_cache["existing"]      = existing
    _csv_cache["new_assets"]    = new_assets
    _csv_cache["unique_assets"] = unique_assets

    return {**state, "existing_count": len(existing), "new_count": len(new_assets)}


# %%
# ═══════════════════════════════════════════════════════════════════════════
# NODE 3 — enrich_existing_in_csv
# For assets already in DB: pull their criticality/role/exposure etc.
# into the working CSV so Agent 2 can skip recalculation for them.
# ═══════════════════════════════════════════════════════════════════════════

# Columns we copy from DB into CSV for existing assets
_DB_ENRICH_COLS = [
    "asset_id", "inferred_role", "exposure_score", "environment",
    "cloud_type", "dependency_level", "dependency_score", "asset_criticality_score",
    "first_seen", "last_seen",
]


def enrich_existing_in_csv(state: AssetLookupState) -> AssetLookupState:
    if state["status"] == "error":
        return state
    
    existing = _csv_cache["existing"]
    df       = _csv_cache["df"]
    now = datetime.now(timezone.utc).isoformat()
    
    # Ensure the enrichment columns exist in df
    for col in _DB_ENRICH_COLS:
        if col not in df.columns:
            df[col] = None

        df[col] = df[col].astype("object")

    log.info("[enrich_existing_in_csv] Enriching %d existing assets in CSV", len(existing))


    # Build a lookup: identity value → db row
    db_by_asset_id: dict = {}
    for item in existing:
        db_row = item["db"]
        db_by_asset_id[db_row["asset_id"]] = db_row

    # Also build a map from csv identity → asset_id
    id_to_asset_id: dict = {}  # (iid, hn, ip) -> asset_id
    for item in existing:
        db = item["db"]
        csv = item["csv"]
        key = (
            clean(csv.get("instance_id")),
            clean(csv.get("hostname")),
            clean(csv.get("ip")),
        )
        id_to_asset_id[key] = db["asset_id"]

    def _match_key(row):
        return (
            clean(row.get("instance_id")),
            clean(row.get("hostname")),
            clean(row.get("ip")),
        )

    enriched = 0
    for i, row in df.iterrows():
        key = _match_key(row)
        asset_id = id_to_asset_id.get(key)
        if not asset_id:
            continue
        db_row = db_by_asset_id[asset_id]
        for col in _DB_ENRICH_COLS:
            df.at[i, col] = db_row.get(col)
        df.at[i, "last_seen"] = now
        enriched += 1

    log.info("  → Enriched %d CSV rows from DB", enriched)
    _csv_cache["df"] = df
    return state

# %%
# ═══════════════════════════════════════════════════════════════════════════
# NODE 4 — assign_uuids_to_new
# Generate UUIDs for new assets and insert skeleton rows
# ═══════════════════════════════════════════════════════════════════════════

def assign_uuids_to_new(state: AssetLookupState) -> AssetLookupState:
    if state["status"] == "error":
        return state

    new_assets = _csv_cache["new_assets"]
    df         = _csv_cache["df"]
    log.info("[assign_uuids_to_new] Generating UUIDs for %d new assets", len(new_assets))
    now = datetime.now(timezone.utc).isoformat()

    for col in _DB_ENRICH_COLS:
        if col not in df.columns:
            df[col] = None

    skeleton_rows  = []
    new_uuid_map   = {}

    for item in new_assets:
        csv = item["csv"]
        new_id = str(uuid.uuid4())
        item["asset_id"] = new_id

        iid = clean(csv.get("instance_id"))
        hn  = clean(csv.get("hostname"))
        ip  = clean(csv.get("ip")) 

        if not iid and not hn and not ip:
            log.warning("[assign_uuids_to_new] Skipping new asset with no identity fields")
            continue

        # KEY: (iid, hn, ip) — all three using the CSV "ip" value
        key = (iid or "", hn or "", ip or "")
        new_uuid_map[key] = new_id

        skeleton_rows.append({
            "asset_id":    new_id,
            "instance_id": iid,
            "hostname":    hn,
            "ip_address":  ip,   # DB column name for the INSERT
            "first_seen":  now,
            "last_seen":   now,
        })

    if skeleton_rows:
        try:
            def _do_insert():
                conn = get_conn()
                insert_skeleton_assets(conn, skeleton_rows)
                actual_map = fetch_actual_asset_ids(conn, skeleton_rows)
                conn.close()
                return actual_map
            actual_uuid_map = retry(_do_insert)
            log.info("  → Inserted/verified %d skeleton rows in DB", len(skeleton_rows))
        except Exception as e:
            log.error("[assign_uuids_to_new] DB insert error after retries: %s", e)
            return {**state, "status": "error", "error": str(e)}
    else:
        actual_uuid_map = {}

    # _row_key must produce (iid, hn, ip) using the CSV "ip" column — same as key above
    def _row_key(row):
        return (
            clean(row.get("instance_id")) or "",
            clean(row.get("hostname"))    or "",
            clean(row.get("ip"))          or "",
        )

    patched = 0
    for i, row in df.iterrows():
        key = _row_key(row)
        if key in actual_uuid_map:
            df.at[i, "asset_id"] = actual_uuid_map[key]
            patched += 1

    log.info("  → Patched asset_id for %d CSV rows (new assets)", patched)
    _csv_cache["df"]          = df
    _csv_cache["new_uuid_map"] = new_uuid_map
    return state


# %%
# ═══════════════════════════════════════════════════════════════════════════
# NODE 5 — update_seen_timestamps
# One final DB batch: last_seen for all, first_seen for new
# ═══════════════════════════════════════════════════════════════════════════

def update_seen_timestamps(state: AssetLookupState) -> AssetLookupState:
    if state["status"] == "error":
        return state

    df  = _csv_cache["df"]
    now = datetime.now(timezone.utc).isoformat()

    # Collect all asset_ids that now have a resolved UUID
    seen_rows = []
    for asset_id in df["asset_id"].dropna().unique():
        seen_rows.append({"asset_id": str(asset_id), "last_seen": now})

    log.info("[update_seen_timestamps] Batch-updating last_seen for %d assets", len(seen_rows))
    try:
        def _do_update():
            conn = get_conn()
            batch_update_seen_timestamps(conn, seen_rows)
            conn.close()
        retry(_do_update)
        log.info("  → Done")
    except Exception as e:
        log.error("[update_seen_timestamps] Failed after retries: %s", e)
        return {**state, "status": "error", "error": str(e)}

    return state


# %%
# ═══════════════════════════════════════════════════════════════════════════
# NODE 6 — save_csv
# Persist enriched working.csv and finalise state for Agent 2
# ═══════════════════════════════════════════════════════════════════════════

def save_csv(state: AssetLookupState) -> AssetLookupState:
    if state["status"] == "error":
        return state

    df   = _csv_cache["df"]
    path = state["working_csv"]

    try:
        os.makedirs("backend/normalized_output", exist_ok=True)
        df.to_csv(path, index=False)
        log.info("[save_csv] Saved %d rows → %s", len(df), path)
    except Exception as e:
        log.error("[save_csv] %s", e)
        return {**state, "status": "error", "error": str(e)}

    return {**state, "status": "done"}


# Node 7 : to call criticality agent
def call_criticality_agent(state: AssetLookupState) -> AssetLookupState:

    if state["status"] == "error":
        return state

    log.info("[call_criticality_agent] Starting Asset Criticality Agent")

    try:
        result = criticality_graph.invoke({
            "working_csv": state["working_csv"],
            "status": "running",
            "error": None,
            "processed": 0,
            "skipped": 0,
            "llm_calls": 0
        })

        if result["status"] == "error":
            return {
                **state,
                "status": "error",
                "error": result["error"]
            }

        log.info("[call_criticality_agent] Asset Criticality Agent completed")

    except Exception as e:
        log.error("[call_criticality_agent] %s", e)

        return {
            **state,
            "status": "error",
            "error": str(e)
        }

    return state

# %%
# ═══════════════════════════════════════════════════════════════════════════
# ROUTING  — skip on error
# ═══════════════════════════════════════════════════════════════════════════

def route(state: AssetLookupState) -> str:
    return "error_end" if state["status"] == "error" else "continue"

# %%
# ═══════════════════════════════════════════════════════════════════════════
# BUILD THE GRAPH
# ═══════════════════════════════════════════════════════════════════════════

builder = StateGraph(AssetLookupState)

builder.add_node("load_csv",              load_csv)
builder.add_node("db_lookup_and_split",   db_lookup_and_split)
builder.add_node("enrich_existing_in_csv",enrich_existing_in_csv)
builder.add_node("assign_uuids_to_new",   assign_uuids_to_new)
builder.add_node("update_seen_timestamps",update_seen_timestamps)
builder.add_node("save_csv",              save_csv)
builder.add_node("call_criticality_agent", call_criticality_agent)

builder.set_entry_point("load_csv")

# load_csv → db_lookup_and_split (or stop on error)
builder.add_conditional_edges(
    "load_csv",
    route,
    {"continue": "db_lookup_and_split", "error_end": END}
)

# db_lookup_and_split → enrich_existing_in_csv
builder.add_conditional_edges(
    "db_lookup_and_split",
    route,
    {"continue": "enrich_existing_in_csv", "error_end": END}
)

# enrich_existing_in_csv → assign_uuids_to_new
builder.add_conditional_edges(
    "enrich_existing_in_csv",
    route,
    {"continue": "assign_uuids_to_new", "error_end": END}
)

# assign_uuids_to_new → update_seen_timestamps
builder.add_conditional_edges(
    "assign_uuids_to_new",
    route,
    {"continue": "update_seen_timestamps", "error_end": END}
)

# update_seen_timestamps → save_csv
builder.add_conditional_edges(
    "update_seen_timestamps",
    route,
    {"continue": "save_csv", "error_end": END}
)
builder.add_conditional_edges(
    "save_csv",
    route,
    {
        "continue": "call_criticality_agent",
        "error_end": END
    }
)

builder.add_edge(
    "call_criticality_agent",
    END
)

asset_lookup_graph = builder.compile()
print("Graph compiled ✓")

# %%
initial_state: AssetLookupState = {
    "working_csv":      "backend/normalized_output/working.csv",
    "status":           "running",
    "error":            None,
    "new_count":        0,
    "existing_count":   0,
}

final_state = asset_lookup_graph.invoke(initial_state)

print("\n=== Asset Lookup Agent — Final State ===")
print(json.dumps(final_state, indent=2))

if final_state["status"] == "done":
    print(f"\n✅ Success — {final_state['existing_count']} existing + {final_state['new_count']} new assets")
    print(f"   CSV enriched and saved → {final_state['working_csv']}")
    print("   Hand state to Agent 2 (Asset Criticality Agent)")
else:
    print(f"\n❌ Error: {final_state.get('error')}")


# ═══════════════════════════════════════════════════════════════════════════
# STANDALONE RUN
# ═══════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":

    initial_state: AssetLookupState = {
        "working_csv": "backend/normalized_output/working.csv",
        "status": "running",
        "error": None,
        "new_count": 0,
        "existing_count": 0,
    }

    final_state = asset_lookup_graph.invoke(initial_state)

    print("\n=== Asset Lookup Agent — Final State ===")
    print(json.dumps(final_state, indent=2))