import aiosqlite
import asyncpg
from pathlib import Path
from datetime import datetime, timedelta
from .utils import printS
import os


async def migrate_sqlite_to_psql(sqlite_path: str, psql_dsn: str) -> dict:
    """
    Migrates telemetry data from local SQLite to remote PostgreSQL.
    Returns a dictionary with status and details.
    """
    try:
        # 1. Read all rows from SQLite (9 columns)
        async with aiosqlite.connect(sqlite_path) as sqlite_db:
            async with sqlite_db.execute("""
                SELECT asset_id, cve_id, score, resolved, cost, token, 
                       start_time, end_time, time_taken
                FROM vulnerabilities
            """) as cursor:
                rows = await cursor.fetchall()

        if not rows:
            return {"status": "success", "message": "No records found in SQLite to migrate.", "migrated_count": 0}
        
        await printS("step 1 done!")
        
        # 2. Transform types for strict PostgreSQL compatibility
        records_to_insert = []
        for row in rows:
            (asset_id, cve_id, score, resolved, cost, token, 
             start_time, end_time, time_taken) = row
            
            # Convert SQLite INTEGER boolean (0/1) to Python bool
            resolved_bool = bool(resolved) if resolved is not None else False
            
            # Convert ISO8601 string timestamps to datetime objects
            start_dt = datetime.fromisoformat(start_time) if start_time else None
            end_dt = datetime.fromisoformat(end_time) if end_time else None
            
            # Convert decimal seconds to a Python timedelta for PostgreSQL's INTERVAL column
            time_taken_interval = timedelta(seconds=time_taken) if time_taken is not None else None
            
            records_to_insert.append((
                asset_id, cve_id, score, resolved_bool, cost, token, 
                start_dt, end_dt, time_taken_interval
            ))

        # 3. Connect to PSQL and execute bulk Upsert
        conn = await asyncpg.connect(psql_dsn)
        await printS("Working here..........")
        try:
            query = """
                INSERT INTO vulnerabilities_history (
                    asset_id, cve_id, score, resolved, cost, token, 
                    start_time, end_time, time_taken
                ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
                ON CONFLICT (asset_id) DO UPDATE SET
                    cve_id = EXCLUDED.cve_id,       
                    score = EXCLUDED.score,
                    resolved = EXCLUDED.resolved,
                    cost = EXCLUDED.cost,
                    token = EXCLUDED.token,
                    start_time = EXCLUDED.start_time,
                    end_time = EXCLUDED.end_time,
                    time_taken = EXCLUDED.time_taken;
            """
            await conn.executemany(query, records_to_insert)
            return {
                "status": "success", 
                "message": f"Successfully migrated {len(records_to_insert)} records.", 
                "migrated_count": len(records_to_insert)
            }
            
        finally:
            await printS("step 3 done!")
            await conn.close()

    except Exception as e:
        await printS("Migration Error!")
        return {"status": "error", "message": str(e), "migrated_count": 0}
    
    
if __name__ == "__main__":
    import asyncio
    
    # Path logic ensuring it finds the DB no matter where you run the command from
    BASE_DIR = Path(__file__).resolve().parent.parent 
    SQLITE_PATH = str(BASE_DIR / "state_db.sqlite")
    
    # Replace with your actual PostgreSQL connection string
    PSQL_DSN = f"postgresql://{db_user}:{db_password}@{db_host}:{db_port}/{db_name}";
    
    print(f"[SYSTEM] Looking for SQLite DB at: {SQLITE_PATH}")
    print("[SYSTEM] Running standalone database migration...")
    
    # Run the async function
    result = asyncio.run(migrate_sqlite_to_psql(SQLITE_PATH, PSQL_DSN))
    
    # Print the outcome
    if result["status"] == "success":
        print(f"✅ {result['message']}")
    else:
        print(f"❌ Migration failed: {result['message']}")