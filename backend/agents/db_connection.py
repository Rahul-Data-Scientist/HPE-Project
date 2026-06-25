import os
from dotenv import load_dotenv
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from sqlalchemy.orm import sessionmaker

# Locate and load the environment variables from .env
load_dotenv()

# Retrieve database connection variables
db_user = os.getenv("DB_USER")
db_password = os.getenv("DB_PASSWORD")
db_host = os.getenv("DB_HOST")
db_port = os.getenv("DB_PORT", "5432")
db_name = os.getenv("DB_NAME", "postgres")

if not all([db_user, db_password, db_host, db_name]):
    raise ValueError("Database credentials (DB_USER, DB_PASSWORD, DB_HOST, DB_NAME) must be set in the environment.")

# Clean up passwords or values if they have trailing/leading whitespace or quotes
db_user = db_user.strip().strip('"').strip("'")
db_password = db_password.strip().strip('"').strip("'")
db_host = db_host.strip().strip('"').strip("'")
db_port = db_port.strip().strip('"').strip("'")
db_name = db_name.strip().strip('"').strip("'")

# Create connection URL using asyncpg driver instead of psycopg2
connection_url = f"postgresql+asyncpg://{db_user}:{db_password}@{db_host}:{db_port}/{db_name}"

# Initialize the SQLAlchemy async engine
# pool_pre_ping checks the connection before executing queries to ensure RDS didn't close idle connections
engine = create_async_engine(connection_url, pool_pre_ping=True)

# Create async session factory
SessionLocal = sessionmaker(
    autocommit=False, 
    autoflush=False, 
    bind=engine, 
    class_=AsyncSession,
    expire_on_commit=False
)

async def get_async_db_session():
    """
    Creates and returns a new SQLAlchemy async session.
    Ensure to await session.close() after use.
    """
    return SessionLocal()