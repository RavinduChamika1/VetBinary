"""
database.py — async SQLAlchemy engine and session factory.
"""
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncSession
from sqlalchemy.orm import DeclarativeBase
from config import DATABASE_URL

# Convert sqlite:// → sqlite+aiosqlite:// if needed
_url = DATABASE_URL
if _url.startswith("sqlite://") and "aiosqlite" not in _url:
    _url = _url.replace("sqlite://", "sqlite+aiosqlite://", 1)

engine = create_async_engine(_url, echo=False, future=True)
AsyncSessionLocal = async_sessionmaker(engine, expire_on_commit=False, class_=AsyncSession)


class Base(DeclarativeBase):
    pass


async def init_db() -> None:
    """Create all tables if they don't exist."""
    async with engine.begin() as conn:
        from models import Scan, ApiCallLog, MonthlyQuota  # noqa: F401
        await conn.run_sync(Base.metadata.create_all)


async def get_db():
    async with AsyncSessionLocal() as session:
        yield session
