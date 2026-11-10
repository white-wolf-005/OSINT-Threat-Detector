import os
from typing import Any, AsyncGenerator

from dotenv import load_dotenv
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from models import Base
from src.core.logger import setup_logger

load_dotenv()

logger = setup_logger("osint.database")

FALLBACK_SQLITE_URL: str = "sqlite+aiosqlite:///./osint.db"
DATABASE_URL: str = os.getenv("DATABASE_URL", FALLBACK_SQLITE_URL)


def _build_engine(db_url: str) -> AsyncEngine:
    engine_kwargs: dict[str, Any] = {"echo": False}
    if db_url.startswith("sqlite"):
        engine_kwargs["connect_args"] = {"check_same_thread": False}
    else:
        engine_kwargs["pool_size"] = 20
        engine_kwargs["max_overflow"] = 10
        engine_kwargs["pool_timeout"] = 30
        engine_kwargs["pool_recycle"] = 1800
    return create_async_engine(db_url, **engine_kwargs)


engine: AsyncEngine = _build_engine(DATABASE_URL)

AsyncSessionLocal: async_sessionmaker[AsyncSession] = async_sessionmaker(
    bind=engine,
    class_=AsyncSession,
    expire_on_commit=False,
)


async def init_models() -> None:
    global engine, AsyncSessionLocal
    try:
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
        logger.info("Database schema initialized successfully on primary DATABASE_URL")
    except Exception:
        if not DATABASE_URL.startswith("sqlite"):
            logger.warning(
                "Primary PostgreSQL database is unreachable. Falling back to local SQLite database (osint.db)"
            )
            await engine.dispose()
            engine = _build_engine(FALLBACK_SQLITE_URL)
            AsyncSessionLocal = async_sessionmaker(
                bind=engine,
                class_=AsyncSession,
                expire_on_commit=False,
            )
            async with engine.begin() as conn:
                await conn.run_sync(Base.metadata.create_all)
            logger.info("Local SQLite fallback database initialized successfully")
        else:
            logger.critical("Failed to initialize database models", exc_info=True)
            raise


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    async with AsyncSessionLocal() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            logger.error("Database session transaction rollback triggered", exc_info=True)
            raise
        finally:
            await session.close()