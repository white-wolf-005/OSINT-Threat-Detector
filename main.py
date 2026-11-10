import json
import os
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any, AsyncGenerator

import aiohttp
import redis.asyncio as redis
import uvicorn
from a2wsgi import ASGIMiddleware
from dotenv import load_dotenv
from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel, Field
from sqlalchemy import desc, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from database import get_db, init_models
from engine import OSINTScanner
from models import ScanHistory
from src.core.logger import setup_logger

load_dotenv()

logger = setup_logger("osint.main")

API_HOST: str = os.getenv("API_HOST", "127.0.0.1")
API_PORT: int = int(os.getenv("API_PORT", "8000"))
REDIS_URL: str = os.getenv("REDIS_URL", "redis://localhost:6379/0")

BASE_DIR: Path = Path(__file__).resolve().parent
TEMPLATES_DIR: Path = BASE_DIR / "templates"
STATIC_DIR: Path = BASE_DIR / "static"

templates: Jinja2Templates = Jinja2Templates(directory=str(TEMPLATES_DIR))
scanner: OSINTScanner = OSINTScanner()


class AnalyzeRequest(BaseModel):
    target: str = Field(..., min_length=3, max_length=253, description="IP, Domain, or Email to analyze")


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    logger.info("OSINT Threat Intelligence Engine starting up")
    await init_models()
    app.state.client_session = aiohttp.ClientSession()
    app.state.redis = redis.from_url(REDIS_URL, decode_responses=True)
    yield
    logger.info("OSINT Threat Intelligence Engine shutting down")
    await app.state.client_session.close()
    await app.state.redis.aclose()


app: FastAPI = FastAPI(
    title="OSINT Threat Intelligence Engine",
    version="2.0.0",
    lifespan=lifespan,
)

app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")
wsgi_app: ASGIMiddleware = ASGIMiddleware(app)


@app.get("/", response_class=HTMLResponse)
async def read_root(request: Request) -> HTMLResponse:
    try:
        return templates.TemplateResponse(
            request=request,
            name="index.html",
        )
    except Exception:
        logger.error("Failed to render root template", exc_info=True)
        raise HTTPException(status_code=500, detail="Template rendering error")


@app.get("/api/health")
async def health_check(request: Request) -> dict[str, Any]:
    redis_online: bool = False
    try:
        redis_client: redis.Redis = request.app.state.redis
        await redis_client.ping()
        redis_online = True
    except Exception:
        redis_online = False

    return {
        "status": "healthy",
        "version": "2.0.0",
        "redis_connected": redis_online,
    }


@app.post("/api/analyze")
async def analyze_target(
    payload: AnalyzeRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
) -> dict[str, Any]:
    clean_target: str = payload.target.strip().lower()
    logger.info(f"Target received for reconnaissance: {clean_target}")

    session: aiohttp.ClientSession = request.app.state.client_session
    redis_client: redis.Redis = request.app.state.redis
    cache_key: str = f"osint_cache:v2:{clean_target}"

    analysis_result: dict[str, Any] | None = None
    is_cached: bool = False

    try:
        cached_data: str | None = await redis_client.get(cache_key)
        if cached_data:
            logger.info(f"Redis cache hit for target: {clean_target}")
            analysis_result = json.loads(cached_data)
            is_cached = True
    except Exception:
        logger.warning("Redis cache read unavailable, proceeding with live scan")

    if analysis_result is None:
        try:
            analysis_result = await scanner.analyze(session, clean_target)
        except Exception:
            logger.error(f"Scanner execution failed for target: {clean_target}", exc_info=True)
            raise HTTPException(status_code=500, detail="Intelligence scan failed")

        try:
            await redis_client.set(cache_key, json.dumps(analysis_result), ex=3600)
        except Exception:
            logger.warning("Could not persist scan result to Redis cache")

    try:
        db_record: ScanHistory = ScanHistory(
            target=str(analysis_result["target"]),
            target_type=str(analysis_result["type"]),
            threat_score=int(analysis_result["threat_score"]),
            results_payload=list(analysis_result["results"]),
        )
        db.add(db_record)
    except Exception:
        logger.error("Failed to record audit entry into database", exc_info=True)

    return {
        "status": "success",
        "data": analysis_result,
        "cached": is_cached,
    }


@app.get("/api/history")
async def get_history(
    limit: int = 20,
    target_type: str | None = None,
    db: AsyncSession = Depends(get_db),
) -> dict[str, Any]:
    try:
        safe_limit: int = max(1, min(limit, 100))
        stmt = select(ScanHistory).order_by(desc(ScanHistory.created_at)).limit(safe_limit)
        if target_type and target_type in {"IPv4", "domain", "email"}:
            stmt = (
                select(ScanHistory)
                .where(ScanHistory.target_type == target_type)
                .order_by(desc(ScanHistory.created_at))
                .limit(safe_limit)
            )

        result = await db.execute(stmt)
        records: list[ScanHistory] = list(result.scalars().all())

        history_data: list[dict[str, Any]] = [
            {
                "id": record.id,
                "target": record.target,
                "type": record.target_type,
                "threat_score": record.threat_score,
                "created_at": record.created_at.isoformat(),
            }
            for record in records
        ]
        return {"status": "success", "data": history_data}
    except Exception:
        logger.error("Failed to retrieve scan history", exc_info=True)
        raise HTTPException(status_code=500, detail="Could not retrieve scan history")


@app.get("/api/stats")
async def get_stats(db: AsyncSession = Depends(get_db)) -> dict[str, Any]:
    try:
        total_stmt = select(func.count(ScanHistory.id))
        avg_stmt = select(func.avg(ScanHistory.threat_score))
        high_risk_stmt = select(func.count(ScanHistory.id)).where(ScanHistory.threat_score >= 45)

        total_res = await db.execute(total_stmt)
        avg_res = await db.execute(avg_stmt)
        high_risk_res = await db.execute(high_risk_stmt)

        total_scans: int = int(total_res.scalar() or 0)
        avg_score: float = round(float(avg_res.scalar() or 0.0), 1)
        high_risk_count: int = int(high_risk_res.scalar() or 0)

        return {
            "status": "success",
            "data": {
                "total_scans": total_scans,
                "average_threat_score": avg_score,
                "high_risk_detections": high_risk_count,
            },
        }
    except Exception:
        logger.error("Failed to calculate telemetry stats", exc_info=True)
        raise HTTPException(status_code=500, detail="Stats calculation failed")


if __name__ == "__main__":
    try:
        uvicorn.run(app, host=API_HOST, port=API_PORT, log_config=None)
    except Exception:
        logger.critical("Uvicorn server crashed unexpectedly", exc_info=True)