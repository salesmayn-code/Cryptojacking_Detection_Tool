"""
FastAPI Backend - Main Application
"""
import asyncio
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from datetime import datetime
import os
import sys
from dotenv import load_dotenv

load_dotenv()

_BACKEND_DIR = os.path.dirname(os.path.abspath(__file__))
_PROJECT_ROOT = os.path.dirname(_BACKEND_DIR)
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)

app = FastAPI(
    title="Cryptojacking Detection API",
    description="Backend API for real-time cryptojacking detection system",
    version="1.0.0"
)

_offline_task = None

# CORS Configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.on_event("startup")
async def on_startup():
    """Initialize database tables on first run"""
    from backend.database import init_db
    from backend.database import SessionLocal
    from backend.routes.systems import refresh_all_system_statuses

    init_db()

    async def _offline_sweeper():
        while True:
            db = SessionLocal()
            try:
                refresh_all_system_statuses(db)
            except Exception:
                db.rollback()
            finally:
                db.close()
            await asyncio.sleep(int(os.getenv("SYSTEM_STATUS_SWEEP_SECONDS", "10")))

    global _offline_task
    _offline_task = asyncio.create_task(_offline_sweeper())


@app.on_event("shutdown")
async def on_shutdown():
    """Stop background tasks on shutdown."""
    global _offline_task
    if _offline_task:
        _offline_task.cancel()
        try:
            await _offline_task
        except Exception:
            pass


@app.get("/")
async def root():
    return {
        "message": "Cryptojacking Detection API",
        "version": "1.0.0",
        "status": "running"
    }

@app.get("/health")
async def health_check():
    return {
        "status": "healthy",
        "timestamp": datetime.now().isoformat()
    }


# Import route modules
if _BACKEND_DIR not in sys.path:
    sys.path.insert(0, _BACKEND_DIR)

from backend.routes import auth, systems, metrics, alerts, reports, agent, audit, notifications, containment

app.include_router(auth.router, prefix="/api/auth", tags=["Authentication"])
app.include_router(systems.router, prefix="/api/systems", tags=["Systems"])
app.include_router(metrics.router, prefix="/api/metrics", tags=["Metrics"])
app.include_router(alerts.router, prefix="/api/alerts", tags=["Alerts"])
app.include_router(reports.router, prefix="/api/reports", tags=["Reports"])
app.include_router(agent.router, prefix="/api/agent", tags=["Agent"])
app.include_router(audit.router, prefix="/api/admin", tags=["Admin"])
app.include_router(notifications.router, prefix="/api/notifications", tags=["Notifications"])
app.include_router(containment.router, prefix="/api", tags=["Containment"])


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "backend.main:app",
        host=os.getenv("API_HOST", "0.0.0.0"),
        port=int(os.getenv("API_PORT", 8000)),
        reload=os.getenv("DEBUG", "True") == "True"
    )
