"""
main.py — VetBinary FastAPI application entry point.
"""
from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from database import init_db
from routers.scan import router as scan_router
from routers.report import router as report_router


@asynccontextmanager
async def lifespan(app: FastAPI):
    await init_db()
    yield


app = FastAPI(
    title="VetBinary API",
    version="1.0.0",
    description=(
        "Pre-deployment file vetting platform. "
        "Checks VirusTotal, sandboxes, NVD, OSV.dev, and CISA KEV. "
        "Never executes files locally."
    ),
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # tightened in production via env
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(scan_router)
app.include_router(report_router)


@app.get("/health")
async def health():
    return {"status": "ok", "service": "VetBinary"}


@app.get("/")
async def root():
    return {
        "service": "VetBinary",
        "version": "1.0.0",
        "docs": "/docs",
        "disclaimer": (
            "VetBinary supports a deployment decision and does not replace "
            "enterprise endpoint security controls."
        ),
    }
