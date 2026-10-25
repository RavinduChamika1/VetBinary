"""
models.py — SQLAlchemy ORM models.
All timestamps are UTC, stored as ISO-8601 strings for SQLite compatibility.
"""
import datetime
from sqlalchemy import String, Integer, Float, Boolean, Text, JSON
from sqlalchemy.orm import Mapped, mapped_column
from database import Base


def _now() -> str:
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


class Scan(Base):
    __tablename__ = "scans"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    created_at: Mapped[str] = mapped_column(String(40), default=_now)
    updated_at: Mapped[str] = mapped_column(String(40), default=_now, onupdate=_now)

    # Upload metadata
    original_filename: Mapped[str] = mapped_column(String(512))
    sha256: Mapped[str] = mapped_column(String(64), index=True)
    file_size_bytes: Mapped[int] = mapped_column(Integer)
    purpose_comment: Mapped[str] = mapped_column(Text)
    deployment_scope: Mapped[str] = mapped_column(String(512), default="")
    allow_public_sandbox: Mapped[bool] = mapped_column(Boolean, default=False)

    # Lifecycle state
    status: Mapped[str] = mapped_column(String(32), default="pending")
    # pending | running | completed | error
    current_step: Mapped[str] = mapped_column(Text, default="")
    error_message: Mapped[str] = mapped_column(Text, default="")

    # Final report (stored as JSON blob)
    report_json: Mapped[str] = mapped_column(Text, default="")

    # Convenience columns for fast querying
    verdict: Mapped[str] = mapped_column(String(32), default="")
    risk_score: Mapped[float] = mapped_column(Float, default=0.0)


class ApiCallLog(Base):
    """Immutable log of every external API call made during a scan."""
    __tablename__ = "api_call_logs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    scan_id: Mapped[int] = mapped_column(Integer, index=True)
    source: Mapped[str] = mapped_column(String(64))          # e.g. "VirusTotal"
    endpoint: Mapped[str] = mapped_column(String(512))
    called_at: Mapped[str] = mapped_column(String(40))
    http_status: Mapped[int] = mapped_column(Integer, default=0)
    outcome: Mapped[str] = mapped_column(String(32))          # ok | error | skipped
    reason: Mapped[str] = mapped_column(Text, default="")     # skip reason or error msg
    response_summary: Mapped[str] = mapped_column(Text, default="")


class MonthlyQuota(Base):
    """Tracks how many submissions have been made to each sandbox per calendar month."""
    __tablename__ = "monthly_quota"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    service: Mapped[str] = mapped_column(String(64), index=True)
    year_month: Mapped[str] = mapped_column(String(7), index=True)  # "YYYY-MM"
    count: Mapped[int] = mapped_column(Integer, default=0)
