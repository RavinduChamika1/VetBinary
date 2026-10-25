"""
utils/logging_utils.py — helpers for recording every external API call.
"""
from __future__ import annotations
import datetime
from typing import Optional
from sqlalchemy.ext.asyncio import AsyncSession
from models import ApiCallLog


def utc_now() -> str:
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


async def log_call(
    db: AsyncSession,
    scan_id: int,
    source: str,
    endpoint: str,
    http_status: int,
    outcome: str,          # ok | error | skipped
    reason: str = "",
    response_summary: str = "",
) -> ApiCallLog:
    entry = ApiCallLog(
        scan_id=scan_id,
        source=source,
        endpoint=endpoint,
        called_at=utc_now(),
        http_status=http_status,
        outcome=outcome,
        reason=reason,
        response_summary=response_summary,
    )
    if db is not None:
        db.add(entry)
        await db.commit()
        await db.refresh(entry)
    return entry


def call_log_to_dict(entry: ApiCallLog) -> dict:
    return {
        "source": entry.source,
        "endpoint": entry.endpoint,
        "called_at": entry.called_at,
        "http_status": entry.http_status,
        "outcome": entry.outcome,
        "reason": entry.reason,
        "response_summary": entry.response_summary,
    }
