"""
utils/quota.py — read/write monthly quota for sandbox services.
"""
from __future__ import annotations
import datetime
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from models import MonthlyQuota


def _current_year_month() -> str:
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m")


async def get_monthly_usage(db: AsyncSession, service: str) -> int:
    ym = _current_year_month()
    result = await db.execute(
        select(MonthlyQuota).where(
            MonthlyQuota.service == service,
            MonthlyQuota.year_month == ym,
        )
    )
    row = result.scalar_one_or_none()
    return row.count if row else 0


async def increment_monthly_usage(db: AsyncSession, service: str) -> int:
    ym = _current_year_month()
    result = await db.execute(
        select(MonthlyQuota).where(
            MonthlyQuota.service == service,
            MonthlyQuota.year_month == ym,
        )
    )
    row = result.scalar_one_or_none()
    if row is None:
        row = MonthlyQuota(service=service, year_month=ym, count=1)
        db.add(row)
    else:
        row.count += 1
    await db.commit()
    return row.count
