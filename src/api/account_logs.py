"""Authenticated, paginated account operation audit API."""
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, ConfigDict, Field
from typing import Literal

from ..core.account_audit import OPERATIONS, SOURCES, STATUSES, audit_account_operation
from ..core.database import Database
from .admin import verify_admin_token


router = APIRouter()
db: Optional[Database] = None


def set_database(database: Database):
    global db
    db = database


def _database():
    if db is None:
        raise HTTPException(status_code=503, detail="Account logs unavailable")
    return db


class ExportLogDetails(BaseModel):
    model_config = ConfigDict(extra="forbid")
    count: int = Field(ge=0, le=1000000, strict=True)


class ExportLogEvent(BaseModel):
    model_config = ConfigDict(extra="forbid")
    operation: Literal["export"]
    status: Literal["success"]
    reason: Literal["export_complete"]
    details: ExportLogDetails


@router.post("/api/account-logs/events")
async def record_export_event(event: ExportLogEvent, _admin: str = Depends(verify_admin_token)):
    log_id = await audit_account_operation(
        _database(), operation="export", status="success", reason="export_complete",
        stage="export", source="admin", details=event.details.model_dump(),
    )
    if log_id is None:
        raise HTTPException(status_code=503, detail="Account logs unavailable")
    return {"success": True, "id": log_id}


@router.get("/api/account-logs")
async def list_account_logs(
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=100),
    token_id: Optional[int] = Query(None, ge=1),
    operation: Optional[str] = None,
    status: Optional[str] = None,
    source: Optional[str] = None,
    q: Optional[str] = Query(None, max_length=254),
    _admin: str = Depends(verify_admin_token),
):
    for value, allowed in ((operation, OPERATIONS), (status, STATUSES), (source, SOURCES)):
        if value and value not in allowed:
            raise HTTPException(status_code=400, detail="Invalid account log filter")
    try:
        return await _database().get_account_operation_logs(
            page=page, page_size=page_size, token_id=token_id,
            operation=operation, status=status, source=source, q=q,
        )
    except HTTPException:
        raise
    except Exception:
        raise HTTPException(status_code=503, detail="Account logs unavailable") from None


@router.get("/api/account-logs/{log_id}")
async def get_account_log(log_id: int, _admin: str = Depends(verify_admin_token)):
    try:
        result = await _database().get_account_operation_log(log_id)
    except HTTPException:
        raise
    except Exception:
        raise HTTPException(status_code=503, detail="Account logs unavailable") from None
    if result is None:
        raise HTTPException(status_code=404, detail="Account log not found")
    return result
