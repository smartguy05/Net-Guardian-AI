"""Admin-only API endpoints for system configuration."""

from typing import Annotated, List, Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.auth import require_admin
from app.db.session import get_async_session
from app.models.retention_policy import RetentionPolicy
from app.models.user import User
from app.services.retention_service import RetentionService

router = APIRouter()


# Pydantic schemas for retention policies
class RetentionPolicyResponse(BaseModel):
    """Response model for a retention policy."""

    id: str
    table_name: str
    display_name: str
    description: Optional[str]
    retention_days: int
    enabled: bool
    last_run: Optional[str]
    deleted_count: int

    class Config:
        from_attributes = True


class RetentionPolicyUpdate(BaseModel):
    """Request model for updating a retention policy."""

    retention_days: Optional[int] = None
    enabled: Optional[bool] = None


class RetentionCleanupRequest(BaseModel):
    """Request model for running cleanup."""

    policy_id: Optional[str] = None
    dry_run: bool = True


class RetentionCleanupResult(BaseModel):
    """Result of a cleanup operation."""

    dry_run: bool
    policies_processed: int
    total_deleted: int
    details: List[dict]


class StorageStatsResponse(BaseModel):
    """Response model for storage statistics."""

    tables: List[dict]
    total_rows: int


def _policy_to_response(policy: RetentionPolicy) -> RetentionPolicyResponse:
    """Convert a policy model to response."""
    return RetentionPolicyResponse(
        id=str(policy.id),
        table_name=policy.table_name,
        display_name=policy.display_name,
        description=policy.description,
        retention_days=policy.retention_days,
        enabled=policy.enabled,
        last_run=policy.last_run.isoformat() if policy.last_run else None,
        deleted_count=policy.deleted_count,
    )


@router.get("/retention/policies", response_model=List[RetentionPolicyResponse])
async def get_retention_policies(
    session: Annotated[AsyncSession, Depends(get_async_session)],
    _admin: Annotated[User, Depends(require_admin)],
) -> List[RetentionPolicyResponse]:
    """Get all retention policies.

    Admin only.
    """
    service = RetentionService(session)

    # Initialize default policies if needed
    await service.initialize_default_policies()

    policies = await service.get_all_policies()
    return [_policy_to_response(p) for p in policies]


@router.get("/retention/policies/{policy_id}", response_model=RetentionPolicyResponse)
async def get_retention_policy(
    policy_id: str,
    session: Annotated[AsyncSession, Depends(get_async_session)],
    _admin: Annotated[User, Depends(require_admin)],
) -> RetentionPolicyResponse:
    """Get a specific retention policy.

    Admin only.
    """
    service = RetentionService(session)
    policy = await service.get_policy(policy_id)

    if not policy:
        raise HTTPException(status_code=404, detail="Policy not found")

    return _policy_to_response(policy)


@router.patch("/retention/policies/{policy_id}", response_model=RetentionPolicyResponse)
async def update_retention_policy(
    policy_id: str,
    update: RetentionPolicyUpdate,
    session: Annotated[AsyncSession, Depends(get_async_session)],
    _admin: Annotated[User, Depends(require_admin)],
) -> RetentionPolicyResponse:
    """Update a retention policy.

    Admin only.
    """
    if update.retention_days is not None and update.retention_days < 0:
        raise HTTPException(
            status_code=400, detail="retention_days must be 0 or greater"
        )

    service = RetentionService(session)
    policy = await service.update_policy(
        policy_id,
        retention_days=update.retention_days,
        enabled=update.enabled,
    )

    if not policy:
        raise HTTPException(status_code=404, detail="Policy not found")

    return _policy_to_response(policy)


@router.post("/retention/cleanup", response_model=RetentionCleanupResult)
async def run_retention_cleanup(
    request: RetentionCleanupRequest,
    session: Annotated[AsyncSession, Depends(get_async_session)],
    _admin: Annotated[User, Depends(require_admin)],
) -> RetentionCleanupResult:
    """Run data cleanup based on retention policies.

    Set dry_run=False to actually delete data.
    Admin only.
    """
    service = RetentionService(session)
    result = await service.run_cleanup(
        policy_id=request.policy_id,
        dry_run=request.dry_run,
    )
    return RetentionCleanupResult(**result)


@router.get("/retention/stats", response_model=StorageStatsResponse)
async def get_storage_stats(
    session: Annotated[AsyncSession, Depends(get_async_session)],
    _admin: Annotated[User, Depends(require_admin)],
) -> StorageStatsResponse:
    """Get storage statistics for retention-managed tables.

    Admin only.
    """
    service = RetentionService(session)

    # Initialize default policies if needed
    await service.initialize_default_policies()

    stats = await service.get_storage_stats()
    return StorageStatsResponse(**stats)
