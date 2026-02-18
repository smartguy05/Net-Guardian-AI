"""Gamification API endpoints."""

from typing import Annotated, Any
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.auth import get_current_user
from app.config import settings
from app.db.session import get_async_session
from app.models.gamification import AchievementCategory
from app.models.user import User
from app.services.gamification_service import get_gamification_service

router = APIRouter()


# ==================== SCHEMAS ====================


class UserStatsResponse(BaseModel):
    """User gamification stats response."""

    user_id: str
    total_points: int
    level: int
    title: str
    current_xp: int
    xp_to_next_level: int
    xp_progress_percent: float
    counters: dict[str, int]
    streak: dict[str, int]
    leaderboard_opt_in: bool
    last_activity: str | None


class AchievementResponse(BaseModel):
    """Achievement response."""

    id: str
    name: str
    description: str
    category: str
    rarity: str
    icon: str
    points: int
    hidden: bool
    unlocked: bool
    earned_at: str | None = None
    context: dict[str, Any] | None = None


class AchievementListResponse(BaseModel):
    """List of achievements response."""

    items: list[AchievementResponse]
    total: int
    unlocked_count: int


class LeaderboardEntryResponse(BaseModel):
    """Leaderboard entry response."""

    rank: int
    user_id: str
    username: str | None = None
    total_points: int
    level: int
    title: str
    alerts_resolved: int
    current_streak: int


class LeaderboardResponse(BaseModel):
    """Leaderboard response."""

    period: str
    entries: list[LeaderboardEntryResponse]
    user_rank: int | None = None


class ChallengeResponse(BaseModel):
    """Challenge response."""

    id: str
    name: str
    description: str
    challenge_type: str
    start_date: str
    end_date: str
    requirements: dict[str, Any]
    reward_points: int
    reward_achievement_id: str | None
    progress: dict[str, Any] | None = None
    completed: bool = False
    completed_at: str | None = None


class ChallengeListResponse(BaseModel):
    """List of challenges response."""

    items: list[ChallengeResponse]
    total: int


class LevelInfoResponse(BaseModel):
    """Level progression info response."""

    levels: list[dict[str, Any]]
    current_level: int
    current_xp: int
    xp_to_next_level: int


class OptInResponse(BaseModel):
    """Leaderboard opt-in response."""

    leaderboard_opt_in: bool


# ==================== ENDPOINTS ====================


@router.get("/stats", response_model=UserStatsResponse)
async def get_my_stats(
    current_user: Annotated[User, Depends(get_current_user)],
) -> UserStatsResponse:
    """Get current user's gamification stats."""
    if not settings.gamification_enabled:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Gamification is disabled",
        )

    service = get_gamification_service()
    stats = await service.get_user_stats(current_user.id)
    return UserStatsResponse(**stats)


@router.get("/stats/{user_id}", response_model=UserStatsResponse)
async def get_user_stats(
    user_id: UUID,
    _current_user: Annotated[User, Depends(get_current_user)],
) -> UserStatsResponse:
    """Get a specific user's gamification stats."""
    if not settings.gamification_enabled:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Gamification is disabled",
        )

    service = get_gamification_service()
    stats = await service.get_user_stats(user_id)
    return UserStatsResponse(**stats)


@router.get("/achievements", response_model=AchievementListResponse)
async def list_achievements(
    current_user: Annotated[User, Depends(get_current_user)],
    category: AchievementCategory | None = None,
    include_hidden: bool = Query(False, description="Include hidden achievements"),
) -> AchievementListResponse:
    """List all achievements with unlock status for current user."""
    if not settings.gamification_enabled:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Gamification is disabled",
        )

    service = get_gamification_service()
    achievements = await service.get_all_achievements(
        user_id=current_user.id,
        category=category,
        include_hidden=include_hidden,
    )

    unlocked_count = sum(1 for a in achievements if a.get("unlocked", False))

    return AchievementListResponse(
        items=[AchievementResponse(**a) for a in achievements],
        total=len(achievements),
        unlocked_count=unlocked_count,
    )


@router.get("/achievements/recent", response_model=list[AchievementResponse])
async def get_recent_achievements(
    current_user: Annotated[User, Depends(get_current_user)],
    limit: int = Query(5, ge=1, le=20),
) -> list[AchievementResponse]:
    """Get recently unlocked achievements for current user."""
    if not settings.gamification_enabled:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Gamification is disabled",
        )

    service = get_gamification_service()
    achievements = await service.get_recent_achievements(
        user_id=current_user.id,
        limit=limit,
    )

    return [
        AchievementResponse(
            id=a["id"],
            name=a["name"],
            description=a["description"],
            category=a["category"],
            rarity=a["rarity"],
            icon=a["icon"],
            points=a["points"],
            hidden=False,
            unlocked=True,
            earned_at=a["earned_at"],
        )
        for a in achievements
    ]


@router.get("/leaderboard", response_model=LeaderboardResponse)
async def get_leaderboard(
    current_user: Annotated[User, Depends(get_current_user)],
    session: Annotated[AsyncSession, Depends(get_async_session)],
    period: str = Query("all_time", regex="^(all_time|weekly|monthly)$"),
    limit: int = Query(10, ge=1, le=100),
) -> LeaderboardResponse:
    """Get the leaderboard."""
    if not settings.gamification_enabled:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Gamification is disabled",
        )

    if not settings.gamification_leaderboard_enabled:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Leaderboard is disabled",
        )

    service = get_gamification_service()
    entries = await service.get_leaderboard(period=period, limit=limit)

    # Get usernames for entries
    from sqlalchemy import select

    from app.models.user import User as UserModel

    user_ids = [UUID(e["user_id"]) for e in entries]
    if user_ids:
        result = await session.execute(
            select(UserModel.id, UserModel.username).where(UserModel.id.in_(user_ids))
        )
        username_map = {str(row[0]): row[1] for row in result.all()}
    else:
        username_map = {}

    # Find current user's rank
    user_rank = None
    for entry in entries:
        if entry["user_id"] == str(current_user.id):
            user_rank = entry["rank"]
            break

    return LeaderboardResponse(
        period=period,
        entries=[
            LeaderboardEntryResponse(
                rank=e["rank"],
                user_id=e["user_id"],
                username=username_map.get(e["user_id"]),
                total_points=e["total_points"],
                level=e["level"],
                title=e["title"],
                alerts_resolved=e["alerts_resolved"],
                current_streak=e["current_streak"],
            )
            for e in entries
        ],
        user_rank=user_rank,
    )


@router.post("/leaderboard/opt-in", response_model=OptInResponse)
async def toggle_leaderboard_opt_in(
    current_user: Annotated[User, Depends(get_current_user)],
) -> OptInResponse:
    """Toggle leaderboard visibility for current user."""
    if not settings.gamification_enabled:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Gamification is disabled",
        )

    service = get_gamification_service()
    new_status = await service.toggle_leaderboard_opt_in(current_user.id)

    return OptInResponse(leaderboard_opt_in=new_status)


@router.get("/challenges", response_model=ChallengeListResponse)
async def list_challenges(
    current_user: Annotated[User, Depends(get_current_user)],
) -> ChallengeListResponse:
    """List active challenges with progress for current user."""
    if not settings.gamification_enabled:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Gamification is disabled",
        )

    service = get_gamification_service()
    challenges = await service.get_active_challenges(user_id=current_user.id)

    return ChallengeListResponse(
        items=[ChallengeResponse(**c) for c in challenges],
        total=len(challenges),
    )


@router.get("/levels", response_model=LevelInfoResponse)
async def get_levels_info(
    current_user: Annotated[User, Depends(get_current_user)],
) -> LevelInfoResponse:
    """Get level progression information."""
    if not settings.gamification_enabled:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Gamification is disabled",
        )

    from app.data.achievements import LEVELS

    service = get_gamification_service()
    stats = await service.get_user_stats(current_user.id)

    return LevelInfoResponse(
        levels=LEVELS,
        current_level=stats["level"],
        current_xp=stats["current_xp"],
        xp_to_next_level=stats["xp_to_next_level"],
    )


@router.post("/sync-achievements")
async def sync_achievements(
    current_user: Annotated[User, Depends(get_current_user)],
) -> dict[str, Any]:
    """Sync achievement definitions to database (admin only)."""
    from app.core.security import UserRole

    if current_user.role != UserRole.ADMIN:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin access required",
        )

    service = get_gamification_service()
    count = await service.sync_achievements()

    return {"synced": count, "message": f"Synced {count} achievements"}
