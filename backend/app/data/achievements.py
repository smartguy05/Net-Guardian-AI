"""Achievement definitions for gamification system."""

from typing import Any, TypedDict

from app.models.gamification import AchievementCategory, AchievementRarity


class LevelInfo(TypedDict):
    """Type for level definition entries."""

    level: int
    xp: int
    title: str

# Point values for different actions
POINT_VALUES = {
    # Alert resolutions by severity
    "alert_resolve_info": 5,
    "alert_resolve_low": 10,
    "alert_resolve_medium": 20,
    "alert_resolve_high": 40,
    "alert_resolve_critical": 100,
    # Other actions
    "anomaly_confirm": 25,
    "anomaly_false_positive": 5,
    "device_quarantine": 30,
    "investigation_complete": 50,
    "challenge_daily": 50,
    "challenge_weekly": 200,
    "challenge_monthly": 500,
}

# XP required for each level
LEVELS: list[LevelInfo] = [
    {"level": 1, "xp": 0, "title": "Novice Guardian"},
    {"level": 2, "xp": 100, "title": "Novice Guardian"},
    {"level": 3, "xp": 250, "title": "Novice Guardian"},
    {"level": 4, "xp": 450, "title": "Novice Guardian"},
    {"level": 5, "xp": 700, "title": "Alert Watcher"},
    {"level": 6, "xp": 1000, "title": "Alert Watcher"},
    {"level": 7, "xp": 1400, "title": "Alert Watcher"},
    {"level": 8, "xp": 1900, "title": "Alert Watcher"},
    {"level": 9, "xp": 2500, "title": "Alert Watcher"},
    {"level": 10, "xp": 3200, "title": "Threat Hunter"},
    {"level": 11, "xp": 4000, "title": "Threat Hunter"},
    {"level": 12, "xp": 5000, "title": "Threat Hunter"},
    {"level": 13, "xp": 6200, "title": "Threat Hunter"},
    {"level": 14, "xp": 7600, "title": "Threat Hunter"},
    {"level": 15, "xp": 9200, "title": "Security Analyst"},
    {"level": 16, "xp": 11000, "title": "Security Analyst"},
    {"level": 17, "xp": 13000, "title": "Security Analyst"},
    {"level": 18, "xp": 15500, "title": "Security Analyst"},
    {"level": 19, "xp": 18500, "title": "Security Analyst"},
    {"level": 20, "xp": 22000, "title": "Cyber Defender"},
    {"level": 21, "xp": 26000, "title": "Cyber Defender"},
    {"level": 22, "xp": 30500, "title": "Cyber Defender"},
    {"level": 23, "xp": 35500, "title": "Cyber Defender"},
    {"level": 24, "xp": 41000, "title": "Cyber Defender"},
    {"level": 25, "xp": 47000, "title": "Elite Guardian"},
    {"level": 26, "xp": 54000, "title": "Elite Guardian"},
    {"level": 27, "xp": 62000, "title": "Elite Guardian"},
    {"level": 28, "xp": 71000, "title": "Elite Guardian"},
    {"level": 29, "xp": 81000, "title": "Elite Guardian"},
    {"level": 30, "xp": 92000, "title": "Master Sentinel"},
    {"level": 35, "xp": 150000, "title": "Master Sentinel"},
    {"level": 40, "xp": 250000, "title": "Network Oracle"},
    {"level": 45, "xp": 400000, "title": "Network Oracle"},
    {"level": 50, "xp": 600000, "title": "Legendary Guardian"},
]

# Achievement definitions
ACHIEVEMENTS = {
    # ==================== ALERT ACHIEVEMENTS ====================
    "first_blood": {
        "name": "First Blood",
        "description": "Resolve your first security alert",
        "category": AchievementCategory.ALERTS,
        "rarity": AchievementRarity.COMMON,
        "icon": "shield-check",
        "points": 10,
        "requirements": {"alerts_resolved": 1},
        "hidden": False,
    },
    "alert_responder": {
        "name": "Alert Responder",
        "description": "Resolve 10 security alerts",
        "category": AchievementCategory.ALERTS,
        "rarity": AchievementRarity.COMMON,
        "icon": "bell",
        "points": 50,
        "requirements": {"alerts_resolved": 10},
        "hidden": False,
    },
    "alert_hunter": {
        "name": "Alert Hunter",
        "description": "Resolve 100 security alerts",
        "category": AchievementCategory.ALERTS,
        "rarity": AchievementRarity.RARE,
        "icon": "target",
        "points": 500,
        "requirements": {"alerts_resolved": 100},
        "hidden": False,
    },
    "alert_master": {
        "name": "Alert Master",
        "description": "Resolve 500 security alerts",
        "category": AchievementCategory.ALERTS,
        "rarity": AchievementRarity.LEGENDARY,
        "icon": "crown",
        "points": 2000,
        "requirements": {"alerts_resolved": 500},
        "hidden": False,
    },
    "critical_responder": {
        "name": "Critical Responder",
        "description": "Resolve 10 critical severity alerts",
        "category": AchievementCategory.ALERTS,
        "rarity": AchievementRarity.RARE,
        "icon": "alert-triangle",
        "points": 300,
        "requirements": {"critical_alerts_resolved": 10},
        "hidden": False,
    },
    "crisis_manager": {
        "name": "Crisis Manager",
        "description": "Resolve 50 critical severity alerts",
        "category": AchievementCategory.ALERTS,
        "rarity": AchievementRarity.LEGENDARY,
        "icon": "flame",
        "points": 1500,
        "requirements": {"critical_alerts_resolved": 50},
        "hidden": False,
    },

    # ==================== ANOMALY ACHIEVEMENTS ====================
    "pattern_spotter": {
        "name": "Pattern Spotter",
        "description": "Confirm 10 real anomalies",
        "category": AchievementCategory.ANOMALIES,
        "rarity": AchievementRarity.UNCOMMON,
        "icon": "eye",
        "points": 150,
        "requirements": {"anomalies_confirmed": 10},
        "hidden": False,
    },
    "anomaly_expert": {
        "name": "Anomaly Expert",
        "description": "Confirm 50 real anomalies",
        "category": AchievementCategory.ANOMALIES,
        "rarity": AchievementRarity.RARE,
        "icon": "scan",
        "points": 400,
        "requirements": {"anomalies_confirmed": 50},
        "hidden": False,
    },
    "false_positive_fighter": {
        "name": "False Positive Fighter",
        "description": "Mark 50 alerts as false positives",
        "category": AchievementCategory.ANOMALIES,
        "rarity": AchievementRarity.UNCOMMON,
        "icon": "x-circle",
        "points": 100,
        "requirements": {"false_positives_marked": 50},
        "hidden": False,
    },
    "noise_reducer": {
        "name": "Noise Reducer",
        "description": "Mark 200 alerts as false positives",
        "category": AchievementCategory.ANOMALIES,
        "rarity": AchievementRarity.RARE,
        "icon": "volume-x",
        "points": 300,
        "requirements": {"false_positives_marked": 200},
        "hidden": False,
    },

    # ==================== DEVICE ACHIEVEMENTS ====================
    "first_quarantine": {
        "name": "First Quarantine",
        "description": "Quarantine your first suspicious device",
        "category": AchievementCategory.DEVICES,
        "rarity": AchievementRarity.COMMON,
        "icon": "lock",
        "points": 25,
        "requirements": {"devices_quarantined": 1},
        "hidden": False,
    },
    "isolation_expert": {
        "name": "Isolation Expert",
        "description": "Quarantine 25 devices",
        "category": AchievementCategory.DEVICES,
        "rarity": AchievementRarity.UNCOMMON,
        "icon": "shield-off",
        "points": 200,
        "requirements": {"devices_quarantined": 25},
        "hidden": False,
    },
    "containment_specialist": {
        "name": "Containment Specialist",
        "description": "Quarantine 100 devices",
        "category": AchievementCategory.DEVICES,
        "rarity": AchievementRarity.RARE,
        "icon": "shield-alert",
        "points": 500,
        "requirements": {"devices_quarantined": 100},
        "hidden": False,
    },

    # ==================== INVESTIGATION ACHIEVEMENTS ====================
    "junior_investigator": {
        "name": "Junior Investigator",
        "description": "Complete your first investigation",
        "category": AchievementCategory.INVESTIGATIONS,
        "rarity": AchievementRarity.COMMON,
        "icon": "search",
        "points": 50,
        "requirements": {"investigations_completed": 1},
        "hidden": False,
    },
    "detective": {
        "name": "Detective",
        "description": "Complete 10 investigations",
        "category": AchievementCategory.INVESTIGATIONS,
        "rarity": AchievementRarity.UNCOMMON,
        "icon": "magnifying-glass",
        "points": 250,
        "requirements": {"investigations_completed": 10},
        "hidden": False,
    },
    "sherlock": {
        "name": "Sherlock",
        "description": "Complete 50 investigations",
        "category": AchievementCategory.INVESTIGATIONS,
        "rarity": AchievementRarity.RARE,
        "icon": "detective",
        "points": 750,
        "requirements": {"investigations_completed": 50},
        "hidden": False,
    },

    # ==================== STREAK ACHIEVEMENTS ====================
    "getting_started": {
        "name": "Getting Started",
        "description": "Maintain a 3-day activity streak",
        "category": AchievementCategory.STREAKS,
        "rarity": AchievementRarity.COMMON,
        "icon": "calendar",
        "points": 30,
        "requirements": {"streak_days": 3},
        "hidden": False,
    },
    "week_warrior": {
        "name": "Week Warrior",
        "description": "Maintain a 7-day activity streak",
        "category": AchievementCategory.STREAKS,
        "rarity": AchievementRarity.UNCOMMON,
        "icon": "calendar-check",
        "points": 100,
        "requirements": {"streak_days": 7},
        "hidden": False,
    },
    "fortnight_defender": {
        "name": "Fortnight Defender",
        "description": "Maintain a 14-day activity streak",
        "category": AchievementCategory.STREAKS,
        "rarity": AchievementRarity.UNCOMMON,
        "icon": "calendar-range",
        "points": 200,
        "requirements": {"streak_days": 14},
        "hidden": False,
    },
    "month_guardian": {
        "name": "Month Guardian",
        "description": "Maintain a 30-day activity streak",
        "category": AchievementCategory.STREAKS,
        "rarity": AchievementRarity.RARE,
        "icon": "calendar-heart",
        "points": 500,
        "requirements": {"streak_days": 30},
        "hidden": False,
    },
    "quarter_sentinel": {
        "name": "Quarter Sentinel",
        "description": "Maintain a 90-day activity streak",
        "category": AchievementCategory.STREAKS,
        "rarity": AchievementRarity.LEGENDARY,
        "icon": "calendar-star",
        "points": 2000,
        "requirements": {"streak_days": 90},
        "hidden": False,
    },

    # ==================== MILESTONE ACHIEVEMENTS ====================
    "level_5": {
        "name": "Rising Star",
        "description": "Reach Level 5",
        "category": AchievementCategory.MILESTONES,
        "rarity": AchievementRarity.COMMON,
        "icon": "star",
        "points": 50,
        "requirements": {"level": 5},
        "hidden": False,
    },
    "level_10": {
        "name": "Threat Hunter",
        "description": "Reach Level 10",
        "category": AchievementCategory.MILESTONES,
        "rarity": AchievementRarity.UNCOMMON,
        "icon": "star",
        "points": 150,
        "requirements": {"level": 10},
        "hidden": False,
    },
    "level_20": {
        "name": "Cyber Defender",
        "description": "Reach Level 20",
        "category": AchievementCategory.MILESTONES,
        "rarity": AchievementRarity.RARE,
        "icon": "star",
        "points": 400,
        "requirements": {"level": 20},
        "hidden": False,
    },
    "level_30": {
        "name": "Master Sentinel",
        "description": "Reach Level 30",
        "category": AchievementCategory.MILESTONES,
        "rarity": AchievementRarity.LEGENDARY,
        "icon": "stars",
        "points": 1000,
        "requirements": {"level": 30},
        "hidden": False,
    },
    "point_collector_1k": {
        "name": "Point Collector",
        "description": "Earn 1,000 total points",
        "category": AchievementCategory.MILESTONES,
        "rarity": AchievementRarity.UNCOMMON,
        "icon": "coins",
        "points": 100,
        "requirements": {"total_points": 1000},
        "hidden": False,
    },
    "point_hoarder_10k": {
        "name": "Point Hoarder",
        "description": "Earn 10,000 total points",
        "category": AchievementCategory.MILESTONES,
        "rarity": AchievementRarity.RARE,
        "icon": "piggy-bank",
        "points": 500,
        "requirements": {"total_points": 10000},
        "hidden": False,
    },

    # ==================== SPECIAL/HIDDEN ACHIEVEMENTS ====================
    "night_owl": {
        "name": "Night Owl",
        "description": "Resolve an alert between 2 AM and 5 AM",
        "category": AchievementCategory.SPECIAL,
        "rarity": AchievementRarity.RARE,
        "icon": "moon",
        "points": 200,
        "requirements": {"night_alert": True},
        "hidden": True,
    },
    "speed_demon": {
        "name": "Speed Demon",
        "description": "Resolve a critical alert within 60 seconds of creation",
        "category": AchievementCategory.SPECIAL,
        "rarity": AchievementRarity.LEGENDARY,
        "icon": "zap",
        "points": 1000,
        "requirements": {"fast_critical_response": True},
        "hidden": True,
    },
    "early_bird": {
        "name": "Early Bird",
        "description": "Be the first to respond to an alert before 6 AM",
        "category": AchievementCategory.SPECIAL,
        "rarity": AchievementRarity.UNCOMMON,
        "icon": "sunrise",
        "points": 100,
        "requirements": {"early_response": True},
        "hidden": True,
    },
    "perfectionist": {
        "name": "Perfectionist",
        "description": "Resolve 10 alerts in a row without any false positives",
        "category": AchievementCategory.SPECIAL,
        "rarity": AchievementRarity.RARE,
        "icon": "check-circle",
        "points": 300,
        "requirements": {"perfect_streak": 10},
        "hidden": True,
    },
    "multitasker": {
        "name": "Multitasker",
        "description": "Resolve 5 alerts within a 5-minute window",
        "category": AchievementCategory.SPECIAL,
        "rarity": AchievementRarity.UNCOMMON,
        "icon": "layers",
        "points": 150,
        "requirements": {"rapid_resolutions": 5},
        "hidden": True,
    },
    "weekend_warrior": {
        "name": "Weekend Warrior",
        "description": "Resolve 10 alerts on a weekend",
        "category": AchievementCategory.SPECIAL,
        "rarity": AchievementRarity.UNCOMMON,
        "icon": "calendar-weekend",
        "points": 100,
        "requirements": {"weekend_resolutions": 10},
        "hidden": True,
    },
    "honeypot_hunter": {
        "name": "Honeypot Hunter",
        "description": "Catch an attacker in a honeypot",
        "category": AchievementCategory.SPECIAL,
        "rarity": AchievementRarity.RARE,
        "icon": "bug",
        "points": 250,
        "requirements": {"honeypot_catches": 1},
        "hidden": True,
    },
    "apt_catcher": {
        "name": "APT Catcher",
        "description": "Identify an advanced persistent threat actor",
        "category": AchievementCategory.SPECIAL,
        "rarity": AchievementRarity.LEGENDARY,
        "icon": "skull",
        "points": 2000,
        "requirements": {"apt_identified": True},
        "hidden": True,
    },
}


def get_level_for_xp(xp: int) -> dict[str, Any]:
    """Get level info for a given XP amount.

    Args:
        xp: Current XP amount.

    Returns:
        Dict with level, title, current_xp, and xp_to_next_level.
    """
    current_level = LEVELS[0]
    next_level = LEVELS[1] if len(LEVELS) > 1 else None

    for i, level in enumerate(LEVELS):
        if xp >= level["xp"]:
            current_level = level
            next_level = LEVELS[i + 1] if i + 1 < len(LEVELS) else None
        else:
            break

    return {
        "level": current_level["level"],
        "title": current_level["title"],
        "current_xp": xp - current_level["xp"],
        "xp_to_next_level": next_level["xp"] - current_level["xp"] if next_level else 0,
        "total_xp": xp,
        "next_level_xp": next_level["xp"] if next_level else current_level["xp"],
    }


def get_xp_for_level(level: int) -> int:
    """Get the XP required to reach a given level.

    Args:
        level: Target level.

    Returns:
        XP required for that level.
    """
    for lvl in LEVELS:
        if lvl["level"] == level:
            return lvl["xp"]
    # If level not found, extrapolate
    if level > LEVELS[-1]["level"]:
        return LEVELS[-1]["xp"] + (level - LEVELS[-1]["level"]) * 100000
    return 0


def get_title_for_level(level: int) -> str:
    """Get the title for a given level.

    Args:
        level: User's level.

    Returns:
        Title string for that level.
    """
    current_title = LEVELS[0]["title"]
    for lvl in LEVELS:
        if level >= lvl["level"]:
            current_title = lvl["title"]
        else:
            break
    return current_title
