"""
WardenIPS - Smart Scoring Engine
================================

Adds cross-plugin correlation and recidivist-aware ban duration policy
on top of per-plugin base risk scoring.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(slots=True)
class SmartScoreResult:
    """Calculated score metadata used by the ban pipeline."""

    score: int
    multi_vector: bool
    bonus_applied: int


class SmartScoringEngine:
    """Applies multi-vector bonus and repeat-offender ban escalation."""

    def __init__(self, base_ban_duration: int = 3600) -> None:
        self._base_ban_duration = max(int(base_ban_duration), 0)

    def apply_multi_vector_bonus(
        self,
        base_score: int,
        unique_connection_types: list[str],
    ) -> SmartScoreResult:
        """
        Adds +50% risk when an IP attacks multiple vectors.

        Multi-vector is active when at least two distinct connection types were
        observed in the current analysis window.
        """
        normalized = {str(item).strip().lower() for item in unique_connection_types if item}
        multi_vector = len(normalized) >= 2
        score = int(base_score)
        bonus = 0
        if multi_vector:
            bonus = max(int(round(score * 0.5)), 1)
            score += bonus
        score = max(0, min(score, 100))
        return SmartScoreResult(score=score, multi_vector=multi_vector, bonus_applied=bonus)

    def recidivist_ban_duration(self, prior_ban_count: int) -> int:
        """
        Returns ban duration based on prior offenses.

        Sequence (minimum policy):
          1st ban: base duration
          2nd ban: at least 24h
          3rd ban: at least 7d
          4th+ ban: 7d + 3d per offense, capped at 30d
        """
        current_offense_index = max(int(prior_ban_count), 0) + 1
        base = self._base_ban_duration

        if current_offense_index <= 1:
            return base
        if current_offense_index == 2:
            return max(base, 24 * 3600)
        if current_offense_index == 3:
            return max(base, 7 * 24 * 3600)

        extra_days = (current_offense_index - 3) * 3
        capped_days = min(7 + extra_days, 30)
        return max(base, capped_days * 24 * 3600)
