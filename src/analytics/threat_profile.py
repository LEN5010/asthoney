"""攻击者威胁画像与风险评分。

评分模型（0-100，可解释、可复现，不依赖大模型）：

    risk = 意图严重度(最高 45) + 战术推进深度(最高 25)
         + 告警强度(最高 20) + 自动化特征(最高 10)

设计取舍：
- 采用"峰值 + 衰减累加"而不是简单求和，避免刷命令数就能把分数拉满。
- 每个分项都回传明细，前端与报告可逐项展示依据（答辩时能讲清"为什么是 87 分"）。
"""

from __future__ import annotations

from typing import Any

from src.analytics.attack_matrix import techniques_for_intent

# 意图类别的基础危害权重（0-1）。与 MainAgent._intent_severity 的排序保持一致。
INTENT_WEIGHT: dict[str, float] = {
    "credential_access": 1.00,
    "lateral_movement": 1.00,
    "tool_transfer": 0.78,
    "cloud_recon": 0.74,
    "collection": 0.70,
    "discovery": 0.45,
    "interactive_shell": 0.40,
    "web_probe": 0.22,
    "generic_probe": 0.18,
    "idle": 0.05,
}

# 攻击链推进阶段：命中越靠后的阶段，说明渗透越深。
KILL_CHAIN_STAGE: dict[str, int] = {
    "generic_probe": 1,
    "web_probe": 1,
    "idle": 1,
    "discovery": 2,
    "interactive_shell": 2,
    "cloud_recon": 3,
    "tool_transfer": 3,
    "credential_access": 4,
    "collection": 4,
    "lateral_movement": 5,
}
MAX_STAGE = 5

SEVERITY_WEIGHT: dict[str, float] = {
    "critical": 1.0,
    "high": 0.72,
    "medium": 0.42,
    "low": 0.18,
}

# 各分项满分
CAP_INTENT = 45.0
CAP_DEPTH = 25.0
CAP_ALERT = 20.0
CAP_AUTOMATION = 10.0


def _round(value: float, digits: int = 1) -> float:
    return round(value + 0.0, digits)


def score_intent_component(categories: list[str]) -> tuple[float, dict[str, Any]]:
    """峰值主导 + 多样性衰减累加。"""
    if not categories:
        return 0.0, {"peak_category": None, "peak_weight": 0.0, "distinct": 0}

    weights = sorted(
        ((INTENT_WEIGHT.get(category, 0.3), category) for category in set(categories)),
        reverse=True,
    )
    peak_weight, peak_category = weights[0]
    # 峰值占 70%，其余类别按 0.5^n 衰减补充剩余 30%，多样化攻击得分更高但不失控。
    score = peak_weight * 0.70
    for index, (weight, _category) in enumerate(weights[1:], start=1):
        score += weight * 0.30 * (0.5**index)
    score = min(1.0, score) * CAP_INTENT
    return _round(score), {
        "peak_category": peak_category,
        "peak_weight": peak_weight,
        "distinct": len(weights),
    }


def score_depth_component(categories: list[str]) -> tuple[float, dict[str, Any]]:
    """按观测到的最深攻击链阶段给分。"""
    if not categories:
        return 0.0, {"max_stage": 0, "max_stage_total": MAX_STAGE}
    max_stage = max(KILL_CHAIN_STAGE.get(category, 1) for category in categories)
    score = (max_stage / MAX_STAGE) * CAP_DEPTH
    return _round(score), {"max_stage": max_stage, "max_stage_total": MAX_STAGE}


def score_alert_component(alerts: list[dict[str, Any]]) -> tuple[float, dict[str, Any]]:
    """告警按严重度加权，对数式收敛避免单一来源刷分。"""
    if not alerts:
        return 0.0, {"alert_count": 0, "critical_count": 0}
    total = sum(SEVERITY_WEIGHT.get(str(a.get("severity", "")).lower(), 0.3) for a in alerts)
    critical_count = sum(1 for a in alerts if str(a.get("severity", "")).lower() == "critical")
    # total=1 -> 0.5, total=3 -> ~0.8, total>=6 -> 接近 1
    ratio = min(1.0, total / (total + 1.6))
    return _round(ratio * CAP_ALERT), {
        "alert_count": len(alerts),
        "critical_count": critical_count,
        "weighted_total": _round(total, 2),
    }


def score_automation_component(
    *, likely_non_human: bool, command_count: int
) -> tuple[float, dict[str, Any]]:
    """自动化 Agent 特征：本系统的差异化观测点，单列一项。"""
    if not likely_non_human:
        return 0.0, {"likely_non_human": False}
    # 命令越多，自动化判定越可信
    confidence = min(1.0, 0.6 + command_count / 40)
    return _round(confidence * CAP_AUTOMATION), {
        "likely_non_human": True,
        "command_count": command_count,
    }


def risk_band(score: float) -> str:
    if score >= 80:
        return "critical"
    if score >= 60:
        return "high"
    if score >= 35:
        return "medium"
    return "low"


def compute_threat_score(
    *,
    categories: list[str],
    alerts: list[dict[str, Any]],
    likely_non_human: bool = False,
    command_count: int = 0,
) -> dict[str, Any]:
    """计算总分并返回逐项依据。"""
    intent_score, intent_detail = score_intent_component(categories)
    depth_score, depth_detail = score_depth_component(categories)
    alert_score, alert_detail = score_alert_component(alerts)
    automation_score, automation_detail = score_automation_component(
        likely_non_human=likely_non_human, command_count=command_count
    )

    total = intent_score + depth_score + alert_score + automation_score
    total = _round(min(100.0, total))

    return {
        "score": total,
        "band": risk_band(total),
        "components": [
            {
                "key": "intent",
                "label": "意图严重度",
                "score": intent_score,
                "max": CAP_INTENT,
                "detail": intent_detail,
            },
            {
                "key": "depth",
                "label": "攻击链深度",
                "score": depth_score,
                "max": CAP_DEPTH,
                "detail": depth_detail,
            },
            {
                "key": "alert",
                "label": "告警强度",
                "score": alert_score,
                "max": CAP_ALERT,
                "detail": alert_detail,
            },
            {
                "key": "automation",
                "label": "自动化特征",
                "score": automation_score,
                "max": CAP_AUTOMATION,
                "detail": automation_detail,
            },
        ],
    }


def build_attacker_profiles(
    *,
    sessions: list[dict[str, Any]],
    intents_by_session: dict[str, list[dict[str, Any]]],
    alerts: list[dict[str, Any]],
    actions: list[dict[str, Any]],
    non_human_sources: set[str] | None = None,
) -> list[dict[str, Any]]:
    """按来源 IP 聚合出攻击者画像列表，按风险分降序。"""
    non_human_sources = non_human_sources or set()
    quarantined = {str(action.get("source")) for action in actions if action.get("source")}

    alerts_by_source: dict[str, list[dict[str, Any]]] = {}
    for alert in alerts:
        alerts_by_source.setdefault(str(alert.get("source", "unknown")), []).append(alert)

    profiles: dict[str, dict[str, Any]] = {}

    for session in sessions:
        source_ip = str(session.get("source_ip") or "unknown")
        session_id = str(session.get("session_id") or "")
        profile = profiles.setdefault(
            source_ip,
            {
                "source_ip": source_ip,
                "sessions": 0,
                "session_ids": [],
                "command_count": 0,
                "categories": [],
                "techniques": {},
                "visited_hosts": set(),
                "first_seen": session.get("created_at"),
                "last_seen": session.get("last_seen"),
            },
        )
        profile["sessions"] += 1
        if session_id:
            profile["session_ids"].append(session_id)
        profile["command_count"] += int(session.get("command_count") or 0)
        for host in session.get("visited_hosts") or []:
            if host:
                profile["visited_hosts"].add(str(host))
        if session.get("entry_hostname"):
            profile["visited_hosts"].add(str(session["entry_hostname"]))

        created_at = session.get("created_at")
        last_seen = session.get("last_seen")
        if created_at and (not profile["first_seen"] or str(created_at) < str(profile["first_seen"])):
            profile["first_seen"] = created_at
        if last_seen and (not profile["last_seen"] or str(last_seen) > str(profile["last_seen"])):
            profile["last_seen"] = last_seen

        for intent in intents_by_session.get(session_id, []):
            category = str(intent.get("category", ""))
            if not category:
                continue
            profile["categories"].append(category)
            for technique in techniques_for_intent(category):
                profile["techniques"][technique["id"]] = technique["name"]

    results: list[dict[str, Any]] = []
    for source_ip, profile in profiles.items():
        source_alerts = alerts_by_source.get(source_ip, [])
        likely_non_human = source_ip in non_human_sources or any(
            str(a.get("alert_type")) == "suspected_non_human_test_agent" for a in source_alerts
        )
        scoring = compute_threat_score(
            categories=profile["categories"],
            alerts=source_alerts,
            likely_non_human=likely_non_human,
            command_count=profile["command_count"],
        )
        results.append(
            {
                "source_ip": source_ip,
                "risk_score": scoring["score"],
                "risk_band": scoring["band"],
                "score_components": scoring["components"],
                "sessions": profile["sessions"],
                "session_ids": profile["session_ids"][:20],
                "command_count": profile["command_count"],
                "alert_count": len(source_alerts),
                "critical_alerts": sum(
                    1 for a in source_alerts if str(a.get("severity", "")).lower() == "critical"
                ),
                "distinct_categories": sorted(set(profile["categories"])),
                "techniques": [
                    {"id": tid, "name": name} for tid, name in sorted(profile["techniques"].items())
                ],
                "visited_hosts": sorted(profile["visited_hosts"]),
                "quarantined": source_ip in quarantined,
                "likely_non_human": likely_non_human,
                "first_seen": profile["first_seen"],
                "last_seen": profile["last_seen"],
            }
        )

    results.sort(key=lambda item: (-item["risk_score"], item["source_ip"]))
    return results
