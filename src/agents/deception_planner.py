"""确定性欺骗规划。

不调用大模型。每条攻击输入得到一份可复现的策略，终端演员只负责把线索说出来。
"""

from __future__ import annotations

import re
from typing import Any

from src.analytics.attack_matrix import techniques_for_intent


_DESTRUCTIVE = re.compile(r"\b(rm|mkfs|reboot|shutdown|halt|poweroff|dd)\b")

_STAGE = {
    "discovery": "environment_validation",
    "credential_access": "secret_harvest",
    "lateral_movement": "pivot_expansion",
    "tool_transfer": "payload_staging",
    "cloud_recon": "control_plane_enumeration",
    "collection": "data_staging",
    "web_probe": "edge_banner",
    "generic_probe": "interactive_probe",
    "interactive_shell": "interactive_probe",
    "idle": "interactive_probe",
}

_EVIDENCE = {
    "discovery": "命令属于系统或目录发现",
    "credential_access": "命令触及口令、密钥或环境凭证",
    "lateral_movement": "命令包含 ssh 与内网地址",
    "tool_transfer": "命令尝试拉取或传送工具",
    "collection": "命令尝试打包或导出数据",
    "cloud_recon": "命令探测云或容器控制面",
    "web_probe": "输入是 HTTP 探测",
    "generic_probe": "未命中专项规则，按低置信探针处理",
    "interactive_shell": "普通交互命令",
    "idle": "空输入",
}

_ACTOR_DETAIL = {
    "model": "大模型生成终端输出",
    "deterministic": "确定性伪终端",
    "static": "静态横幅，未进入高交互仿真",
}


def plan_deception(
    *,
    intent: dict[str, Any],
    payload: str,
    protocol: str,
    current_asset: dict[str, Any] | None = None,
    neighbors: list[dict[str, Any]] | None = None,
    seen_categories: list[str] | None = None,
) -> dict[str, Any]:
    """按意图类别选择欺骗策略，并给出要埋进终端的那一行线索。"""
    category = str(intent.get("category") or "generic_probe")
    hop = _next_hop(intent, current_asset, neighbors or [])
    destructive = bool(_DESTRUCTIVE.search(payload.strip().lower()))

    if destructive:
        strategy = "stall"
    elif category == "web_probe" or (category in {"generic_probe", "idle"} and protocol != "ssh"):
        strategy = "banner"
    elif category == "lateral_movement":
        strategy = "pivot"
    elif category in {"tool_transfer", "collection"}:
        strategy = "stall"
    else:
        strategy = "deepen"

    technique = techniques_for_intent(category)
    first = technique[0] if technique else {}
    seen = seen_categories or []
    return {
        "strategy": strategy,
        "cognitive_stage": _STAGE.get(category, "interactive_probe"),
        "planted_clue": "" if strategy == "banner" or destructive else _clue(category, hop),
        "rationale": _rationale(strategy, category, hop, seen, destructive),
        "evidence": "命中破坏性命令规则" if destructive else _EVIDENCE.get(category, _EVIDENCE["generic_probe"]),
        "technique": str(first.get("id") or ""),
        "technique_name": str(first.get("name") or ""),
        "next_hop": hop,
    }


def critique_output(*, command: str, response: str, actor_mode: str, guardrail: str) -> dict[str, str]:
    """记录响应来源，不拦截或改写模型输出。"""
    if actor_mode == "model":
        detail = "使用大模型生成终端响应"
    elif actor_mode == "interpreter":
        detail = "使用当前主机的虚拟文件与目录状态"
    elif guardrail == "model_error":
        detail = "模型暂不可用，使用本地响应"
    elif guardrail == "model_empty":
        detail = "模型返回空内容，使用本地响应"
    elif guardrail == "model_timeout":
        detail = "模型超过交互等待上限，使用本地响应"
    else:
        detail = "使用本地终端响应"
    return {"verdict": "pass", "detail": detail}


def observation_metadata(
    *,
    protocol: str,
    plan: dict[str, Any],
    analyst_category: str,
    terminal_intent: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """一条命令只保留分析员的意图。终端分类不同时记在元数据里，不再另开一条意图。"""
    metadata: dict[str, Any] = {
        "protocol": protocol,
        "strategy": str(plan.get("strategy") or ""),
        "technique": str(plan.get("technique") or ""),
        "source": "analyst",
    }
    terminal_category = str((terminal_intent or {}).get("category") or "")
    if terminal_category and terminal_category != analyst_category:
        metadata["terminal_category"] = terminal_category
    return metadata


def build_trace_steps(
    *,
    intent: dict[str, Any],
    plan: dict[str, Any],
    actor_mode: str,
    critic: dict[str, str],
) -> list[dict[str, Any]]:
    """四个角色的展示轨迹。顺序固定，方便面板和单测对齐。"""
    confidence = float(intent.get("confidence") or 0.0)
    return [
        {
            "role": "analyst",
            "title": "意图分析",
            "detail": str(intent.get("summary") or "未形成意图摘要"),
            "evidence": str(plan.get("evidence") or ""),
            "confidence": confidence,
            "category": str(intent.get("category") or "unknown"),
        },
        {
            "role": "planner",
            "title": "欺骗规划",
            "detail": str(plan.get("rationale") or ""),
            "strategy": str(plan.get("strategy") or ""),
            "planted_clue": str(plan.get("planted_clue") or ""),
            "technique": str(plan.get("technique") or ""),
            "cognitive_stage": str(plan.get("cognitive_stage") or ""),
        },
        {
            "role": "actor",
            "title": "终端仿真",
            "detail": _ACTOR_DETAIL.get(actor_mode, _ACTOR_DETAIL["deterministic"]),
            "mode": actor_mode,
        },
        {
            "role": "critic",
            "title": "响应来源",
            "detail": str(critic.get("detail") or ""),
            "verdict": str(critic.get("verdict") or "pass"),
        },
    ]


def _next_hop(
    intent: dict[str, Any],
    current_asset: dict[str, Any] | None,
    neighbors: list[dict[str, Any]],
) -> str:
    target = str(intent.get("target_ip") or "").strip()
    if target:
        return target
    current_ip = str((current_asset or {}).get("ip_address") or "")
    for neighbor in neighbors:
        ip = str(neighbor.get("ip_address") or "")
        if ip and ip != current_ip and not ip.startswith("0.0.0.0"):
            return ip
    if current_ip != "10.0.5.2":
        return "10.0.5.2"
    return "10.0.8.7"


def _clue(category: str, hop: str) -> str:
    if category == "discovery":
        return f"/srv/backup/db.env 指向 {hop}"
    if category == "credential_access":
        return f"ssh -i /srv/backup/id_rsa svc_finance_sync@{hop}"
    if category == "lateral_movement":
        return f"过期隧道配置指向 {hop}"
    if category == "tool_transfer":
        return f"传输被拒绝，磁盘上仍留有 /srv/backup/sync-oss.sh，下一跳 {hop}"
    if category == "collection":
        return "/srv/backup/export-2026-04-18.tar.gz"
    if category == "cloud_recon":
        return "/srv/backup/.aliyun/credentials"
    return f"备份目录备注指向 {hop}"


def _rationale(
    strategy: str,
    category: str,
    hop: str,
    seen: list[str],
    destructive: bool,
) -> str:
    if destructive:
        return "变更命令由当前虚拟主机处理，记录文件状态变化，不切换主机。"
    if category == "lateral_movement" and "credential_access" in seen:
        return f"凭证摸索之后立刻横向，沿 {hop} 展开下一跳诱饵。"
    lines = {
        ("deepen", "discovery"): "攻击者还在确认这台机器，目录列表里露出备份线索，引诱继续翻文件。",
        ("deepen", "credential_access"): "对方在当前主机翻凭证，只露出下一跳提示，会话先不换机器。",
        ("pivot", "lateral_movement"): f"检测到 ssh 横向，沿 {hop} 合成或进入下一跳诱饵。",
        ("stall", "tool_transfer"): "对方在拉工具，拒绝真正传输，只漏出文件名。",
        ("stall", "collection"): "对方在打包数据，挡住导出，只露出归档文件名。",
        ("deepen", "cloud_recon"): "对方在摸云控制面，留一份伪造凭证路径，不给出可用密钥。",
        ("banner", "web_probe"): "这是 HTTP 探测，只回横幅，不进入终端仿真。",
        ("banner", "generic_probe"): "低置信探针，只回边缘横幅。",
    }
    if (strategy, category) in lines:
        return lines[(strategy, category)]
    if strategy == "pivot":
        return f"按攻击意图把会话引向 {hop}。"
    if strategy == "stall":
        return "给一点线索，但不让这条命令真正成功。"
    if strategy == "banner":
        return "流量还没有高交互语义，只回应横幅。"
    return "留在当前主机，用一条备份线索把会话留住。"
