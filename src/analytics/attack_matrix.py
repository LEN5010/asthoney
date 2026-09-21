"""意图类别到 MITRE ATT&CK 战术/技术的映射。

课设定位说明：这里只覆盖本蜜网实际可观测到的技术子集，不追求完整 ATT&CK 矩阵。
每个映射都能由 `_infer_intent` 里的具体判据支撑，避免"贴标签但讲不清依据"。
"""

from __future__ import annotations

from typing import Any

# ATT&CK Enterprise 战术，按攻击链顺序排列（矩阵列顺序即此顺序）。
TACTIC_ORDER: list[dict[str, str]] = [
    {"id": "TA0043", "key": "reconnaissance", "name": "侦察"},
    {"id": "TA0001", "key": "initial_access", "name": "初始访问"},
    {"id": "TA0002", "key": "execution", "name": "执行"},
    {"id": "TA0007", "key": "discovery", "name": "发现"},
    {"id": "TA0006", "key": "credential_access", "name": "凭证访问"},
    {"id": "TA0008", "key": "lateral_movement", "name": "横向移动"},
    {"id": "TA0009", "key": "collection", "name": "收集"},
    {"id": "TA0010", "key": "exfiltration", "name": "数据窃取"},
]

TACTIC_BY_KEY = {item["key"]: item for item in TACTIC_ORDER}

# intent category -> ATT&CK 技术列表
INTENT_TECHNIQUE_MAP: dict[str, list[dict[str, str]]] = {
    "discovery": [
        {"id": "T1082", "name": "系统信息发现", "tactic": "discovery"},
        {"id": "T1083", "name": "文件与目录发现", "tactic": "discovery"},
        {"id": "T1033", "name": "属主/用户发现", "tactic": "discovery"},
    ],
    "credential_access": [
        {"id": "T1003", "name": "操作系统凭证转储", "tactic": "credential_access"},
        {"id": "T1552.001", "name": "文件中的凭证", "tactic": "credential_access"},
    ],
    "lateral_movement": [
        {"id": "T1021.004", "name": "远程服务：SSH", "tactic": "lateral_movement"},
        {"id": "T1570", "name": "横向工具转移", "tactic": "lateral_movement"},
    ],
    "tool_transfer": [
        {"id": "T1105", "name": "入口工具转移", "tactic": "execution"},
    ],
    "cloud_recon": [
        {"id": "T1580", "name": "云基础设施发现", "tactic": "discovery"},
        {"id": "T1526", "name": "云服务发现", "tactic": "discovery"},
    ],
    "collection": [
        {"id": "T1005", "name": "本地系统数据收集", "tactic": "collection"},
        {"id": "T1560", "name": "收集数据打包归档", "tactic": "collection"},
    ],
    "interactive_shell": [
        {"id": "T1059.004", "name": "命令解释器：Unix Shell", "tactic": "execution"},
    ],
    "web_probe": [
        {"id": "T1595", "name": "主动扫描", "tactic": "reconnaissance"},
    ],
    "generic_probe": [
        {"id": "T1595.002", "name": "主动扫描：漏洞扫描", "tactic": "reconnaissance"},
    ],
    "idle": [],
}

# 告警类型也参与矩阵覆盖统计（MCP 诱饵命中是本系统的特色观测点）。
ALERT_TECHNIQUE_MAP: dict[str, list[dict[str, str]]] = {
    "agent_oriented_mcp_trap": [
        {"id": "T1068", "name": "特权提升利用尝试", "tactic": "execution"},
        {"id": "T1195", "name": "供应链/工具链滥用", "tactic": "initial_access"},
    ],
    "suspected_non_human_test_agent": [
        {"id": "T1595", "name": "主动扫描", "tactic": "reconnaissance"},
    ],
}


def techniques_for_intent(category: str) -> list[dict[str, str]]:
    return INTENT_TECHNIQUE_MAP.get(category, [])


def techniques_for_alert(alert_type: str) -> list[dict[str, str]]:
    return ALERT_TECHNIQUE_MAP.get(alert_type, [])


def build_matrix(
    intents: list[dict[str, Any]],
    alerts: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """聚合意图与告警，产出可直接渲染的 ATT&CK 矩阵结构。

    返回按 TACTIC_ORDER 排好的列，每列含命中的技术及其观测次数。
    """
    alerts = alerts or []
    # technique_id -> 聚合项
    hits: dict[str, dict[str, Any]] = {}

    def register(technique: dict[str, str], observed_at: Any, evidence: str) -> None:
        entry = hits.setdefault(
            technique["id"],
            {
                "id": technique["id"],
                "name": technique["name"],
                "tactic": technique["tactic"],
                "count": 0,
                "first_seen": observed_at,
                "last_seen": observed_at,
                "evidence": [],
            },
        )
        entry["count"] += 1
        if observed_at:
            if not entry["first_seen"] or str(observed_at) < str(entry["first_seen"]):
                entry["first_seen"] = observed_at
            if not entry["last_seen"] or str(observed_at) > str(entry["last_seen"]):
                entry["last_seen"] = observed_at
        if evidence and len(entry["evidence"]) < 5 and evidence not in entry["evidence"]:
            entry["evidence"].append(evidence)

    for intent in intents:
        category = str(intent.get("category", ""))
        raw_input = str(intent.get("raw_input", "")).strip()
        created_at = intent.get("created_at")
        for technique in techniques_for_intent(category):
            register(technique, created_at, raw_input[:120])

    for alert in alerts:
        alert_type = str(alert.get("alert_type", ""))
        created_at = alert.get("created_at")
        details = alert.get("details") or {}
        evidence = str(details.get("tool_name") or details.get("summary") or alert_type)
        for technique in techniques_for_alert(alert_type):
            register(technique, created_at, evidence[:120])

    columns: list[dict[str, Any]] = []
    for tactic in TACTIC_ORDER:
        tactic_techniques = [
            item for item in hits.values() if item["tactic"] == tactic["key"]
        ]
        tactic_techniques.sort(key=lambda item: (-item["count"], item["id"]))
        columns.append(
            {
                **tactic,
                "techniques": tactic_techniques,
                "total_hits": sum(item["count"] for item in tactic_techniques),
            }
        )

    covered = sum(1 for column in columns if column["techniques"])
    return {
        "tactics": columns,
        "technique_count": len(hits),
        "total_observations": sum(item["count"] for item in hits.values()),
        "tactics_covered": covered,
        "tactics_total": len(TACTIC_ORDER),
    }
