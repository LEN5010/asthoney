from src.analytics.attack_matrix import build_matrix
from src.analytics.threat_profile import build_attacker_profiles, compute_threat_score


def test_matrix_maps_lateral_movement_to_ssh_technique():
    matrix = build_matrix(
        [{"category": "lateral_movement", "raw_input": "ssh admin@10.0.5.2", "created_at": "2026-09-17"}],
        [],
    )
    lateral = next(column for column in matrix["tactics"] if column["key"] == "lateral_movement")
    technique_ids = {item["id"] for item in lateral["techniques"]}
    assert "T1021.004" in technique_ids
    assert matrix["total_observations"] >= 1


def test_threat_score_is_explainable_and_capped():
    scoring = compute_threat_score(
        categories=["lateral_movement", "credential_access", "discovery"],
        alerts=[{"severity": "critical"}, {"severity": "high"}],
        likely_non_human=True,
        command_count=12,
    )
    assert 0 <= scoring["score"] <= 100
    assert scoring["band"] in {"low", "medium", "high", "critical"}
    keys = {item["key"] for item in scoring["components"]}
    assert keys == {"intent", "depth", "alert", "automation"}
    component_sum = sum(item["score"] for item in scoring["components"])
    assert component_sum + 0.2 >= scoring["score"]


def test_profiles_aggregate_by_source_and_mark_quarantine():
    profiles = build_attacker_profiles(
        sessions=[
            {
                "session_id": "demo-ssh-01",
                "source_ip": "198.51.100.9",
                "command_count": 3,
                "visited_hosts": ["db-replica-01"],
                "entry_hostname": "ssh-edge-2222",
            }
        ],
        intents_by_session={
            "demo-ssh-01": [
                {"category": "discovery", "raw_input": "whoami"},
                {"category": "lateral_movement", "raw_input": "ssh admin@10.0.5.2"},
            ]
        },
        alerts=[{"source": "198.51.100.9", "severity": "critical", "alert_type": "high_risk_intent_detected"}],
        actions=[{"source": "198.51.100.9", "kind": "quarantine"}],
    )
    assert len(profiles) == 1
    profile = profiles[0]
    assert profile["source_ip"] == "198.51.100.9"
    assert profile["quarantined"] is True
    assert profile["sessions"] == 1
    assert "lateral_movement" in profile["distinct_categories"]
