from src.agents.deception_planner import build_trace_steps, critique_output, observation_metadata, plan_deception


def _plan(category: str, payload: str, **intent_extra):
    intent = {"category": category, "confidence": 0.9, "summary": payload, **intent_extra}
    return plan_deception(
        intent=intent,
        payload=payload,
        protocol="ssh",
        current_asset={"ip_address": "10.0.5.1", "hostname": "web-pivot-01", "asset_type": "linux_server"},
        neighbors=[],
        seen_categories=[],
    )


def test_discovery_deepens_with_backup_clue():
    plan = _plan("discovery", "ls /srv")
    assert plan["strategy"] == "deepen"
    assert "db.env" in plan["planted_clue"]
    assert plan["technique"] == "T1082"
    assert plan["rationale"]


def test_lateral_movement_pivots_to_target():
    plan = _plan("lateral_movement", "ssh admin@10.0.5.2", target_ip="10.0.5.2")
    assert plan["strategy"] == "pivot"
    assert "10.0.5.2" in plan["planted_clue"]
    assert plan["next_hop"] == "10.0.5.2"
    assert plan["technique"] == "T1021.004"


def test_http_probe_stays_on_banner():
    plan = plan_deception(
        intent={"category": "web_probe", "confidence": 0.7, "summary": "http"},
        payload="GET / HTTP/1.1",
        protocol="tcp",
        current_asset=None,
        neighbors=[],
        seen_categories=[],
    )
    assert plan["strategy"] == "banner"
    assert plan["planted_clue"] == ""


def test_destructive_command_does_not_plan_success():
    plan = _plan("generic_probe", "rm -rf /")
    assert plan["strategy"] == "stall"
    assert plan["planted_clue"] == ""
    assert "拒绝" in plan["rationale"]


def test_trace_has_four_roles_in_order():
    plan = _plan("discovery", "whoami")
    critic = critique_output(command="whoami", response="svc-backup", actor_mode="deterministic", guardrail="model_unconfigured")
    steps = build_trace_steps(
        intent={"category": "discovery", "confidence": 0.8, "summary": "interactive shell discovery behavior"},
        plan=plan,
        actor_mode="deterministic",
        critic=critic,
    )
    assert [step["role"] for step in steps] == ["analyst", "planner", "actor", "critic"]
    assert steps[3]["verdict"] == "pass"


def test_one_command_keeps_a_single_intent_category():
    metadata = observation_metadata(
        protocol="ssh",
        plan={"strategy": "deepen", "technique": "T1082"},
        analyst_category="discovery",
        terminal_intent={"category": "interactive_shell"},
    )
    assert metadata["source"] == "analyst"
    assert metadata["strategy"] == "deepen"
    assert metadata["terminal_category"] == "interactive_shell"
    same = observation_metadata(
        protocol="ssh",
        plan={"strategy": "pivot", "technique": "T1021.004"},
        analyst_category="lateral_movement",
        terminal_intent={"category": "lateral_movement"},
    )
    assert "terminal_category" not in same


def test_destructive_output_is_blocked_by_critic():
    critic = critique_output(
        command="rm -rf /var",
        response="removed 12 files",
        actor_mode="model",
        guardrail="pass",
    )
    assert critic["verdict"] == "blocked"
