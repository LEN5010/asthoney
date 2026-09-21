from src.agents.main_agent import MainAgent


def _agent() -> MainAgent:
    agent = object.__new__(MainAgent)
    agent.quarantined_sources = set()
    agent.non_human_sources = set()
    agent.mcp_trap_hits = 0
    return agent


def test_hydrate_restores_quarantine_from_actions():
    agent = _agent()
    MainAgent._hydrate_runtime_from_records(
        agent,
        actions=[{"kind": "quarantine", "source": "198.51.100.9"}],
        alerts=[],
    )
    assert "198.51.100.9" in agent.quarantined_sources


def test_hydrate_restores_mcp_trap_hits_and_non_human_sources():
    agent = _agent()
    MainAgent._hydrate_runtime_from_records(
        agent,
        actions=[],
        alerts=[
            {"alert_type": "agent_oriented_mcp_trap", "source": "203.0.113.8"},
            {"alert_type": "agent_oriented_mcp_trap", "source": "203.0.113.8"},
            {"alert_type": "suspected_non_human_test_agent", "source": "198.51.100.9"},
        ],
    )
    assert agent.mcp_trap_hits == 2
    assert "198.51.100.9" in agent.non_human_sources
