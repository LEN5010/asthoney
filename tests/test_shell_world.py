import asyncio

from src.agents.main_agent import MainAgent
from src.agents.sub_agent import SubAgent
from src.config import AppSettings, DashScopeClient


def _agent(asset_type: str = "linux_server", hostname: str = "web-pivot-01") -> SubAgent:
    settings = AppSettings(dashscope_api_key="")
    return SubAgent(
        settings=settings,
        dashscope_client=DashScopeClient(settings),
        session_id="world-session",
        source_ip="198.51.100.9",
        asset_snapshot={
            "asset_id": "asset:test",
            "hostname": hostname,
            "ip_address": "10.0.5.1",
            "asset_type": asset_type,
            "persona": asset_type,
            "metadata": {},
        },
        local_view={"neighbors": []},
    )


def test_cd_then_ls_stays_in_the_session_world():
    agent = _agent()
    entered = asyncio.run(agent.handle_input("cd /srv"))
    assert entered["response"] == ""
    listing = asyncio.run(agent.handle_input("ls"))
    assert "backup" in listing["response"]
    assert agent.world.cwd == "/srv"


def test_missing_cd_does_not_move():
    agent = _agent()
    before = agent.world.cwd
    missing = asyncio.run(agent.handle_input("cd /no/such"))
    assert "No such file" in missing["response"]
    assert agent.world.cwd == before


def test_touch_and_rm_update_the_virtual_world():
    agent = _agent()
    created = asyncio.run(agent.handle_input("touch /tmp/note"))
    assert created["response"] == ""
    listing = asyncio.run(agent.handle_input("ls /tmp"))
    assert "note" in listing["response"]
    removed = asyncio.run(agent.handle_input("rm /tmp/note"))
    assert removed["response"] == ""
    assert "note" not in asyncio.run(agent.handle_input("ls /tmp"))["response"]
    assert "/tmp/note" not in agent.world.snapshot()["created"]
    assert "No such file" in asyncio.run(agent.handle_input("cat /tmp/note"))["response"]


def test_listed_file_can_be_named_but_not_entered():
    agent = _agent()
    listed = asyncio.run(agent.handle_input("ls /etc/passwd"))
    assert listed["response"] == "passwd"
    rejected = asyncio.run(agent.handle_input("cd /etc/passwd"))
    assert "Not a directory" in rejected["response"]
    assert agent.world.cwd != "/etc/passwd"


def test_find_on_empty_directory_is_not_missing():
    agent = _agent()
    created = asyncio.run(agent.handle_input("mkdir /tmp/emptybin"))
    assert created["response"] == ""
    found = asyncio.run(agent.handle_input("find /tmp/emptybin"))
    assert "No such file" not in found["response"]


def test_closed_session_world_reads_the_stored_snapshot():
    agent = object.__new__(MainAgent)
    agent.active_sub_agents = {}

    class _Store:
        async def load_session_world(self, session_id: str) -> dict:
            assert session_id == "s1"
            return {"cwd": "/srv", "hostname": "web-pivot-01", "files": []}

    agent.graph_db = _Store()
    result = asyncio.run(agent.session_world("s1"))
    assert result["source"] == "stored"
    assert result["available"] is True
    assert result["cwd"] == "/srv"


def test_uname_uses_the_host_in_the_world():
    result = asyncio.run(_agent(hostname="web-pivot-01").handle_input("uname -a"))
    assert result["actor_mode"] == "interpreter"
    assert "web-pivot-01" in result["response"]
    assert "Linux" in result["response"]


def test_listed_archive_can_be_read():
    result = asyncio.run(_agent().handle_input("cat /srv/backup/export-2026-04-18.tar.gz"))
    assert result["actor_mode"] == "interpreter"
    assert "finance-export.tar" in result["response"]


def test_pipe_grep_head_and_redirect_stay_in_the_world():
    agent = _agent()
    piped = asyncio.run(agent.handle_input("echo DB_HOST=10.0.5.2 | grep DB_HOST"))
    assert piped["response"] == "DB_HOST=10.0.5.2"
    headed = asyncio.run(agent.handle_input("head -n 1 /etc/passwd"))
    assert headed["response"].startswith("root:")
    chained = asyncio.run(agent.handle_input("cd /srv && ls"))
    assert "backup" in chained["response"]
    assert agent.world.cwd == "/srv"
    written = asyncio.run(agent.handle_input("echo hello > /tmp/out.txt"))
    assert written["response"] == ""
    read_back = asyncio.run(agent.handle_input("cat /tmp/out.txt"))
    assert read_back["response"] == "hello"
    denied = asyncio.run(agent.handle_input("echo no > /srv/backup/db.env"))
    assert "Permission denied" in denied["response"]
    secret = asyncio.run(agent.handle_input("cat /srv/backup/db.env"))
    assert "DB_HOST=10.0.5.2" in secret["response"]
    wrapped = asyncio.run(agent.handle_input("bash -c 'grep DB_HOST /srv/backup/db.env'"))
    assert "DB_HOST=10.0.5.2" in wrapped["response"]
    long_listing = asyncio.run(agent.handle_input("ls -l /etc/passwd"))
    assert "passwd" in long_listing["response"]
    assert "-rw-r--r--" in long_listing["response"]
    found = asyncio.run(agent.handle_input("find /srv -name db.env"))
    assert found["response"] == "/srv/backup/db.env"


def test_database_secret_stays_off_the_pivot():
    pivot = asyncio.run(_agent().handle_input("cat /srv/backup/db.env"))
    assert "DB_HOST=10.0.5.2" in pivot["response"]
    assert "DB_PASS" not in pivot["response"]
    replica = asyncio.run(_agent("database_server", "db-replica-01").handle_input("cat /srv/backup/db.env"))
    assert "DB_PASS=Sync-2026-Apr" in replica["response"]
    oss = asyncio.run(_agent("oss_gateway", "oss-sync-bridge").handle_input("cat /srv/backup/db.env"))
    assert "DB_PASS" not in oss["response"]


def test_or_operator_runs_rhs_only_after_failure():
    agent = _agent()
    fallback = asyncio.run(agent.handle_input("false || echo hi"))
    assert fallback["response"] == "hi"
    skipped = asyncio.run(agent.handle_input("echo ok || echo no"))
    assert skipped["response"] == "ok"
    bare = asyncio.run(agent.handle_input("false"))
    assert bare["response"] == ""


def test_or_operator_respects_quotes_and_pipes():
    agent = _agent()
    quoted = asyncio.run(agent.handle_input('echo "a || b"'))
    assert quoted["response"] == "a || b"
    piped = asyncio.run(agent.handle_input("false | cat || echo fallback"))
    # 与 bash 一致：管道退出码取最后一级，cat 成功则 || 右侧不执行。
    assert "fallback" not in piped["response"]
    chained = asyncio.run(agent.handle_input("false || echo one || echo two"))
    assert chained["response"] == "one"


def test_rm_directory_requires_recursive_and_removes_children():
    agent = _agent()
    asyncio.run(agent.handle_input("mkdir /tmp/check"))
    asyncio.run(agent.handle_input("touch /tmp/check/file"))
    assert "Is a directory" in asyncio.run(agent.handle_input("rm /tmp/check"))["response"]
    assert asyncio.run(agent.handle_input("rm -r /tmp/check"))["response"] == ""
    assert "/tmp/check/file" not in agent.world.files
    assert "/tmp/check" not in agent.world.directories
    assert asyncio.run(agent.handle_input("rm -f /tmp/missing"))["response"] == ""


def test_hidden_files_directories_and_ssh_clues_are_consistent():
    agent = _agent()
    run = lambda cmd: asyncio.run(agent.handle_input(cmd))["response"]
    assert ".backup-state" not in run("ls").split()
    assert ".backup-state" in run("ls -a").split()
    assert {".", ".."} <= set(run("ls -a").split())
    assert "." not in run("ls -A").split()
    assert run("ls -ld /home").startswith("drwx")
    assert run("ls -ld /home").endswith(" /home")
    assert run("cd /home") == ""
    assert "svc-backup" in run("ls")
    assert "HostName 10.0.5.2" in run("cat ~/.ssh/config")
    assert "IdentityFile" in run("cat ~/.ssh/config")
    assert "backup.sh" in run("cat /var/tmp/handoff.txt")
    assert "simulated" not in run("cat /etc/hosts")
    assert "10.0.5.2" in run("cat /etc/hosts")
    assert "10.0.5.1" in run("ip addr")
    assert "10.0.5.1" in run("ip route")


def test_readonly_exploration_multi_path_ls_and_home():
    agent = _agent()
    run = lambda command: asyncio.run(agent.handle_input(command))
    listing = run("ls -la /var/tmp /srv/backup")
    assert listing["actor_mode"] == "interpreter"
    assert "/var/tmp:" in listing["response"] and "/srv/backup:" in listing["response"]
    assert "handoff.txt" in listing["response"] and "db.env" in listing["response"]
    assert run("ls -d /home /srv")["response"] == "/home\n\n/srv"
    assert run("cd")["response"] == ""
    assert run("pwd")["response"] == "/home/svc-backup"
    assert "Host finance-replica" in run("cat .ssh/config")["response"]


def test_backup_clue_timeline_and_transfer_direction():
    pivot = _agent().world
    replica = _agent("database_server", "db-replica-01").world
    archive = _agent("oss_gateway", "oss-sync-bridge").world
    assert "Sep 22 retry completed" in pivot.files["/var/tmp/handoff.txt"]
    assert "status=completed" in pivot.files["/var/tmp/.backup-state"]
    assert "finance-latest.sql" in pivot.files["/var/tmp/backup.sh"]
    assert pivot.files["/srv/backup/finance-latest.sql"] == replica.files["/srv/backup/finance.dump"]
    assert "/srv/sync/nightly.sh" in replica.files["/srv/backup/archive-sync.sh"]
    assert "scp svc-backup@10.0.5.2:/srv/backup/finance.dump" in archive.files["/srv/sync/nightly.sh"]
    assert "ossutil cp /var/tmp/" in archive.files["/srv/oss/sync-oss.sh"]


def test_absolute_paths_and_identity_flags_share_one_world():
    world = _agent().world
    assert world.execute('id') == world.execute('/usr/bin/id')
    assert world.execute('id -u') == world.execute('/usr/bin/id -ru') == '997'
    assert world.execute('id -un') == 'svc-backup'
    assert world.execute('/usr/bin/getent passwd svc-backup').startswith('svc-backup:x:997:997:')
    assert world.execute('uname -r') == '5.15.0-92-generic'
    assert world.execute('/usr/bin/uname -r') in world.execute('uname -a')
    assert '997\t997\t997\t997' in world.execute('cat /proc/self/status')


def test_compound_unknown_does_not_discard_or_regenerate_known_commands():
    agent = _agent()
    class NoModel:
        is_configured = True
        async def chat(self, *args, **kwargs):
            raise AssertionError('compound command must not be regenerated wholesale')
    agent.dashscope_client = NoModel()
    result = asyncio.run(agent.handle_input('echo START; id; uninstalled_xyz; hostname; echo END'))
    text = result['response']
    assert result['actor_mode'] == 'interpreter'
    assert 'START' in text and 'uid=997' in text and 'END' in text
    assert 'uninstalled_xyz: command not found' in text
    assert 'echo: command not found' not in text
    assert 'admin note' not in text


def test_variables_quoting_substitution_and_exit_status():
    world = _agent().world
    assert world.execute('echo "$HOME"') == '/home/svc-backup'
    assert world.execute("echo '$HOME'") == '$HOME'
    assert world.execute('echo "UID=$(id -u) HOST=$(hostname)"') == 'UID=997 HOST=web-pivot-01'
    assert world.execute('false; echo $?') == '1'
    assert world.execute('cat /missing 2>/dev/null; echo $?') == '1'
    assert world.execute('false && echo NO; echo YES') == 'YES'
    assert world.execute('echo "a; b | c"') == 'a; b | c'
    assert world.execute('echo "escaped \\"quote\\""') == 'escaped "quote"'


def test_script_and_encoded_stdin_use_virtual_shell():
    import base64
    world = _agent().world
    assert world.execute('/bin/bash -c "id -u; uname -r"') == '997\n5.15.0-92-generic'
    script = 'echo "HOME=$HOME"\nid -u\nuname -r\n'
    encoded = base64.b64encode(script.encode()).decode()
    assert world.execute(f'echo {encoded} | /bin/base64 -d | /bin/bash') == 'HOME=/home/svc-backup\n997\n5.15.0-92-generic'
    assert world.execute('printf "#!/bin/bash\\nid -u\\n" > /tmp/check.sh; /bin/bash /tmp/check.sh') == '997'


def test_type_paths_and_proc_are_consistent():
    world = _agent().world
    assert world.execute('type echo') == 'echo is a shell builtin'
    assert world.execute('command -v bash') == '/bin/bash'
    assert world.execute('/usr/bin/which id') == '/usr/bin/id'
    assert 'No such file' not in world.execute('ls -l /bin/bash /usr/bin/id /bin/cat')
    assert world.execute('cat /proc/self/cmdline | tr "\\0" " "') == 'bash '
    assert world.execute('cat /etc/machine-id') == _agent().world.execute('cat /etc/machine-id')
    assert world.execute('cat /etc/shadow 2>/dev/null; echo "rc=$?"') == 'rc=1'


def test_real_agent_recon_batch_is_interpreted_without_model():
    commands = [
        'echo "===== ID/WHO ====="; id; whoami; who; w; echo; echo "===== OS ====="; cat /etc/os-release; uname -a; echo; echo "===== UPTIME/DATE ====="; uptime; date; echo; echo "===== CPU/MEM ====="; nproc; free -h; echo; echo "===== VIRT ====="; systemd-detect-virt 2>/dev/null; ls -la / | head -30',
        'echo "===== IP ADDR ====="; ip -br addr 2>/dev/null || ifconfig -a; echo; echo "===== ROUTES ====="; ip route 2>/dev/null || route -n; echo; echo "===== ARP/NEIGH ====="; ip neigh 2>/dev/null || arp -a; echo; echo "===== RESOLV ====="; cat /etc/resolv.conf; echo; echo "===== HOSTS ====="; cat /etc/hosts; echo; echo "===== HOSTNAME ====="; hostname; hostnamectl 2>/dev/null; echo; echo "===== LISTEN ====="; (ss -tulnp 2>/dev/null || netstat -tulnp 2>/dev/null) | head -40',
        'echo $PATH; echo "---"; /usr/bin/id; echo "---shell---"; /usr/bin/getent passwd svc-backup; echo "---ls /bin---"; /bin/ls /bin | /usr/bin/head -5',
        'cat /proc/self/status | /bin/grep -E "^(Uid|Gid|Name)"; echo "--- env ---"; env | sort; echo "--- bashrc ---"; cat ~/.bashrc 2>/dev/null | tail -20',
    ]
    for command in commands:
        result = asyncio.run(_agent().handle_input(command))
        assert result['actor_mode'] == 'interpreter'
        assert 'command not found' not in result['response']
        assert 'uid=0' not in result['response']
        assert 'admin note' not in result['response']


def test_find_options_do_not_become_paths():
    world = _agent().world
    result = world.execute('find / -maxdepth 4 -type f -name db.env')
    assert result == '/srv/backup/db.env'
    assert world.execute('find /srv -name missing') == ''


def test_agent_tool_inventory_loop_uses_local_command_lookup():
    world = _agent().world
    text = world.execute('for t in id bash missing_tool; do echo "$t"; command -v "$t"; done')
    assert text == 'id\n/usr/bin/id\nbash\n/bin/bash\nmissing_tool'
    assert world.execute('id -u') == '997'
