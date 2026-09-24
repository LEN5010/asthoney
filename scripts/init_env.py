"""Create a local demo configuration with random secrets; never overwrite an existing file."""
from pathlib import Path
import secrets


def initialize(root: Path) -> Path:
    target = root / ".env"
    template = (root / ".env.example").read_text(encoding="utf-8")
    template = template.replace("NEO4J_PASSWORD=please_change_me", "NEO4J_PASSWORD=" + secrets.token_urlsafe(24))
    with target.open("x", encoding="utf-8") as output:
        output.write(template)
    target.chmod(0o600)
    return target


if __name__ == "__main__":
    try:
        print("已创建配置：" + str(initialize(Path(__file__).resolve().parents[1])))
        print("配置已生成；填写模型配置后运行 bash scripts/run_local.sh。")
    except FileExistsError:
        raise SystemExit("已有 .env，未做修改。")
