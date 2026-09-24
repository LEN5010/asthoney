"""Create the course submission from an explicit allowlist and validate its structure.

Report documents must already be rendered and reviewed. This command does not
include local secrets, runtime state, virtual environments or historical drafts.
"""
from __future__ import annotations
import hashlib
import json
from pathlib import Path
import re
import shutil
import zipfile

TITLE = "基于多智能体的生成式欺骗蜜罐网与态势感知系统"
MEMBERS = "132-刘毅凡 133-蔡铭达 134-王子越 218-江博琛"
ROOT_NAME = f"14-{TITLE}（{MEMBERS}）"
EXCLUDED = {"__pycache__", ".pytest_cache", ".git", ".venv", "venv", "node_modules", "bin", "obj"}
ROOT_FILES = ["main.py", "README.md", "运行说明.md", ".env.example", ".dockerignore", "Dockerfile",
              "docker-compose.yml", "requirements.txt", "requirements.lock", "pytest.ini", "package.json", "package-lock.json"]


def source_files(root: Path):
    for name in ROOT_FILES:
        yield root / name
    for name in ["src", "static", "scripts", "tests"]:
        for item in sorted((root / name).rglob("*")):
            if item.is_relative_to(root / "tests/evidence") and item.name != "final-pytest.txt":
                continue  # Previous revisions' logs do not describe this release.
            if item.is_file() and not item.is_symlink() and not (set(item.relative_to(root).parts) & EXCLUDED) and item.suffix != ".pyc":
                yield item
    for glob in ["docs/final/*.md", "docs/final/*.json", "docs/diagrams/*.drawio", "docs/diagrams/*.png",
                 "docs/evidence/ui/*.png", "docs/evidence/ui/final-layout.json",
                 "docs/evidence/grok-rehearsal/summary.json", "docs/evidence/grok-rehearsal/final-replay.json",
                 "docs/evidence/grok-rehearsal/live-ui.json", "docs/evidence/grok-rehearsal/replay-ui.json",
                 "docs/evidence/reset/*.json", "docs/evidence/reset/*.png",
                 "docs/evidence/shell-incident/after.json", "docs/evidence/shell-incident/plain-ssh.json",
                 "docs/evidence/short-prompt/final-check.json", "docs/evidence/short-prompt/ui-polish.json",
                 "docs/defense/*.md", "docs/defense/*.txt", "docs/defense/guide.json",
                 "docs/defense/output/*.docx", "docs/defense/final/*.pdf",
                 "docs/答辩提纲.md", "docs/验收记录.md"]:
        yield from sorted(root.glob(glob))


def build(root: Path) -> Path:
    destination = root / "delivery" / ROOT_NAME
    if destination.exists():
        shutil.rmtree(destination)  # Only the known generated submission directory.
    code = destination / "代码"
    team = destination / "团队文档"
    personal = destination / "个人文档"
    for directory in [code, team, personal]:
        directory.mkdir(parents=True, exist_ok=True)
    for file in source_files(root):
        relative = file.relative_to(root)
        target = code / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(file, target)
    counts = {}
    for spec_file in sorted((root / "docs/final").glob("*.json")):
        spec = json.loads(spec_file.read_text(encoding="utf-8"))
        if "blocks" not in spec:
            continue
        filename = spec["filename"]
        dest = team if spec_file.stem == "team" else personal
        docx = root / "docs/final/documents" / filename
        pdf = root / "docs/evidence/render" / spec_file.stem / filename.replace(".docx", ".pdf")
        for file in [docx, pdf]:
            if not file.is_file():
                raise FileNotFoundError(f"缺少已渲染报告：{file}")
            shutil.copy2(file, dest / file.name)
        if dest == personal:
            text = "".join(x.get("text", "") for x in spec["blocks"] if x["type"] == "p")
            count = len(re.findall(r"[\u4e00-\u9fff]", text))
            assert count >= 600, filename
            counts[spec_file.stem] = count
    assert len(list(team.glob("*.docx"))) == 1 and len(list(team.glob("*.pdf"))) == 1
    assert len(list(personal.glob("*.docx"))) == 4 and len(list(personal.glob("*.pdf"))) == 4
    hashes = {}
    for file in sorted(destination.rglob("*")):
        if not file.is_file():
            continue
        rel = file.relative_to(destination)
        assert not (set(rel.parts) & EXCLUDED), str(rel)
        assert file.name != ".env" and "var" not in rel.parts, str(rel)
        if file.suffix in {".py", ".js", ".md", ".json", ".example", ".txt"}:
            assert not re.search(rb"sk-[A-Za-z0-9]{20,}", file.read_bytes()), "密钥模式：" + str(rel)
        hashes[str(rel)] = hashlib.sha256(file.read_bytes()).hexdigest()
    manifest = {"group": 14, "project": TITLE, "members": MEMBERS,
                "personal_report_hanzi": counts,
                "pending_user_action": "蔡铭达、王子越、江博琛按收尾任务核验个人报告；组长确认后提交学习通。",
                "sha256": hashes}
    (code / "提交校验.json").write_text(json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8")
    archive = destination.with_suffix(".zip")
    with zipfile.ZipFile(archive, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as zip_file:
        for file in sorted(destination.rglob("*")):
            if file.is_file():
                zip_file.write(file, file.relative_to(destination.parent))
    with zipfile.ZipFile(archive) as zip_file:
        assert zip_file.testzip() is None
        assert all(Path(name).parts[0] == ROOT_NAME for name in zip_file.namelist())
    print(json.dumps({"archive": str(archive), "bytes": archive.stat().st_size,
                      "files": len(hashes) + 1, "personal_hanzi": counts}, ensure_ascii=False, indent=2))
    return archive


if __name__ == "__main__":
    build(Path(__file__).resolve().parents[1])
