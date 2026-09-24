"""Wait for configured Neo4j using the same settings/interpreter as the app."""
from pathlib import Path
import sys
import time
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from neo4j import GraphDatabase
from src.config import AppSettings


def main() -> int:
    settings = AppSettings()
    for _ in range(30):
        try:
            with GraphDatabase.driver(settings.neo4j_uri,
                    auth=(settings.neo4j_user, settings.neo4j_password),
                    connection_timeout=2) as driver:
                driver.verify_connectivity()
            print("Neo4j 已就绪。")
            return 0
        except Exception:
            time.sleep(2)
    print("Neo4j 连接失败：核对 URI、端口和密码；容器部署请检查 docker compose logs neo4j。", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
