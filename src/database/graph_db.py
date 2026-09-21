from __future__ import annotations

import hashlib
import json
import logging
from typing import Any
from uuid import uuid4

from neo4j import AsyncGraphDatabase
from neo4j.exceptions import Neo4jError

from src.config import AppSettings


class GraphDB:
    def __init__(self, settings: AppSettings) -> None:
        self.settings = settings
        self.logger = logging.getLogger(self.__class__.__name__)
        self._driver = None

    async def connect(self) -> None:
        self._driver = AsyncGraphDatabase.driver(
            self.settings.neo4j_uri,
            auth=(self.settings.neo4j_user, self.settings.neo4j_password),
            encrypted=self.settings.neo4j_encrypted,
        )
        await self.healthcheck()

    async def close(self) -> None:
        if self._driver is not None:
            await self._driver.close()

    async def healthcheck(self) -> bool:
        if self._driver is None:
            raise RuntimeError("Neo4j driver is not initialized")
        async with self._driver.session(database=self.settings.neo4j_database) as session:
            record = await session.run("RETURN 1 AS ok")
            result = await record.single()
        return bool(result and result["ok"] == 1)

    async def init_schema(self) -> None:
        queries = [
            "CREATE CONSTRAINT asset_id_unique IF NOT EXISTS FOR (a:Asset) REQUIRE a.asset_id IS UNIQUE",
            "CREATE CONSTRAINT session_id_unique IF NOT EXISTS FOR (s:Session) REQUIRE s.session_id IS UNIQUE",
            "CREATE CONSTRAINT identity_id_unique IF NOT EXISTS FOR (i:Identity) REQUIRE i.identity_id IS UNIQUE",
            "CREATE CONSTRAINT alert_id_unique IF NOT EXISTS FOR (a:Alert) REQUIRE a.alert_id IS UNIQUE",
            "CREATE CONSTRAINT action_id_unique IF NOT EXISTS FOR (a:Action) REQUIRE a.action_id IS UNIQUE",
            "CREATE CONSTRAINT decision_id_unique IF NOT EXISTS FOR (d:Decision) REQUIRE d.decision_id IS UNIQUE",
            "CREATE INDEX asset_ip_index IF NOT EXISTS FOR (a:Asset) ON (a.ip_address)",
        ]
        async with self._driver.session(database=self.settings.neo4j_database) as session:
            for query in queries:
                cursor = await session.run(query)
                await cursor.consume()

    async def upsert_asset(
        self,
        *,
        asset_id: str,
        asset_type: str,
        ip_address: str,
        hostname: str,
        persona: str,
        exposure_level: str = "medium",
        metadata: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        query = """
        MERGE (a:Asset {asset_id: $asset_id})
        ON CREATE SET a.created_at = datetime()
        SET a.asset_type = $asset_type,
            a.ip_address = $ip_address,
            a.hostname = $hostname,
            a.persona = $persona,
            a.exposure_level = $exposure_level,
            a.metadata_json = $metadata_json,
            a.updated_at = datetime()
        RETURN a {
            .*,
            metadata: a.metadata_json
        } AS asset
        """
        params = {
            "asset_id": asset_id,
            "asset_type": asset_type,
            "ip_address": ip_address,
            "hostname": hostname,
            "persona": persona,
            "exposure_level": exposure_level,
            "metadata_json": json.dumps(metadata or {}, ensure_ascii=True),
        }
        record = await self._run_single(query, params)
        return self._hydrate_asset(record["asset"])

    async def link_assets(
        self,
        *,
        from_asset_id: str,
        to_asset_id: str,
        vector: str,
        confidence: float = 0.7,
        metadata: dict[str, Any] | None = None,
    ) -> None:
        query = """
        MATCH (src:Asset {asset_id: $from_asset_id})
        MATCH (dst:Asset {asset_id: $to_asset_id})
        MERGE (src)-[r:CAN_REACH {vector: $vector}]->(dst)
        SET r.confidence = $confidence,
            r.metadata_json = $metadata_json,
            r.updated_at = datetime()
        """
        await self._run(
            query,
            {
                "from_asset_id": from_asset_id,
                "to_asset_id": to_asset_id,
                "vector": vector,
                "confidence": confidence,
                "metadata_json": json.dumps(metadata or {}, ensure_ascii=True),
            },
        )

    async def create_or_update_session(
        self,
        *,
        session_id: str,
        source_ip: str,
        entry_asset_id: str,
        protocol: str,
        metadata: dict[str, Any] | None = None,
    ) -> None:
        query = """
        MERGE (s:Session {session_id: $session_id})
        ON CREATE SET s.created_at = datetime()
        SET s.protocol = $protocol,
            s.metadata_json = $metadata_json,
            s.last_seen = datetime()
        MERGE (i:Identity {identity_id: $source_ip})
        ON CREATE SET i.kind = 'external', i.created_at = datetime()
        SET i.last_seen = datetime()
        WITH s, i
        MATCH (a:Asset {asset_id: $entry_asset_id})
        MERGE (i)-[ri:INITIATED]->(s)
        SET ri.protocol = $protocol, ri.last_seen = datetime()
        MERGE (s)-[rs:TARGETS]->(a)
        SET rs.last_seen = datetime()
        """
        await self._run(
            query,
            {
                "session_id": session_id,
                "source_ip": source_ip,
                "entry_asset_id": entry_asset_id,
                "protocol": protocol,
                "metadata_json": json.dumps(metadata or {}, ensure_ascii=True),
            },
        )

    async def record_connection(
        self,
        *,
        session_id: str,
        source_ip: str,
        current_asset_id: str,
        protocol: str,
        payload: str,
    ) -> None:
        query = """
        MATCH (s:Session {session_id: $session_id})
        MATCH (a:Asset {asset_id: $current_asset_id})
        MERGE (e:Event {
            event_id: $event_id
        })
        SET e.kind = 'connection',
            e.direction = 'attacker_to_maze',
            e.protocol = $protocol,
            e.payload = $payload,
            e.prompt = '',
            e.source_ip = $source_ip,
            e.created_at = datetime()
        MERGE (s)-[:OBSERVED]->(e)
        MERGE (e)-[:TOUCHED]->(a)
        """
        await self._run(
            query,
            {
                "event_id": str(uuid4()),
                "session_id": session_id,
                "current_asset_id": current_asset_id,
                "protocol": protocol,
                "payload": payload,
                "source_ip": source_ip,
            },
        )

    async def record_response(
        self,
        *,
        session_id: str,
        current_asset_id: str,
        protocol: str,
        payload: str,
        prompt: str = "",
    ) -> None:
        query = """
        MATCH (s:Session {session_id: $session_id})
        MATCH (a:Asset {asset_id: $current_asset_id})
        MERGE (e:Event {
            event_id: $event_id
        })
        SET e.kind = 'response',
            e.direction = 'maze_to_attacker',
            e.protocol = $protocol,
            e.payload = $payload,
            e.prompt = $prompt,
            e.source_ip = 'maze',
            e.created_at = datetime()
        MERGE (s)-[:OBSERVED]->(e)
        MERGE (e)-[:TOUCHED]->(a)
        """
        await self._run(
            query,
            {
                "event_id": str(uuid4()),
                "session_id": session_id,
                "current_asset_id": current_asset_id,
                "protocol": protocol,
                "payload": payload,
                "prompt": prompt,
            },
        )

    async def record_intent(
        self,
        *,
        session_id: str,
        asset_id: str,
        category: str,
        confidence: float,
        raw_input: str,
        summary: str,
        metadata: dict[str, Any] | None = None,
    ) -> None:
        query = """
        MATCH (s:Session {session_id: $session_id})
        MATCH (a:Asset {asset_id: $asset_id})
        CREATE (i:Intent {
            intent_id: $intent_id,
            category: $category,
            confidence: $confidence,
            raw_input: $raw_input,
            summary: $summary,
            metadata_json: $metadata_json,
            created_at: datetime()
        })
        MERGE (s)-[:EMITTED]->(i)
        MERGE (i)-[:AGAINST]->(a)
        """
        await self._run(
            query,
            {
                "intent_id": str(uuid4()),
                "session_id": session_id,
                "asset_id": asset_id,
                "category": category,
                "confidence": confidence,
                "raw_input": raw_input,
                "summary": summary,
                "metadata_json": json.dumps(metadata or {}, ensure_ascii=True),
            },
        )

    async def synthesize_next_hop(
        self,
        *,
        source_asset_id: str,
        session_id: str,
        intent: dict[str, Any],
    ) -> dict[str, Any]:
        target_ip = str(intent.get("target_ip") or self._derive_ip(intent, session_id, source_asset_id))
        target_asset_id = f"asset:{target_ip}"
        existing_asset = await self.fetch_asset(target_asset_id)
        target_hostname = str(
            intent.get("target_hostname")
            or (existing_asset or {}).get("hostname")
            or self._derive_hostname(target_ip, intent)
        )
        target_role = str(
            (intent.get("target_role") or self._derive_role(intent))
            if existing_asset is None
            else existing_asset.get("asset_type", self._derive_role(intent))
        )
        persona = str(
            (existing_asset or {}).get("persona")
            or self._derive_persona(intent)
        )
        lure = self._derive_lure(intent)
        existing_metadata = dict((existing_asset or {}).get("metadata", {}))
        jit_synthesized = bool(existing_metadata.get("jit_synthesized", existing_asset is None))
        synthesis_metadata = {
            **existing_metadata,
            "lure": existing_metadata.get("lure", lure),
            "jit_synthesized": jit_synthesized,
            "synthesized_by": "main_agent",
            "source_asset_id": source_asset_id,
            "session_id": session_id,
            "intent_category": intent.get("category", "unknown"),
            "intent_confidence": float(intent.get("confidence", 0.0)),
            "synthesis_mode": "just_in_time",
            "cognitive_stage": self._derive_cognitive_stage(intent),
        }

        await self.upsert_asset(
            asset_id=target_asset_id,
            asset_type=target_role,
            ip_address=target_ip,
            hostname=target_hostname,
            persona=persona,
            exposure_level="high",
            metadata=synthesis_metadata,
        )
        await self.link_assets(
            from_asset_id=source_asset_id,
            to_asset_id=target_asset_id,
            vector=intent.get("category", "observed_move"),
            confidence=float(intent.get("confidence", 0.8)),
            metadata={
                "session_id": session_id,
                "jit_synthesized": True,
                "synthesis_mode": "just_in_time",
                "source_asset_id": source_asset_id,
                "intent_summary": intent.get("summary", "unknown"),
            },
        )
        query = """
        MATCH (s:Session {session_id: $session_id})
        MATCH (a:Asset {asset_id: $target_asset_id})
        MERGE (s)-[r:VISITED]->(a)
        SET r.last_seen = datetime()
        RETURN a {
            .*,
            metadata: a.metadata_json
        } AS asset
        """
        record = await self._run_single(
            query,
            {"session_id": session_id, "target_asset_id": target_asset_id},
        )
        return self._hydrate_asset(record["asset"])

    async def fetch_asset(self, asset_id: str) -> dict[str, Any] | None:
        query = """
        MATCH (a:Asset {asset_id: $asset_id})
        RETURN a {
            .*,
            metadata: a.metadata_json
        } AS asset
        """
        if self._driver is None:
            raise RuntimeError("Neo4j driver is not initialized")
        try:
            async with self._driver.session(database=self.settings.neo4j_database) as session:
                cursor = await session.run(query, {"asset_id": asset_id})
                record = await cursor.single()
                if record is None:
                    return None
                return self._hydrate_asset(record["asset"])
        except Neo4jError:
            self.logger.exception("Neo4j query failed")
            raise

    async def fetch_local_view(self, asset_id: str) -> dict[str, Any]:
        query = """
        MATCH (a:Asset {asset_id: $asset_id})
        OPTIONAL MATCH (a)-[r:CAN_REACH]->(n:Asset)
        RETURN
            a {
                .*,
                metadata: a.metadata_json
            } AS asset,
            collect(
                CASE
                    WHEN n IS NULL THEN NULL
                    ELSE n {
                        .*,
                        metadata: n.metadata_json
                    }
                END
            ) AS neighbors,
            collect(
                CASE
                    WHEN r IS NULL THEN NULL
                    ELSE {
                        vector: r.vector,
                        confidence: r.confidence,
                        metadata: r.metadata_json
                    }
                END
            ) AS edges
        """
        record = await self._run_single(query, {"asset_id": asset_id})
        asset = self._hydrate_asset(record["asset"])
        neighbors = [self._hydrate_asset(item) for item in record["neighbors"] if item]
        edges = [self._hydrate_edge(item) for item in record["edges"] if item]
        return {"asset": asset, "neighbors": neighbors, "edges": edges}

    async def record_alert(
        self,
        *,
        alert_type: str,
        severity: str,
        source: str,
        details: dict[str, Any],
        session_id: str | None = None,
    ) -> dict[str, Any]:
        alert_id = str(uuid4())
        query = """
        MERGE (a:Alert {alert_id: $alert_id})
        SET a.alert_type = $alert_type,
            a.severity = $severity,
            a.source = $source,
            a.details_json = $details_json,
            a.created_at = datetime()
        WITH a
        MERGE (i:Identity {identity_id: $source})
        ON CREATE SET i.kind = 'external', i.created_at = datetime()
        SET i.last_seen = datetime()
        MERGE (i)-[:TRIGGERED]->(a)
        """
        await self._run(
            query,
            {
                "alert_id": alert_id,
                "alert_type": alert_type,
                "severity": severity,
                "source": source,
                "details_json": json.dumps(details, ensure_ascii=True),
            },
        )
        if session_id:
            await self._run(
                """
                MATCH (s:Session {session_id: $session_id})
                MATCH (a:Alert {alert_id: $alert_id})
                MERGE (s)-[:RAISED]->(a)
                """,
                {"session_id": session_id, "alert_id": alert_id},
            )
        return {
            "alert_id": alert_id,
            "alert_type": alert_type,
            "severity": severity,
            "source": source,
            "details": details,
        }

    async def recent_alerts(self, limit: int = 20) -> list[dict[str, Any]]:
        query = """
        MATCH (a:Alert)
        RETURN a {
            .*,
            details: a.details_json
        } AS alert
        ORDER BY a.created_at DESC
        LIMIT $limit
        """
        records = await self._run_many(query, {"limit": limit})
        return [self._hydrate_alert(item["alert"]) for item in records]

    async def asset_count(self) -> int:
        record = await self._run_single("MATCH (a:Asset) RETURN count(a) AS total", {})
        return int(record["total"])

    async def recent_payloads(self, limit: int = 20) -> list[dict[str, Any]]:
        query = """
        MATCH (s:Session)-[:OBSERVED]->(e:Event {kind: 'connection'})-[:TOUCHED]->(a:Asset)
        RETURN {
            session_id: s.session_id,
            event_id: e.event_id,
            payload: e.payload,
            protocol: e.protocol,
            source_ip: e.source_ip,
            created_at: e.created_at,
            asset_id: a.asset_id,
            hostname: a.hostname
        } AS payload
        ORDER BY e.created_at DESC
        LIMIT $limit
        """
        records = await self._run_many(query, {"limit": limit})
        return [self._normalize_graph_value(item["payload"]) for item in records]

    async def recent_sessions(self, *, protocol: str | None = None, limit: int = 25) -> list[dict[str, Any]]:
        protocol_filter = "WHERE s.protocol = $protocol" if protocol else ""
        query = f"""
        MATCH (s:Session)<-[:INITIATED]-(i:Identity)
        OPTIONAL MATCH (s)-[:TARGETS]->(entry:Asset)
        {protocol_filter}
        CALL {{
            WITH s
            OPTIONAL MATCH (s)-[:VISITED]->(visited:Asset)
            RETURN collect(DISTINCT visited.hostname) AS visited_hosts
        }}
        CALL {{
            WITH s
            OPTIONAL MATCH (s)-[:OBSERVED]->(cmd:Event {{kind: 'connection'}})
            RETURN count(cmd) AS command_count,
                   max(cmd.created_at) AS last_command_at
        }}
        CALL {{
            WITH s
            OPTIONAL MATCH (s)-[:OBSERVED]->(last_cmd:Event {{kind: 'connection'}})
            RETURN last_cmd.payload AS last_payload
            ORDER BY last_cmd.created_at DESC
            LIMIT 1
        }}
        CALL {{
            WITH s
            OPTIONAL MATCH (s)-[visit:VISITED]->(current:Asset)
            RETURN current.hostname AS current_hostname
            ORDER BY visit.last_seen DESC
            LIMIT 1
        }}
        RETURN {{
            session_id: s.session_id,
            protocol: s.protocol,
            source_ip: i.identity_id,
            created_at: s.created_at,
            last_seen: s.last_seen,
            entry_asset_id: entry.asset_id,
            entry_hostname: entry.hostname,
            current_hostname: current_hostname,
            visited_hosts: visited_hosts,
            command_count: command_count,
            last_command_at: last_command_at,
            last_payload: last_payload
        }} AS session
        ORDER BY s.last_seen DESC
        LIMIT $limit
        """
        params: dict[str, Any] = {"limit": limit}
        if protocol:
            params["protocol"] = protocol
        records = await self._run_many(query, params)
        return [self._normalize_graph_value(item["session"]) for item in records]

    async def graph_overview(self) -> dict[str, Any]:
        asset_query = """
        MATCH (a:Asset)
        RETURN {
            asset_id: a.asset_id,
            hostname: a.hostname,
            ip_address: a.ip_address,
            asset_type: a.asset_type,
            persona: a.persona,
            exposure_level: a.exposure_level,
            metadata: a.metadata_json
        } AS asset
        ORDER BY a.asset_id ASC
        """
        edge_query = """
        MATCH (src:Asset)-[r:CAN_REACH]->(dst:Asset)
        RETURN {
            from_asset_id: src.asset_id,
            to_asset_id: dst.asset_id,
            vector: r.vector,
            confidence: r.confidence
        } AS edge
        ORDER BY src.asset_id ASC, dst.asset_id ASC
        """
        records_assets = await self._run_many(asset_query, {})
        records_edges = await self._run_many(edge_query, {})
        assets = [self._hydrate_asset(item["asset"]) for item in records_assets]
        edges = [self._normalize_graph_value(item["edge"]) for item in records_edges]
        type_counts: dict[str, int] = {}
        jit_synthesized_assets = 0
        for asset in assets:
            asset_type = str(asset.get("asset_type", "unknown"))
            type_counts[asset_type] = type_counts.get(asset_type, 0) + 1
            metadata = asset.get("metadata", {})
            if isinstance(metadata, dict) and metadata.get("jit_synthesized"):
                jit_synthesized_assets += 1
        return {
            "assets": assets,
            "edges": edges,
            "type_counts": type_counts,
            "jit_synthesized_assets": jit_synthesized_assets,
        }

    async def session_detail(self, session_id: str) -> dict[str, Any]:
        summary_query = """
        MATCH (s:Session {session_id: $session_id})<-[:INITIATED]-(i:Identity)
        OPTIONAL MATCH (s)-[:TARGETS]->(entry:Asset)
        RETURN {
            session_id: s.session_id,
            protocol: s.protocol,
            source_ip: i.identity_id,
            created_at: s.created_at,
            last_seen: s.last_seen,
            entry_asset_id: entry.asset_id,
            entry_hostname: entry.hostname
        } AS session
        """
        transcript_query = """
        MATCH (s:Session {session_id: $session_id})-[:OBSERVED]->(e:Event)-[:TOUCHED]->(a:Asset)
        RETURN {
            event_id: e.event_id,
            kind: e.kind,
            direction: e.direction,
            protocol: e.protocol,
            payload: e.payload,
            prompt: e.prompt,
            source_ip: e.source_ip,
            created_at: e.created_at,
            asset_id: a.asset_id,
            hostname: a.hostname
        } AS item
        ORDER BY e.created_at ASC
        """
        intent_query = """
        MATCH (s:Session {session_id: $session_id})-[:EMITTED]->(i:Intent)-[:AGAINST]->(a:Asset)
        RETURN {
            intent_id: i.intent_id,
            category: i.category,
            confidence: i.confidence,
            summary: i.summary,
            raw_input: i.raw_input,
            created_at: i.created_at,
            asset_id: a.asset_id,
            hostname: a.hostname
        } AS intent
        ORDER BY i.created_at ASC
        """
        summary = self._normalize_graph_value((await self._run_single(summary_query, {"session_id": session_id}))["session"])
        transcript_records = await self._run_many(transcript_query, {"session_id": session_id})
        intent_records = await self._run_many(intent_query, {"session_id": session_id})
        return {
            "session": summary,
            "transcript": [self._normalize_graph_value(item["item"]) for item in transcript_records],
            "intents": [self._normalize_graph_value(item["intent"]) for item in intent_records],
        }

    async def session_transcript(self, session_id: str) -> list[dict[str, Any]]:
        query = """
        MATCH (s:Session {session_id: $session_id})-[:OBSERVED]->(e:Event)-[:TOUCHED]->(a:Asset)
        RETURN {
            event_id: e.event_id,
            kind: e.kind,
            direction: e.direction,
            protocol: e.protocol,
            payload: e.payload,
            prompt: e.prompt,
            source_ip: e.source_ip,
            created_at: e.created_at,
            asset_id: a.asset_id,
            hostname: a.hostname
        } AS item
        ORDER BY e.created_at ASC
        """
        records = await self._run_many(query, {"session_id": session_id})
        return [self._normalize_graph_value(item["item"]) for item in records]

    async def session_intents(self, session_id: str) -> list[dict[str, Any]]:
        query = """
        MATCH (s:Session {session_id: $session_id})-[:EMITTED]->(i:Intent)-[:AGAINST]->(a:Asset)
        RETURN {
            intent_id: i.intent_id,
            category: i.category,
            confidence: i.confidence,
            summary: i.summary,
            raw_input: i.raw_input,
            created_at: i.created_at,
            asset_id: a.asset_id,
            hostname: a.hostname
        } AS intent
        ORDER BY i.created_at ASC
        """
        records = await self._run_many(query, {"session_id": session_id})
        return [self._normalize_graph_value(item["intent"]) for item in records]

    async def all_intents(self, limit: int = 500) -> list[dict[str, Any]]:
        """全局意图流，用于 ATT&CK 矩阵与画像聚合。"""
        query = """
        MATCH (s:Session)-[:EMITTED]->(i:Intent)-[:AGAINST]->(a:Asset)
        RETURN {
            intent_id: i.intent_id,
            session_id: s.session_id,
            category: i.category,
            confidence: i.confidence,
            summary: i.summary,
            raw_input: i.raw_input,
            created_at: i.created_at,
            asset_id: a.asset_id,
            hostname: a.hostname
        } AS intent
        ORDER BY i.created_at DESC
        LIMIT $limit
        """
        records = await self._run_many(query, {"limit": limit})
        return [self._normalize_graph_value(item["intent"]) for item in records]

    async def activity_timeline(self, limit: int = 120) -> list[dict[str, Any]]:
        """把意图、告警、动作合并为一条按时间倒序的全局攻击链时间线。"""
        query = """
        CALL {
            MATCH (s:Session)-[:EMITTED]->(i:Intent)-[:AGAINST]->(a:Asset)
            RETURN {
                kind: 'intent',
                ref_id: i.intent_id,
                session_id: s.session_id,
                source_ip: null,
                category: i.category,
                severity: null,
                title: i.category,
                detail: i.summary,
                raw_input: i.raw_input,
                hostname: a.hostname,
                created_at: i.created_at
            } AS item
            ORDER BY i.created_at DESC
            LIMIT $limit
        UNION ALL
            MATCH (id:Identity)-[:TRIGGERED]->(al:Alert)
            RETURN {
                kind: 'alert',
                ref_id: al.alert_id,
                session_id: null,
                source_ip: id.identity_id,
                category: null,
                severity: al.severity,
                title: al.alert_type,
                detail: al.details_json,
                raw_input: null,
                hostname: null,
                created_at: al.created_at
            } AS item
            ORDER BY al.created_at DESC
            LIMIT $limit
        UNION ALL
            MATCH (ac:Action)-[:CONTAINS]->(id:Identity)
            RETURN {
                kind: 'action',
                ref_id: ac.action_id,
                session_id: null,
                source_ip: id.identity_id,
                category: null,
                severity: null,
                title: ac.kind,
                detail: ac.reason,
                raw_input: null,
                hostname: null,
                created_at: ac.created_at
            } AS item
            ORDER BY ac.created_at DESC
            LIMIT $limit
        }
        RETURN item
        ORDER BY item.created_at DESC
        LIMIT $limit
        """
        records = await self._run_many(query, {"limit": limit})
        items = [self._normalize_graph_value(record["item"]) for record in records]
        # alert 的 detail 是 JSON 字符串，解析成对象方便前端直接用。
        for item in items:
            if item.get("kind") == "alert" and isinstance(item.get("detail"), str):
                try:
                    item["detail"] = json.loads(item["detail"])
                except (json.JSONDecodeError, TypeError):
                    item["detail"] = {}
        return items

    async def record_decision(
        self,
        *,
        session_id: str,
        asset_id: str,
        raw_input: str,
        strategy: str,
        steps: list[dict[str, Any]],
    ) -> dict[str, Any]:
        decision_id = str(uuid4())
        query = """
        MATCH (s:Session {session_id: $session_id})
        CREATE (d:Decision {
            decision_id: $decision_id,
            raw_input: $raw_input,
            asset_id: $asset_id,
            strategy: $strategy,
            steps_json: $steps_json,
            created_at: datetime()
        })
        MERGE (s)-[:DECIDED]->(d)
        RETURN d {
            .*,
            steps: d.steps_json
        } AS decision
        """
        record = await self._run_single(
            query,
            {
                "session_id": session_id,
                "decision_id": decision_id,
                "raw_input": raw_input[:500],
                "asset_id": asset_id,
                "strategy": strategy,
                "steps_json": json.dumps(steps, ensure_ascii=False),
            },
        )
        return self._hydrate_decision(record["decision"])

    async def session_decisions(self, session_id: str) -> list[dict[str, Any]]:
        query = """
        MATCH (s:Session {session_id: $session_id})-[:DECIDED]->(d:Decision)
        RETURN d {
            .*,
            steps: d.steps_json
        } AS decision
        ORDER BY d.created_at ASC
        """
        records = await self._run_many(query, {"session_id": session_id})
        return [self._hydrate_decision(item["decision"]) for item in records]

    async def quarantine_source(self, source: str, reason: str) -> dict[str, Any]:
        action_id = str(uuid4())
        query = """
        MERGE (a:Action {action_id: $action_id})
        SET a.kind = 'quarantine',
            a.reason = $reason,
            a.created_at = datetime()
        WITH a
        MERGE (i:Identity {identity_id: $source})
        ON CREATE SET i.kind = 'external', i.created_at = datetime()
        SET i.last_seen = datetime()
        MERGE (a)-[:CONTAINS]->(i)
        """
        await self._run(query, {"action_id": action_id, "source": source, "reason": reason})
        return {"action_id": action_id, "kind": "quarantine", "source": source, "reason": reason}

    async def recent_actions(self, limit: int = 20) -> list[dict[str, Any]]:
        query = """
        MATCH (a:Action)-[:CONTAINS]->(i:Identity)
        RETURN {
            action_id: a.action_id,
            kind: a.kind,
            reason: a.reason,
            created_at: a.created_at,
            source: i.identity_id
        } AS action
        ORDER BY a.created_at DESC
        LIMIT $limit
        """
        records = await self._run_many(query, {"limit": limit})
        return [self._normalize_graph_value(item["action"]) for item in records]

    async def purge_history(self) -> dict[str, int]:
        counts = {
            "sessions": 0,
            "events": 0,
            "intents": 0,
            "decisions": 0,
            "alerts": 0,
            "actions": 0,
            "identities": 0,
            "jit_assets": 0,
            "jit_edges": 0,
        }

        count_queries = {
            "sessions": "MATCH (s:Session) RETURN count(s) AS total",
            "events": "MATCH (e:Event) RETURN count(e) AS total",
            "intents": "MATCH (i:Intent) RETURN count(i) AS total",
            "decisions": "MATCH (d:Decision) RETURN count(d) AS total",
            "alerts": "MATCH (a:Alert) RETURN count(a) AS total",
            "actions": "MATCH (a:Action) RETURN count(a) AS total",
            "identities": "MATCH (i:Identity) RETURN count(i) AS total",
            "jit_assets": "MATCH (a:Asset) WHERE a.metadata_json CONTAINS '\"jit_synthesized\": true' RETURN count(a) AS total",
            "jit_edges": "MATCH ()-[r:CAN_REACH]->() WHERE r.metadata_json CONTAINS '\"jit_synthesized\": true' RETURN count(r) AS total",
        }
        for key, query in count_queries.items():
            record = await self._run_single(query, {})
            counts[key] = int(record["total"])

        delete_queries = [
            "MATCH ()-[r:CAN_REACH]->() WHERE r.metadata_json CONTAINS '\"jit_synthesized\": true' DELETE r",
            "MATCH (s:Session) DETACH DELETE s",
            "MATCH (e:Event) DETACH DELETE e",
            "MATCH (d:Decision) DETACH DELETE d",
            "MATCH (i:Intent) DETACH DELETE i",
            "MATCH (a:Alert) DETACH DELETE a",
            "MATCH (a:Action) DETACH DELETE a",
            "MATCH (i:Identity) DETACH DELETE i",
            "MATCH (a:Asset) WHERE a.metadata_json CONTAINS '\"jit_synthesized\": true' DETACH DELETE a",
        ]
        for query in delete_queries:
            await self._run(query, {})
        return counts

    async def _run(self, query: str, params: dict[str, Any]) -> None:
        if self._driver is None:
            raise RuntimeError("Neo4j driver is not initialized")
        try:
            async with self._driver.session(database=self.settings.neo4j_database) as session:
                cursor = await session.run(query, params)
                await cursor.consume()
        except Neo4jError:
            self.logger.exception("Neo4j query failed")
            raise

    async def _run_single(self, query: str, params: dict[str, Any]) -> dict[str, Any]:
        if self._driver is None:
            raise RuntimeError("Neo4j driver is not initialized")
        try:
            async with self._driver.session(database=self.settings.neo4j_database) as session:
                cursor = await session.run(query, params)
                record = await cursor.single()
                if record is None:
                    raise RuntimeError("Neo4j query returned no records")
                return dict(record)
        except Neo4jError:
            self.logger.exception("Neo4j query failed")
            raise

    async def _run_many(self, query: str, params: dict[str, Any]) -> list[dict[str, Any]]:
        if self._driver is None:
            raise RuntimeError("Neo4j driver is not initialized")
        try:
            async with self._driver.session(database=self.settings.neo4j_database) as session:
                cursor = await session.run(query, params)
                records = await cursor.data()
                return [dict(item) for item in records]
        except Neo4jError:
            self.logger.exception("Neo4j query failed")
            raise

    def _derive_ip(self, intent: dict[str, Any], session_id: str, source_asset_id: str) -> str:
        category = intent.get("category", "unknown")
        base_map = {
            "lateral_movement": ("10.0.5.", 2),
            "credential_access": ("10.0.6.", 10),
            "collection": ("10.0.7.", 20),
            "tool_transfer": ("10.0.8.", 30),
            "cloud_recon": ("10.0.9.", 40),
        }
        subnet_prefix, minimum_host = base_map.get(category, ("10.0.5.", 50))
        seed = f"{session_id}|{source_asset_id}|{category}|{intent.get('summary', '')}"
        digest = hashlib.sha256(seed.encode("utf-8")).hexdigest()
        host_octet = minimum_host + (int(digest[:2], 16) % 120)
        return f"{subnet_prefix}{host_octet}"

    def _derive_hostname(self, target_ip: str, intent: dict[str, Any]) -> str:
        category = intent.get("category", "unknown")
        hostname_map = {
            "lateral_movement": "db-replica-01",
            "credential_access": "vault-cache-02",
            "collection": "finance-archive-01",
            "tool_transfer": "oss-sync-bridge",
            "cloud_recon": "ram-audit-proxy",
        }
        return hostname_map.get(category, f"node-{target_ip.replace('.', '-')}")

    def _derive_role(self, intent: dict[str, Any]) -> str:
        category = intent.get("category", "unknown")
        role_map = {
            "lateral_movement": "linux_server",
            "credential_access": "secret_store",
            "collection": "file_server",
            "tool_transfer": "oss_gateway",
            "cloud_recon": "cloud_proxy",
        }
        return role_map.get(category, "linux_server")

    def _derive_persona(self, intent: dict[str, Any]) -> str:
        category = intent.get("category", "unknown")
        if category == "lateral_movement":
            return "damaged_linux_terminal"
        if category == "credential_access":
            return "misconfigured_secret_store"
        if category == "collection":
            return "archive_server_with_leaky_exports"
        if category == "tool_transfer":
            return "oss_bridge_host"
        if category == "cloud_recon":
            return "cloud_control_proxy"
        return "compromised_linux_terminal"

    def _derive_lure(self, intent: dict[str, Any]) -> str:
        category = intent.get("category", "unknown")
        lures = {
            "lateral_movement": "stolen SSH key appears to grant deeper access",
            "credential_access": "plaintext service credential cache under /srv/backups",
            "collection": "financial archives and tarballs with customer exports",
            "tool_transfer": "OSS sync scripts and cloud copy credentials",
            "cloud_recon": "temporary RAM and STS audit tooling",
        }
        return lures.get(category, "partial internal topology and noisy service logs")

    def _derive_cognitive_stage(self, intent: dict[str, Any]) -> str:
        category = str(intent.get("category", "unknown"))
        stage_map = {
            "discovery": "environment_validation",
            "credential_access": "secret_harvest",
            "lateral_movement": "pivot_expansion",
            "tool_transfer": "payload_staging",
            "cloud_recon": "control_plane_enumeration",
            "collection": "data_staging",
        }
        return stage_map.get(category, "interactive_probe")

    def _hydrate_asset(self, asset: dict[str, Any]) -> dict[str, Any]:
        hydrated = self._normalize_graph_value(dict(asset))
        metadata = hydrated.get("metadata")
        if isinstance(metadata, str):
            hydrated["metadata"] = json.loads(metadata or "{}")
        return hydrated

    def _hydrate_edge(self, edge: dict[str, Any]) -> dict[str, Any]:
        hydrated = self._normalize_graph_value(dict(edge))
        metadata = hydrated.get("metadata")
        if isinstance(metadata, str):
            hydrated["metadata"] = json.loads(metadata or "{}")
        return hydrated

    def _hydrate_decision(self, decision: dict[str, Any]) -> dict[str, Any]:
        hydrated = self._normalize_graph_value(dict(decision))
        steps = hydrated.get("steps")
        if isinstance(steps, str):
            hydrated["steps"] = json.loads(steps or "[]")
        return hydrated

    def _hydrate_alert(self, alert: dict[str, Any]) -> dict[str, Any]:
        hydrated = self._normalize_graph_value(dict(alert))
        details = hydrated.get("details")
        if isinstance(details, str):
            hydrated["details"] = json.loads(details or "{}")
        return hydrated

    def _normalize_graph_value(self, value: Any) -> Any:
        if isinstance(value, dict):
            return {key: self._normalize_graph_value(item) for key, item in value.items()}
        if isinstance(value, list):
            return [self._normalize_graph_value(item) for item in value]
        if hasattr(value, "iso_format") and callable(value.iso_format):
            return value.iso_format()
        if hasattr(value, "isoformat") and callable(value.isoformat):
            return value.isoformat()
        return value
