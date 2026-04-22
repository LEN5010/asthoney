# Generative Infinite Deception Maze

面向 2026 A-ST 赛项的多智能体生成式欺骗蜜网原型。该实现将轻量级网络流量接入、LangGraph 主智能体编排、Qwen 子智能体高交互终端仿真、Neo4j 全局状态图以及 MCP 逻辑诱饵组合为一个可本地运行的生产风格骨架。

## 项目目录

```text
.
├── .env.example
├── README.md
├── main.py
├── requirements.txt
├── static
│   ├── index.html
│   ├── session.html
│   └── sessions.html
└── src
    ├── __init__.py
    ├── agents
    │   ├── __init__.py
    │   ├── main_agent.py
    │   └── sub_agent.py
    ├── config.py
    ├── database
    │   ├── __init__.py
    │   └── graph_db.py
    ├── network
    │   ├── __init__.py
    │   └── traffic_engine.py
    └── trap
        ├── __init__.py
        └── mcp_trap.py
```

## 架构摘要

- `TrafficEngine` 负责处理基础 TCP/SSH 入口与异步会话生命周期，仅在流量被识别为高交互语义负载时才提升到智能体层。
- `MainAgent` 维护全局状态图与多节点路由逻辑，使用 LangGraph 将意图分析、欺骗节点合成、子智能体切换解耦。
- `SubAgent` 通过 DashScope `qwen-max` 生成高交互 Linux 终端响应，同时保留确定性降级逻辑，避免 API 抖动导致服务中断。
- `GraphDB` 将资产、会话、意图、告警和抢占式隔离动作统一存储于 Neo4j，用于支撑动态横向移动诱捕。
- `MCP Trap` 暴露不应被合法 Agent 调用的危险工具，一旦触发即产生高置信度告警并触发隔离动作。
- `Web Dashboard` 提供态势总览、SSH 会话列表、单会话日志查看以及 AI 自动研判页面。
- `AI Session Analysis` 基于 DashScope 对攻击者行为提炼战术手段、攻击目标，并评估是否疑似非真人测试 Agent；当模型不可用时自动退回启发式分析。

## 本地运行

1. 创建 Python 3.11+ 虚拟环境并安装依赖。

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
```

2. 启动 Neo4j。

如果本机已安装 Neo4j Desktop 或 Neo4j Community，可直接使用默认 `bolt://127.0.0.1:7687`。使用 Docker 时可执行：

```bash
docker run -d \
  --name maze-neo4j \
  -p 7474:7474 \
  -p 7687:7687 \
  -e NEO4J_AUTH=neo4j/please_change_me \
  neo4j:5.23
```

3. 配置 `.env` 中的 `DASHSCOPE_API_KEY` 与 `NEO4J_PASSWORD`。

4. 启动服务。

```bash
uvicorn main:app --host 0.0.0.0 --port 8000
```

## 一键验证

启动后可以通过以下接口和端口验证系统行为：

```bash
curl http://127.0.0.1:8000/healthz
curl http://127.0.0.1:8000/status
curl http://127.0.0.1:8000/sessions
curl -X POST http://127.0.0.1:8000/simulate \
  -H 'Content-Type: application/json' \
  -d '{"payload":"ssh admin@10.0.5.2","protocol":"ssh","source_ip":"198.51.100.9","destination_port":2222}'
```

可使用 `nc` 对诱捕端口进行交互：

```bash
nc 127.0.0.1 2222
nc 127.0.0.1 2323
```

MCP 逻辑诱饵接口示例：

```bash
curl http://127.0.0.1:8000/mcp/tools
curl -X POST http://127.0.0.1:8000/mcp/tools/bypass_security_guardrails \
  -H 'Content-Type: application/json' \
  -H 'x-agent-id: rogue-agent-01' \
  -d '{"arguments":{"target":"policy-engine","mode":"off"}}'
```

## WebView 页面

- 总览态势面板: `http://127.0.0.1:8000/`
- SSH 会话列表页: `http://127.0.0.1:8000/sessions/view`
- 单条 SSH 对话详情页: `http://127.0.0.1:8000/session/view?session_id=<session_id>`

## 会话日志与 AI 分析接口

```bash
curl http://127.0.0.1:8000/sessions
curl http://127.0.0.1:8000/sessions/<session_id>
curl http://127.0.0.1:8000/sessions/<session_id>/analysis
```

`/sessions/<session_id>/analysis` 会输出：

- `summary`: 攻击过程摘要
- `objective`: 当前判断的攻击者目的
- `techniques`: 提炼出的战术手段
- `likely_non_human_test_agent`: 是否疑似非真人测试 Agent
- `likely_non_human_reasons`: 判定依据
- `suggested_actions`: 后续防御建议

## 运行说明

- FastAPI 控制面默认监听 `8000`。
- 异步蜜罐入口默认监听 `2222` 和 `2323`。
- 如果未配置 `DASHSCOPE_API_KEY`，子智能体仍可运行，但会退化为确定性伪终端响应。
- Neo4j 中会持续积累 `Asset`、`Session`、`Intent`、`Alert`、`Action` 与 `Event` 节点，其中 `Event` 同时记录攻击者输入和蜜罐响应，可用于逐条 SSH 对话回放。
- `/payloads` 侧重展示最新攻击输入，`/sessions` 与 `/sessions/<session_id>` 则用于完整会话审计与前端日志回放。
