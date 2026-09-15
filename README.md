# 基于多智能体的生成式欺骗蜜罐网与态势感知系统

《应用软件开发》课程设计（网络安全产品方向）。系统将 TCP/SSH 仿真诱捕入口、LangGraph 主智能体编排、大模型子智能体高交互终端仿真、Neo4j 全局状态图、MCP 逻辑诱饵与 Web 态势面板组合为一个可单机运行的欺骗防御原型。

## 功能概览

- `TrafficEngine` 处理 TCP/SSH 仿真入口与异步会话生命周期，对输入做控制字符消毒与超时控制，仅在流量具备高交互语义时提升到智能体层。
- `MainAgent` 基于 LangGraph 状态图完成意图分析、欺骗节点路由与子智能体调度，并执行抢占式告警与模拟隔离闭环。
- `SubAgent` 通过 OpenAI 兼容大模型接口生成高交互 Linux 终端响应；模型不可用或触发护栏时自动降级为确定性伪终端，保证演示可重复。
- `GraphDB` 将 Asset、Session、Identity、Event、Intent、Alert、Action 统一存入 Neo4j，支持按会话回放与即时合成下一跳诱饵资产（JIT 拓扑）。
- `MCP Trap` 暴露对自主 Agent 具有语义诱惑性的危险工具，一经调用即产生高置信告警并触发模拟隔离。
- `Web Dashboard` 提供态势总览、SSH 会话列表、单会话终端回放与 AI 自动研判页面。
- 控制面敏感接口（`/simulate`、`/history/purge`、会话研判控制）由 `X-Admin-Token` 令牌鉴权保护（安全需求 SR-02）。

## 项目目录

```text
.
├── .env.example          # 配置模板（复制为 .env 后填写）
├── docker-compose.yml    # 一键启动 Neo4j
├── main.py               # FastAPI 控制面入口
├── pytest.ini
├── requirements.txt
├── scripts
│   ├── demo_smoke.sh     # 功能冒烟（演示数据注入）
│   └── security_smoke.sh # 安全冒烟（对应报告表 8-2）
├── src
│   ├── agents            # 主/子智能体
│   ├── config.py         # 配置与大模型客户端
│   ├── database          # Neo4j 图存储
│   ├── network           # 诱捕流量入口
│   └── trap              # MCP 逻辑诱饵
├── static                # Web 态势面板（原生 HTML/CSS/JS）
└── tests                 # 单元测试
```

## 快速开始

1. 启动 Neo4j（二选一）：

```bash
# 方式一：docker compose（推荐，密码取 .env 中的 NEO4J_PASSWORD）
docker compose up -d neo4j

# 方式二：已有本地 Neo4j 或历史容器
docker start maze-neo4j
```

2. 准备 Python 3.11+ 环境并安装依赖：

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
```

3. 编辑 `.env`：

- `NEO4J_PASSWORD`：与 Neo4j 一致。
- `ADMIN_API_TOKEN`：控制面管理令牌（必填，否则敏感接口不可用）。
- `DASHSCOPE_API_KEY` / `DASHSCOPE_BASE_URL` / `DASHSCOPE_MODEL`：可选。支持 DashScope 原生 SDK 或任意 OpenAI 兼容网关；不配置时终端仿真与研判自动降级为确定性/启发式模式，核心功能不受影响。

4. 启动服务：

```bash
uvicorn main:app --host 0.0.0.0 --port 8000
```

## 验证与演示

```bash
# 功能冒烟 + 注入演示数据（demo-ssh-01 会话）
ADMIN_API_TOKEN=<你的令牌> bash scripts/demo_smoke.sh

# 安全冒烟（鉴权、超长输入、危险命令、MCP 陷阱、消毒、密钥检查）
ADMIN_API_TOKEN=<你的令牌> bash scripts/security_smoke.sh

# 单元测试
python -m pytest
```

手工交互演示：

```bash
nc 127.0.0.1 2222        # SSH 仿真入口，逐条输入 whoami / ls / ssh admin@10.0.5.2 等
curl http://127.0.0.1:8000/mcp/tools   # MCP 诱饵工具列表
curl -X POST http://127.0.0.1:8000/mcp/tools/bypass_security_guardrails \
  -H 'Content-Type: application/json' -H 'x-agent-id: rogue-agent-01' \
  -d '{"arguments":{"target":"policy-engine"}}'   # 触发陷阱 -> 403 + critical 告警
```

## Web 页面

- 态势总览：`http://127.0.0.1:8000/`
- SSH 会话列表：`http://127.0.0.1:8000/sessions/view`
- 单会话回放与 AI 研判：`http://127.0.0.1:8000/session/view?session_id=<session_id>`
- OpenAPI 文档：`http://127.0.0.1:8000/docs`

## 主要接口

| 接口 | 方法 | 说明 | 鉴权 |
| --- | --- | --- | --- |
| `/healthz` `/status` | GET | 健康检查与运行状态 | 否 |
| `/sessions` `/sessions/{id}` | GET | 会话列表与明细（转录、意图） | 否 |
| `/sessions/{id}/analysis` | GET | AI/启发式攻击研判 | 否 |
| `/sessions/{id}/analysis/controls` | POST | 研判联动控制（告警+隔离） | 是 |
| `/alerts` `/actions` `/payloads` `/graph/overview` | GET | 告警、动作、载荷、资产图 | 否 |
| `/simulate` | POST | 注入模拟攻击载荷（演示/测试用） | 是 |
| `/history/purge` | POST | 清空历史（需 `confirm=true`） | 是 |
| `/mcp/tools` `/mcp/profile` | GET | MCP 诱饵工具面 | 否（诱捕面） |
| `/mcp/tools/{tool_name}` | POST | 调用工具；陷阱工具返回 403 并告警 | 否（诱捕面） |

鉴权方式：请求头携带 `X-Admin-Token: <ADMIN_API_TOKEN>`。

## 安全边界说明

- 本系统为课程实验环境：诱捕面全部使用仿真资产与伪造数据，SSH 入口为协议横幅仿真而非完整 SSH 协议栈；隔离动作默认 `simulate` 模式，不触碰真实网络。
- 危险命令（rm/mkfs/reboot 等）仅返回仿真拒绝输出，不在宿主机执行；模型输出经护栏检查后才回写给连接方。
- 密钥仅从 `.env` 读取，`.env` 不入库。
