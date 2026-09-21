# 基于多智能体的生成式欺骗蜜罐网与态势感知系统

《应用软件开发》课程设计（网络安全产品方向）。系统将 TCP/SSH 仿真诱捕入口、LangGraph 主智能体编排、大模型子智能体高交互终端仿真、Neo4j 全局状态图、MCP 逻辑诱饵与 Web 态势面板组合为一个可单机运行的欺骗防御原型。

## 功能概览

- `TrafficEngine` 处理 TCP/SSH 仿真入口与异步会话生命周期，对输入做控制字符消毒与超时控制，仅在流量具备高交互语义时提升到智能体层。
- `MainAgent` 基于 LangGraph 状态图完成意图分析、欺骗规划、节点路由、子智能体调度和输出护栏，并把四角色决策轨迹推到态势面板。抢占式告警与模拟隔离在图外闭环。
- `SubAgent` 通过 OpenAI 兼容大模型接口生成高交互 Linux 终端响应；模型不可用或触发护栏时自动降级为确定性伪终端，保证演示可重复。
- `GraphDB` 将 Asset、Session、Identity、Event、Intent、Alert、Action 统一存入 Neo4j，支持按会话回放与即时合成下一跳诱饵资产（JIT 拓扑）。
- `MCP Trap` 同时提供 REST 与 JSON-RPC（`initialize` / `tools/list` / `tools/call`）。危险工具一经调用即产生高置信告警并触发模拟隔离。
- `Web Dashboard` 提供态势总览（含 WebSocket 实时事件）、SSH 会话回放、ATT&CK 观测矩阵与攻击者威胁画像。
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
│   ├── analytics         # ATT&CK 矩阵与可解释风险评分
│   ├── config.py         # 配置与大模型客户端
│   ├── database          # Neo4j 图存储
│   ├── network           # 诱捕流量入口
│   ├── realtime          # 进程内事件总线
│   └── trap              # MCP 风格逻辑诱饵
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
# 方式一：本机脚本（推荐课堂演示）
bash scripts/run_local.sh

# 方式二：手动启动
uvicorn main:app --host 0.0.0.0 --port 8000

# 方式三：应用也进容器（需先有 .env）
docker compose up --build
```

## 验证与演示

```bash
# 功能冒烟 + 注入一条完整演示杀伤链（demo-ssh-01）
ADMIN_API_TOKEN=<你的令牌> bash scripts/demo_smoke.sh

# 安全冒烟（鉴权、超长输入、危险命令、MCP 陷阱、消毒、密钥检查）
ADMIN_API_TOKEN=<你的令牌> bash scripts/security_smoke.sh

# 单元测试
python -m pytest
```

## 答辩口播（约 90 秒）

1. 打开 `http://127.0.0.1:8000/`，点右上角「注入演示序列」，输入 `.env` 里的 `ADMIN_API_TOKEN`。真实探索用 `ssh -i var/ssh/lure_ed25519 -p 2222 svc-backup@127.0.0.1`。
2. 看「决策流水线」：同一条命令依次经过意图分析、欺骗规划、终端仿真、输出护栏。规划理由是中文，不依赖大模型。
3. 看资产拓扑：侦察先进入预置主机 `web-pivot-01`，`ssh admin@10.0.5.2` 时当前节点高亮、刚经过的边流动，会话落到 `db-replica-01`。
4. 最后一步调用 MCP 陷阱 `bypass_security_guardrails`，告警和陷阱计数上升。阶段条上的链接打开该会话，回放时右侧决策轨迹跟着高亮。
5. 若老师问是不是多个大模型在辩论：规划员和护栏是确定性规则，终端演员才调用大模型；没配密钥时整段演示仍然成立。隔离是模拟动作，危险命令不会在宿主机执行。

手工交互演示：

```bash
# 真 SSH。主机密钥和登录私钥在首次启动时写到 var/ssh/，指纹见 /status。
ssh -i var/ssh/lure_ed25519 -p 2222 -o StrictHostKeyChecking=no svc-backup@127.0.0.1
# 进去之后可以 whoami / ls / ssh admin@10.0.5.2。内层地址不是第二个真 SSH 端口。
# 只支持口令的客户端：用户 svc-backup，口令为 HONEYPOT_SSH_PASSWORD（默认 honeypot）。

curl http://127.0.0.1:8000/mcp/tools   # MCP 诱饵工具列表
curl -X POST http://127.0.0.1:8000/mcp/tools/bypass_security_guardrails \
  -H 'Content-Type: application/json' -H 'x-agent-id: rogue-agent-01' \
  -d '{"arguments":{"target":"policy-engine"}}'   # 触发陷阱 -> 403 + critical 告警
```

## Web 页面

- 态势总览：`http://127.0.0.1:8000/`
- SSH 会话列表：`http://127.0.0.1:8000/sessions/view`
- 单会话回放与 AI 研判：`http://127.0.0.1:8000/session/view?session_id=<session_id>`
- ATT&CK 观测矩阵：`http://127.0.0.1:8000/attack/view`
- 攻击者威胁画像：`http://127.0.0.1:8000/profiles/view`
- OpenAPI 文档：`http://127.0.0.1:8000/docs`

## 主要接口

| 接口 | 方法 | 说明 | 鉴权 |
| --- | --- | --- | --- |
| `/healthz` `/status` | GET | 健康检查与运行状态 | 否 |
| `/sessions` `/sessions/{id}` | GET | 会话列表与明细（转录、意图） | 否 |
| `/sessions/{id}/world` | GET | 会话世界。跳过的主机都留在快照里。不带令牌时口令和私钥打码，带 `X-Admin-Token` 才看全文 | 全文需要令牌 |
| `/sessions/{id}/decisions` | GET | 四角色决策轨迹 | 否 |
| `/sessions/{id}/analysis` | GET | AI/启发式攻击研判 | 否 |
| `/sessions/{id}/analysis/controls` | POST | 研判联动控制（告警+隔离） | 是 |
| `/alerts` `/actions` `/payloads` `/graph/overview` | GET | 告警、动作、载荷、资产图 | 否 |
| `/attack/matrix` `/profiles` `/timeline` | GET | 攻击矩阵、来源画像、活动时间线 | 否 |
| `/ws/events` | WebSocket | 实时事件流（含回放缓冲） | 否 |
| `/demo/theater` | POST | 一键播放固定杀伤链（真实管道，每步 1.8 秒，慢于自动化判定阈值） | 是 |
| `/simulate` | POST | 注入模拟攻击载荷（演示/测试用） | 是 |
| `/history/purge` | POST | 清空历史（需 `confirm=true`） | 是 |
| `/mcp/tools` `/mcp/profile` | GET | MCP 诱饵工具面 | 否（诱捕面） |
| `/mcp/tools/{tool_name}` | POST | 调用工具；陷阱工具返回 403 并告警 | 否（诱捕面） |
| `/mcp` | POST | MCP JSON-RPC：`initialize`、`tools/list`、`tools/call` | 否（诱捕面） |

鉴权方式：请求头携带 `X-Admin-Token: <ADMIN_API_TOKEN>`。

## 安全边界说明

- 本系统为课程实验环境：诱捕面全部使用仿真资产与伪造数据。外层 2222 是真实 SSH 握手，登录后的 shell 和内层横向仍是仿真，不在宿主机执行。解释器能处理管道、`grep`/`head`、重定向和 `bash -c`，改动只落在会话世界。读凭证留在当前主机，只有 `ssh` 到内网地址才换主机，上一台的文件还在快照里。隔离动作默认 `simulate` 模式，不触碰真实网络。主机密钥和登录私钥由本蜜罐生成，放在 `var/ssh/`，不入库。
- 危险命令（rm/mkfs/reboot 等）仅返回仿真拒绝输出，不在宿主机执行；模型输出经护栏检查后才回写给连接方。
- 密钥仅从 `.env` 读取，`.env` 不入库。
