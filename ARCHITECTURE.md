# 架构说明

这是本地 MCP 攻防实验室：以良性/恶意 stdio MCP server 和脚本化 agent 复现工具投毒、rug pull、工具遮蔽，并由宿主网关实施 Rule of Two、schema pin、审批令牌与审计。

## 核心模块及职责

- `mcp_servers/benign|malicious`：受控的演示工具与攻击样例。
- `host/gateway.py`、`tool_router.py`：所有工具调用的唯一通路。
- `policy/`：能力、角色、完整性 pin、描述检查、审批与锁。
- `observability/`：JSONL 审计、Sigma 规则和数据流报告；`attacks/`、`tests/` 验证基线与加固差异。

数据流：agent -> HostGateway -> 策略判定/必要审批 -> 本地模拟工具 -> 审计记录。默认无网络外发，敏感文件和邮箱均为模拟件。

## 关键依赖和外部服务

Python、MCP、PyYAML、httpx；可选 OpenAI 兼容 API（`ASL_OPENAI_API_KEY`），默认禁用。

## 技术债务

实验运行会生成审计、pin、outbox 工件；应在 CI 采用临时目录并确保示例工件不被误当作生产数据。
