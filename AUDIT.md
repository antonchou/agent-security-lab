# 安全与质量审计

## 严重

- 无已确认项。本项目故意包含恶意 MCP 描述和假密钥，用于本地攻防测试；`lab_fs/sensitive/id_rsa.fake` 与 PoC 中 `sk-lab-fake-*` 均为 README 声明的合成数据，不是凭据泄露。

## 中等

- `configs/lab.baseline.yaml`：基线 profile 按设计不执行 pin、审批和冲突拒绝。不得用于不可信 MCP 或真实副作用环境；建议 CLI 对 baseline 增加醒目警告，并要求 `--unsafe-lab` 显式确认。
- `src/agent_security_lab/config.py:150`：可启用外部 OpenAI 兼容服务。建议在启用时明确日志脱敏策略、网络出口限制和密钥轮换。

## 轻微

- `Makefile:clean` 使用递归删除命令，仅应在实验目录中运行；Windows 开发者需要等价安全脚本。测试包含 unit/integration/attack 场景，未见覆盖率阈值，建议加入 pytest-cov。
