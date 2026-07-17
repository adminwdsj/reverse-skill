# 本包领域覆盖图（深度优先）

> 对照社区「几百个微 skill」：我们用 **少量深 skill + 路由 + ops** 覆盖主战场。  
> 日期：2026-07-17

## 域 → 本包入口

| 域 | PRIMARY / 模块 | 备注 |
|----|----------------|------|
| 移动 Android | `apk-reverse/` `mobile-reverse/` | |
| 移动 iOS | `mobile-reverse/` | |
| 二进制深挖 | `ida-reverse/` `radare2/` | |
| 通用 RE / 反调试 / OLLVM | `reverse-engineering/` | |
| .NET | `dotnet-reverse/` | |
| 前端 JS / 签名 | `js-reverse/` | |
| DSL/风控 VM | `reverse-engineering/dsl-vm-reverse/` | |
| 固件 IoT | `firmware-pentest/` | |
| 恶意样本 | `malware-analysis/` | |
| 渗透工具 | `pentest-tools/` (+ src-hunter) | |
| 多阶段攻击 | `attack-chain/` | |
| Pwn | `pwn-chain/` | |
| N-day 补丁 | `patch-diff-exploit/` | |
| EDR 研究 | `edr-bypass-re/` | |
| API | `api-security/` | |
| 供应链 SBOM | `supply-chain-security/` | |
| LLM/Agent | `llm-security/` | + `ops/skill-supply-chain.md` |
| 浏览器自动化 | `browser-automation/` | |
| 报告/图 | `docs-generator/` `diagram-generator/` | |
| 符号迁移 | `binary-diff/` | |
| 作战契约 | `ops/` | **特色** |
| CTF 编排 | `CTF-Sandbox-Orchestrator/` | |
| 密码学广覆盖 | 本地可选 `crypto-analysis`（gitignore） | 公开核心以 RE 模式文档为主 |

## 明确不整库并入的域（路由未命中时的策略）

| 域 | 策略 |
|----|------|
| OT/ICS | 联网搜方法论 → 提议新 skill 或外链 ToB/社区 |
| 纯 GRC/合规长文 | 不替代专业 GRC 工具；可写报告模板引用 |
| 800+ ATT&CK 微 skill | 用本表 + ATT&CK 可选标签（Finding 字段） |

## 与 MITRE ATT&CK（可选）

Finding 模板允许 `optional_attack: Txxxx`（见 `ops/evidence-finding-path.md`），**不强制**完整 ATT&CK 引擎。
