# kiro.rs

Rust 编写的 Anthropic Claude API 兼容代理，将 Anthropic API 请求转换为 Kiro API 请求。

## 构建与测试

本机无 Rust toolchain，cargo 经 docker 镜像 `rust:1.92-alpine` 跑——**不是** `docker compose`：compose 服务名为 `kiro-rs`（非 `kiro`）且用 runtime 发布镜像，**不含 cargo**，仅用于起服务。

```bash
# 测试（唯一阻塞门槛）
docker run --rm -v "$PWD":/app -w /app rust:1.92-alpine sh -c 'cargo test --workspace'

# 格式化（merge 前必跑——CI 的 Check formatting 会拦）
docker run --rm -v "$PWD":/app -w /app rust:1.92-alpine sh -c 'rustup component add rustfmt && cargo fmt'

# lint（非阻塞，仅参考；alpine 需先装组件）
docker run --rm -v "$PWD":/app -w /app rust:1.92-alpine sh -c 'rustup component add clippy && cargo clippy'

# 构建发布镜像 / 起服务（compose）
docker compose build && docker compose up -d
```

阻塞门槛仅 `cargo test`，clippy 警告不阻塞合并（仓库有存量 clippy）；但 `cargo fmt` 失败应修。

## 项目结构

```
src/
├── main.rs              # 入口
├── token.rs             # token 计数（输入/输出 token 估算）
├── anthropic/           # Anthropic API 兼容层
│   ├── handlers.rs      # 请求处理
│   ├── converter.rs     # Anthropic → Kiro 请求转换
│   ├── stream.rs        # SSE 流式响应
│   ├── prompt_cache.rs  # 本地 prompt cache 模拟
│   ├── websearch.rs     # WebSearch 工具转换
│   └── router.rs        # 路由定义
├── kiro/                # Kiro 上游交互
│   ├── token_manager.rs # OAuth token 自动刷新
│   ├── provider.rs      # 多凭据管理 / 负载均衡
│   ├── endpoint/        # 上游 API 端点
│   └── model/           # Kiro 请求/响应模型
├── model/               # 共享模型
│   ├── config.rs        # 应用配置
│   ├── arg.rs           # CLI 参数（--config / --credentials / --models）
│   └── registry.rs      # 模型注册表（ModelRegistry，从 models.toml 加载）
├── admin/               # Admin API + Web UI
└── admin_ui/            # 前端（嵌入式）
models.toml              # 模型配置（可外部覆盖，内嵌 fallback）
```

## 发版

轻量 tag 触发 CI：格式 `vYYYY.0M.0D.N`（零填充 CalVer），如 `v2026.03.01.1`。

## 文档分层

- **公开文档**：放 repo 内（本文件 + README），随代码版本走
- **私有文档**：放 `~/.claude/projects/<project-key>/docs/`，通过本文件末尾 `@import` 自动加载索引

repo 内不保留 `docs/` 目录，所有设计文档、实现细节归私有侧管理。

## 关键约定

- 模型映射由 `models.toml` 配置驱动（`ModelRegistry`），新增模型只改配置文件重启生效，无需改代码；文件不存在时 fallback 内嵌默认，文件存在但语法错误时 fail-fast 退出
- 请求转换流程：Anthropic 格式 → build_history → validate_tool_pairing / remove_orphaned（配对校验）→ 发送
- prompt cache 是纯本地模拟（进程内 HashMap），从不向 Kiro 透传 cache_control
- 空 tool_result 统一替换为占位文本，不发空串
- 空 tool description 在 `convert_tools` 出口兜底填 `Tool: {name}` 占位——Anthropic 原生 description 对自定义工具是 optional（空串合法），但上游 Kiro/Bedrock `toolSpecification.description` 硬约束 length>=1，空串 400 拒整个请求；不删字段（缺失=length 0 同样拒）、不删工具（历史 tool_use 落单撞 validate_tool_pairing）；占位非空白避免诱导退化（退化行为见 #26）（#46）
- 历史保留结构化 toolUses/toolResults，纯 tool_use 轮 content 留空串——绝不注入空格占位空壳轮（会诱导模型只回空格/句号，CC 长会话死循环根因，#26）
- 转换层引入降级/裁剪/占位/改写前须黑盒实测背书，禁止基于推断（#26）
- 业务长响应（generateAssistantResponse 流式/非流式）走 idle/read 超时（930s，>ALB 900），不设全局总超时——上游在吐字节就不超时；短请求（MCP/WebSearch/oauth/count_tokens）保留 total 死线，与业务 client 按 ClientKind 解耦防 Slowloris（#31）
- 上游 body 读错误诊断须先判 is_timeout 再分类——reqwest 把 body 读超时无差别包成 Decode（Display 恒为 "error decoding response body"），真因藏 source chain（reqwest #2839，#31）
- tool_result 内的 image content block 提取后 hoist 到当轮 `userInputMessage.images`（复用 user 贴图路径），tool_result content 保留纯文本、仅图无文时塞占位——上游 `toolResults[].content` 只认 text 不承载图片；图片与 tool_result 落同一 userInputMessage、下游 with_images 零改动（kiro-go 源码 + 黑盒 A/B + e2e 三重背书，#35）
- 日志默认 JSON Lines（生产排障用 jq），`LOG_FORMAT=text` 回退人类可读文本（本地开发）；请求结局靠显式事件观测而非 span CLOSE 携带 late-record 字段——middleware 发 `request completed`(带 status) 覆盖全量请求，每个业务终结点发 `request outcome`(带 req_outcome=success 或 anthropic error_type)，新增终结点须同步补发结局事件、且勿在已走 map_provider_error 的路径重复发；大 body debug 日志统一挂 `target:"kiro_rs::payload"` 供一键静音、必经 `truncate_for_log` 截断；上游 body 入日志一律 `upstream_body=%truncate` 结构化字段，不整段插值进 message（细节见私有 docs/debug-log-observability.md，#71）
- 工具 schema 的 `$ref`/`$defs` 原样透传给上游，不做本地展开；normalize 只保证顶层 `type:object`。上游普遍认 `$ref`/`$defs`（黑盒两轮 12 种形态实测 11 种通过），本地展开是净负债——曾在递归/自引用 schema 上把 `type` 字段展开成畸形嵌套对象，反而制造出上游会拒绝的 400 `TOOL_SCHEMA_INVALID`（细节见私有 docs/issue92-schema-ref-expansion-regression.md，#74）

## 私有文档

@~/.claude/projects/-Users-woodragon-Work-github-kiro-rs/CLAUDE.md
