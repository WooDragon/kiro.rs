# kiro-rs

> 基于 [hank9999/kiro.rs](https://github.com/hank9999/kiro.rs) 的维护分支，重点补足多凭据场景下的稳定性与 Anthropic 客户端兼容性。

这个 fork 不再重复维护一份与上游几乎相同的长篇 README。除了下文列出的增强点外，其余功能、配置项、API 兼容性、Docker 用法与部署方式请优先参考上游项目文档。

## 相比上游的优化

### 1. `balanced` 模式会话粘性

- 会从请求里的会话信息提取 `conversationId` / session ID，并在 `balanced` 模式下把同一会话尽量固定到同一凭据
- 只有请求成功后才建立绑定，避免把失败请求错误地粘到某个凭据上
- 当凭据被禁用、额度耗尽或不再可用时，会自动解除粘性并回退到其他可用凭据
- 更适合 Claude Code 一类长会话场景，能降低多凭据轮转带来的上下文漂移

### 2. 更稳健的均衡调度

- 调度会考虑进行中的请求，而不是只看历史结果，负载分配更平滑
- 异常路径会正确释放请求占用，避免 `balanced` 模式长期偏斜
- Opus 请求会自动避开不支持 Opus 的凭据，减少无效尝试

### 3. 更好的 Anthropic 客户端兼容性

- Anthropic 兼容接口响应会补充 Anthropic 风格的 `request-id` 响应头
- 更方便接入依赖该头部的客户端、日志系统和问题排查流程

### 4. 更严格的会话 ID 校验

- 对 UUID 形式的 session ID 做严格校验
- 避免异常格式误触发会话绑定逻辑，减少错误路由

## 快速开始

完整说明请先看上游：

- 上游仓库：<https://github.com/hank9999/kiro.rs>
- 上游 README：<https://github.com/hank9999/kiro.rs/blob/master/README.md>

本仓库只保留最小必要的本地入口：

### 1. 构建前端资源

```bash
cd admin-ui
corepack enable
corepack prepare pnpm@9 --activate
pnpm install --frozen-lockfile
pnpm build
```

### 2. 构建或测试

```bash
cargo build --release
cargo test
```

### 3. 准备配置文件

可直接参考仓库内示例文件：

- [`config.example.json`](./config.example.json)
- [`credentials.example.social.json`](./credentials.example.social.json)
- [`credentials.example.idc.json`](./credentials.example.idc.json)
- [`credentials.example.multiple.json`](./credentials.example.multiple.json)
- [`credentials.example.apikey.json`](./credentials.example.apikey.json)

### 4. 启动

```bash
./target/release/kiro-rs -c /path/to/config.json --credentials /path/to/credentials.json
```

## 何时优先使用这个 fork

- 你在多凭据 `balanced` 模式下，希望同一会话尽量固定到同一凭据
- 你需要更稳的凭据切换与回退行为
- 你的 Anthropic 兼容客户端依赖 `request-id` 响应头

如果你只需要上游的标准能力，并希望第一时间跟进上游文档与发布节奏，建议直接使用上游项目。

## 其他说明

- 与上游差异之外的通用功能、配置字段、Admin UI、Docker、API 端点和模型映射，请直接参考上游文档，避免两份 README 长期漂移
- 本项目与 AWS / Kiro / Anthropic / Claude 官方无关
- License: [MIT](./LICENSE)
