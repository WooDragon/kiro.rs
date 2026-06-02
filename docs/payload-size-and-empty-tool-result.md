# Payload 大小兜底与空 tool_result fallback

两处纯防御性硬化，**不改变正常请求的现有行为**（未触发时 byte-identical 透传）。
对应 Issue [#23](https://github.com/WooDragon/kiro.rs/issues/23)。

## 背景

交叉比对社区 Top3 Kiro 代理（kiro-gateway / Kiro-Go / KiroProxy）后发现两处防御
"所有对手都做、唯独 kiro.rs 没做"——这本身就是这两类风险在生产中真实存在的信号。

---

## P0-2：空 tool_result fallback

### 问题
当工具返回空内容时，kiro.rs 原先把它发成 `{"text":""}`，触发 Kiro 上游对空 text 的
validation 400。

### 方案
所有 `ToolResult` 内容都流经两个构造器（`src/kiro/model/requests/tool.rs`
的 `ToolResult::success` / `ToolResult::error`）。在两个入口加 `trim().is_empty()` 守卫
（覆盖空串 + 纯空白），空则替换为括号注解式纯文本占位符：

| 构造器 | 空内容占位符 |
|--------|--------------|
| `success` | `(empty result)` |
| `error`   | `(tool returned no error message)` |

- success / error 用**不同**文案，便于模型区分"空的成功"与"空的错误"语义。
- 用括号注解纯文本而非 `<伪标签>`：括号是"元信息/非正文"的通用约定，模型可区分这是状态
  描述而非工具真实 stdout；三个社区实现也都用纯文本占位符。
- **非空内容绝不改写**，防止过度替换。

---

## P0-1：payload 大小兜底（proactive 裁剪）

### 问题
超长对话直接撞上游，每次都要等 Kiro 返回 `CONTENT_LENGTH_EXCEEDS_THRESHOLD` 才知道超限，
浪费一次完整 roundtrip。

### 触发方式
**proactive**：在请求转换完成后、发送前裁剪。`src/anthropic/handlers.rs` 的
`finalize_request_body` 复用本来就要做的那一次序列化，直接测 `KiroRequest` 的真实 wire size：

1. 序列化为 `String`（唯一一次）。
2. `body.len() <= KIRO_MAX_PAYLOAD_BYTES` → 直接返回（**热路径零额外成本**）。
3. 超限 → 调 `trim_history_to_byte_limit` 裁剪最旧历史对，重新序列化返回。

### 裁剪算法（`src/anthropic/converter.rs::trim_history_to_byte_limit`）
1. `pinned_front = if has_system_pair { 2 } else { 0 }`——system 对永不裁。
2. 尾部保留 `KEEP_RECENT_PAIRS = 2` 对（4 条）——**活跃 tool turn 永在保留区内**。
3. `excess = bytes_before - max_bytes`。从 `pinned_front` 起**正向（旧→新）**取相邻
   (User, Assistant) 对，每对体积用对整个 `Message` 序列化的长度估算（含 `tool_uses` 等
   全部字段），累加到 `cut >= excess` 即停，一次性 `drain`。
4. **安全低估**：估算漏掉的仅是相邻元素间的结构性逗号，故 `est ≤ 真实字节`；删 history 内容
   等额减少完整 body ⟹ 数学保证**一轮达标**，无需补删循环、无需在函数内重测。

### 锁死的安全前提
- **裁剪必须在 `sanitize_history_tools` 之后**：此时仅活跃 turn 还带结构化 `tool_uses`，
  其余历史 tool 数据已降级为文本 → 成对裁旧不可能产生孤立 tool_use/tool_result 配对。
- **只裁 `conversation_state.history`**，绝不下沉到 `payload.messages`（prompt cache 指纹的
  数据源）→ 裁剪与缓存天然解耦，不扰动 usage/cache 数字（详见下）。
- **current_message 独立于 history**，永不进入裁剪窗口（用户最新提问绝不截断）。

### has_system_pair flag
history 里的 system 对**伪装成普通 User+Assistant**（无 role 标记，`Message` enum 只有
User/Assistant 两变体），无法从数据可靠识别。故由 `build_history` 唯一注入点置位并经
`ConversionResult.has_system_pair` 向下游传递，作为单一真相源——这不是多余状态，是无法从
数据反推的事实传递。

### 鲁棒性（fail-open）
遇结构异常（history 长度为奇数、首条非 User、裁剪窗口内 role 不成对）→ **跳过裁剪、warn
记录、原样发送**，交 `map_provider_error` 兜底。用运行时检查而非 `debug_assert!`（后者
release 下 no-op 等于裸奔）。

### 配置
| env | 默认 | 说明 |
|-----|------|------|
| `KIRO_MAX_PAYLOAD_BYTES` | `921600`（900 KiB） | 请求体字节上限。**每次请求现读**，可热调无需重启。保守阈值优先避免误删历史；配合 warn 日志暴露真实分布，上线后按数据调低。 |

裁剪真实发生时会打 warn 日志，含 `pairs_removed` / `bytes_before` / `bytes_after_est`。

### 能力边界
裁剪**只解决"历史累积超限"**，解决不了：
- 单条超大 current_message（用户问题，绝不截断）
- 超大 tool / system 定义

这些仍由 `map_provider_error` 返回干净 400——`map_provider_error` 是裁剪兜不住时的最终防线。

### 与 prompt cache 的关系
kiro.rs 的 prompt cache 是纯本地模拟（进程内 HashMap），从不向 Kiro 透传 cache_control。
缓存指纹对**原始 `payload.messages`** 计算，本裁剪只作用于**转换后的
`conversation_state.history`**（不同数据源、不同时序）→ 裁剪不扰动缓存数字。唯一可接受的小
瑕疵：裁剪真实发生时（rare），上报 client 的 `input_tokens`/cache 数字基于完整 payload，
略高于实际发给 Kiro 的量——方向无害（不少算），仅 usage 显示。

---

## 关键文件
- `src/kiro/model/requests/tool.rs` — P0-2 两构造器守卫 + 占位符常量
- `src/anthropic/converter.rs` — `trim_history_to_byte_limit` / `TrimStats` /
  `max_payload_bytes` / `build_history` 返回 `has_system_pair`
- `src/anthropic/handlers.rs` — `finalize_request_body` helper（两入口共用）
