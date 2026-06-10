# Code Review Instructions

Rust proxy translating Anthropic API ↔ Kiro upstream. Correctness = faithful protocol translation with minimal intervention.

## Find real bugs (high priority)

- Logic errors: wrong condition, off-by-one, missed edge case
- State machine violations: SSE event ordering, block open/close invariants
- Semantic divergence between stream and non-stream paths doing the same thing
- Guard conditions that don't match their documented intent
- Concurrency issues with shared state across async boundaries

## Do NOT suggest (low value for this codebase)

- Extracting helpers/abstractions for code under 10 lines
- Adding error handling for structurally unreachable scenarios
- Style-only changes (naming, import order, comment wording) without a concrete failure mode
- "Consider using X library" without identifying an actual bug in the current approach
- Adding doc comments to internal functions

## Project conventions

- No response middleware by design. Inline response modifications in handlers are intentional.
- Same-module private field access is fine. Only flag cross-module violations.
- Unit tests use StreamContext directly (no HTTP integration harness for handlers).
- `cargo test --workspace` is the only merge gate. Clippy is non-blocking.
- Comments explain WHY (hidden constraints), never WHAT.

## What makes a good comment

Valuable: points to a concrete bug with a triggering scenario, or a reachable input that breaks a guard.

Low-value: asks to "extract", "rename", "add docs", or "consider" without identifying a failure mode.
