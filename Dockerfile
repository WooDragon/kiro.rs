FROM node:22-alpine AS frontend-builder

WORKDIR /app/admin-ui
# 先 COPY manifest + lockfile（早于源码），install 层可被 Docker 缓存复用
COPY admin-ui/package.json admin-ui/pnpm-lock.yaml ./
# pin pnpm@9：pnpm 10 默认拦截依赖 build script，导致 esbuild/@swc native binary 不就位、
# pnpm install 直接 exit 1（ERR_PNPM_IGNORED_BUILDS）。pnpm 9 默认运行 build script。
# --frozen-lockfile：按 lockfile 锁定版本安装，保证可复现；lockfile 与 package.json 不一致即报错。
RUN npm install -g pnpm@9 && pnpm install --frozen-lockfile
COPY admin-ui ./
RUN pnpm build

FROM rust:1.92-alpine AS builder

RUN apk add --no-cache musl-dev perl make

WORKDIR /app
COPY Cargo.toml Cargo.lock* ./
# models.toml 被 registry.rs 以 include_str! 在编译期读入作为内嵌 fallback，
# 缺它直接编译失败，故必须进构建上下文（不是仅运行期配置）。
COPY models.toml ./
COPY src ./src
COPY --from=frontend-builder /app/admin-ui/dist /app/admin-ui/dist

RUN cargo build --release --no-default-features

FROM alpine:3.21

RUN apk add --no-cache ca-certificates

WORKDIR /app
COPY --from=builder /app/target/release/kiro-rs /app/kiro-rs

VOLUME ["/app/config"]

EXPOSE 8990

CMD ["./kiro-rs", "-c", "/app/config/config.json", "--credentials", "/app/config/credentials.json", "--models", "/app/config/models.toml"]
