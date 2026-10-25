import type { ProxyItem } from '@/types/proxy'

/** 协议中文标签，用于下拉与展示 */
export const PROTOCOL_LABELS: Record<string, string> = {
  socks5h: 'SOCKS5h',
  socks5: 'SOCKS5',
  http: 'HTTP',
  https: 'HTTPS',
}

/** 默认协议：SOCKS5h（代理端解析域名） */
export const DEFAULT_PROTOCOL = 'socks5h'

/** 从脱敏/原始 URL 中取出协议；无法解析时返回空串 */
export function protocolOf(url: string): string {
  const match = /^([a-zA-Z][a-zA-Z0-9+.-]*):\/\//.exec(url.trim())
  return match ? match[1].toLowerCase() : ''
}

/**
 * 由协议 + 主机端口拼出池 URL。
 *
 * 只做拼接：不做 trim（主机端口里的空白交给后端拒绝并回显原因），
 * 也不臆造缺失的端口。
 */
export function buildProxyUrl(protocol: string, hostPort: string): string {
  return `${protocol}://${hostPort}`
}

/**
 * 把 URL 拆成协议与主机端口，用于编辑表单回填。
 *
 * 后端返回的 URL 已脱敏（不含 userinfo/query/fragment/path），这里只切 scheme。
 * 协议不在受支持清单内时保留原协议串，让表单如实显示并交给后端判断。
 */
export function splitProxyUrl(url: string): { protocol: string; hostPort: string } {
  const protocol = protocolOf(url)
  if (!protocol) {
    return { protocol: DEFAULT_PROTOCOL, hostPort: url }
  }
  return { protocol, hostPort: url.slice(protocol.length + 3) }
}

/**
 * PATCH 请求体：剔除 `undefined`（= 保留），保留显式 `null`（= 清除）。
 *
 * 这是密码/用户名三态的核心——`undefined` 与 `null` 在 JSON 里语义完全不同，
 * 不能靠真值判断合并。
 */
export function compactPatch<T extends object>(patch: T): Partial<T> {
  const out: Record<string, unknown> = {}
  for (const [key, value] of Object.entries(patch)) {
    if (value !== undefined) {
      out[key] = value
    }
  }
  return out as Partial<T>
}

/** 池条目在凭据卡片上的单行描述：名称 + 脱敏地址 */
export function describeProxy(proxy: ProxyItem): string {
  return `${proxy.name}（${proxy.url}）`
}
