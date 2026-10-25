// 代理池与凭据代理绑定的共享类型

/** 协议：池 URL 只允许这四种（后端 validate_pool_url 同源） */
export const PROXY_PROTOCOLS = ['socks5h', 'socks5', 'http', 'https'] as const
export type ProxyProtocol = (typeof PROXY_PROTOCOLS)[number]

/** 池条目（响应永不包含密码） */
export interface ProxyItem {
  id: string
  name: string
  /** 已脱敏 URL */
  url: string
  username?: string
  hasPassword: boolean
  referenceCount: number
}

/** 池列表响应（新增/编辑/删除/绑定的成功响应都是它） */
export interface ProxyListResponse {
  proxies: ProxyItem[]
}

/** 新增池代理请求（不传 id，由服务端生成） */
export interface CreateProxyRequest {
  name: string
  url: string
  username?: string
  password?: string
}

/**
 * 编辑池代理请求。
 *
 * 后端用 serde double-option：字段缺省=保留，null=清除，值=替换。
 * 因此这里显式区分“不发送”与“发送 null”——用 `undefined` 表示前者，
 * `null` 表示后者，序列化前由 `compactPatch` 剔除 undefined 键。
 */
export interface UpdateProxyRequest {
  name?: string
  url?: string
  username?: string | null
  password?: string | null
}

/** 凭据代理绑定（tagged by mode） */
export type ProxyBinding =
  | { mode: 'inherit' }
  | { mode: 'direct' }
  | { mode: 'pool'; proxyId: string }
  | { mode: 'inline'; url: string; username?: string; password?: string }

/** 凭据的代理来源模式 */
export type ProxyMode = ProxyBinding['mode']
