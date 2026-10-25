import type { ProxyBinding as ProxyBindingPayload } from '@/types/proxy'

// 凭据状态响应
export interface CredentialsStatusResponse {
  total: number
  available: number
  currentId: number
  credentials: CredentialStatusItem[]
}

// 单个凭据状态
export interface CredentialStatusItem {
  id: number
  priority: number
  disabled: boolean
  failureCount: number
  isCurrent: boolean
  expiresAt: string | null
  authMethod: string | null
  hasProfileArn: boolean
  email?: string
  refreshTokenHash?: string
  apiKeyHash?: string
  maskedApiKey?: string
  successCount: number
  lastUsedAt: string | null
  /** 是否配置了任何形式的代理（旧字段，仅保留兼容；展示请用 proxyMode/effectiveProxyUrl） */
  hasProxy: boolean
  /** 代理 URL（已脱敏；仅内联/直连时有值） */
  proxyUrl?: string
  /** 代理来源：inherit | direct | pool | inline */
  proxyMode: string
  /** 池条目 ID（仅 pool 模式） */
  proxyId?: string
  /** 池条目名称（仅 pool 模式） */
  proxyName?: string
  /** 该凭据实际使用的脱敏代理地址（含继承来的全局代理） */
  effectiveProxyUrl?: string
  refreshFailureCount: number
  disabledReason?: string
  endpoint: string
}

// 余额响应
export interface BalanceResponse {
  id: number
  subscriptionTitle: string | null
  currentUsage: number
  usageLimit: number
  remaining: number
  usagePercentage: number
  nextResetAt: number | null
}

// 成功响应
export interface SuccessResponse {
  success: boolean
  message: string
}

// 错误响应
export interface AdminErrorResponse {
  error: {
    type: string
    message: string
  }
}

// 请求类型
export interface SetDisabledRequest {
  disabled: boolean
}

export interface SetPriorityRequest {
  priority: number
}

// 添加凭据请求
//
// 代理有两种互斥写法：新的 tagged `proxy`，或旧的三字段
// `proxyUrl/proxyUsername/proxyPassword`。两者同时出现后端返回 400，
// 因此调用方必须二选一（见 add-credential-dialog 的组装逻辑）。
export interface AddCredentialRequest {
  refreshToken?: string
  authMethod?: 'social' | 'idc' | 'api_key'
  clientId?: string
  clientSecret?: string
  priority?: number
  authRegion?: string
  apiRegion?: string
  machineId?: string
  proxyUrl?: string
  proxyUsername?: string
  proxyPassword?: string
  proxy?: ProxyBindingPayload
  kiroApiKey?: string
  endpoint?: string
}

// 添加凭据响应
export interface AddCredentialResponse {
  success: boolean
  message: string
  credentialId: number
  email?: string
}
