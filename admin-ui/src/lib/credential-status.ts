const labels = new Map<string, string>([
  ['Manual', '人工禁用'],
  ['TooManyFailures', '连续请求失败'],
  ['TooManyRefreshFailures', '连续刷新失败'],
  ['QuotaExceeded', '额度已用尽'],
  ['InvalidRefreshToken', '刷新凭据已失效'],
  ['InvalidConfig', '凭据配置无效'],
  ['TemporarilySuspended', '上游临时安全锁定'],
])

export function disabledReasonLabel(reason?: string): string {
  if (!reason?.trim()) return '禁用原因未提供'
  return labels.get(reason) ?? reason
}
