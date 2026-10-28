import { describe, expect, it } from 'vitest'
import { disabledReasonLabel } from './credential-status'

describe('禁用原因可读映射', () => {
  it.each([
    ['Manual', '人工禁用'],
    ['TooManyFailures', '连续请求失败'],
    ['TooManyRefreshFailures', '连续刷新失败'],
    ['QuotaExceeded', '额度已用尽'],
    ['InvalidRefreshToken', '刷新凭据已失效'],
    ['InvalidConfig', '凭据配置无效'],
    ['TemporarilySuspended', '上游临时安全锁定'],
    ['FutureReason', 'FutureReason'],
    ['TEMPORARILY_SUSPENDED', 'TEMPORARILY_SUSPENDED'],
    ['constructor', 'constructor'],
    [undefined, '禁用原因未提供'],
    ['', '禁用原因未提供'],
    ['   ', '禁用原因未提供'],
  ])('Given 原因 %s，Then 显示 %s', (reason, label) => {
    expect(disabledReasonLabel(reason)).toBe(label)
  })
})
