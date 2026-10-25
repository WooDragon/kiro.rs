import { describe, it, expect } from 'vitest'
import {
  buildProxyUrl,
  compactPatch,
  protocolOf,
  splitProxyUrl,
  DEFAULT_PROTOCOL,
} from '@/lib/proxies'

describe('协议与 URL 处理', () => {
  it('默认协议是 SOCKS5h（代理端解析域名）', () => {
    expect(DEFAULT_PROTOCOL).toBe('socks5h')
  })

  it('从 URL 取出协议并小写化', () => {
    expect(protocolOf('SOCKS5h://host:1080')).toBe('socks5h')
    expect(protocolOf('http://host:3128')).toBe('http')
    expect(protocolOf('host:3128')).toBe('')
  })

  it('拼接时不在主机端口上做 trim（空白交给后端拒绝并回显）', () => {
    expect(buildProxyUrl('socks5h', ' 127.0.0.1:1080 ')).toBe('socks5h:// 127.0.0.1:1080 ')
  })

  it('拆分保留协议与主机端口，无法解析时保留原串', () => {
    expect(splitProxyUrl('socks5h://127.0.0.1:1080/')).toEqual({
      protocol: 'socks5h',
      hostPort: '127.0.0.1:1080/',
    })
    expect(splitProxyUrl('127.0.0.1:1080')).toEqual({
      protocol: DEFAULT_PROTOCOL,
      hostPort: '127.0.0.1:1080',
    })
  })
})

describe('PATCH 三态序列化', () => {
  it('保留显式 null（清除），剔除 undefined（保持不变）', () => {
    const patch = compactPatch({
      name: '新名字',
      username: null as string | null | undefined,
      password: undefined as string | null | undefined,
    })

    expect(patch).toEqual({ name: '新名字', username: null })
    expect('password' in patch).toBe(false)
  })

  it('空串被保留为明确的空密码，不被当作缺省', () => {
    const patch = compactPatch({ password: '' })
    expect(patch).toEqual({ password: '' })
    expect(patch.password).toBe('')
  })

  it('含空格的密码逐字保留', () => {
    const patch = compactPatch({ password: ' pass word ' })
    expect(patch.password).toBe(' pass word ')
  })
})
