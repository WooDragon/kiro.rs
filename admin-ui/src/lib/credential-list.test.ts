import { describe, expect, it } from 'vitest'
import { credentialPage, filterCredentials, pageSelection, pruneSelection, togglePageSelection } from './credential-list'
import type { CredentialStatusItem } from '@/types/api'

const items = [
  { id: 23, email: 'Zed@Example.test', proxyName: 'OFFICE', disabled: false, maskedApiKey: 'hidden-secret' },
  { id: 1, email: 'amy@example.test', disabled: true, effectiveProxyUrl: 'http://private' },
  { id: 12, disabled: false },
] as CredentialStatusItem[]

describe('本地搜索与状态不改变服务端顺序或搜索秘密', () => {
  it.each([
    ['  ', 'all', [23, 1, 12]], [' EXAMPLE ', 'all', [23, 1]], ['oFfiCe', 'all', [23]],
    [' 23 ', 'all', [23]], ['', 'enabled', [23, 12]], ['', 'disabled', [1]],
    ['office', 'disabled', []], ['hidden-secret', 'all', []], ['private', 'all', []], ['missing', 'all', []],
  ] as const)('%s / %s', (query, status, ids) => {
    expect(filterCredentials(items, query, status).map(item => item.id)).toEqual(ids)
  })
})

it.each([0, 1, 12, 13, 24, 25])('分页边界 count=%i 不出现1/0且越界夹紧', count => {
  const source = Array.from({ length: count }, (_, id) => ({ ...items[0], id }))
  const last = credentialPage(source, 99)
  expect(last.totalPages).toBe(Math.max(1, Math.ceil(count / 12)))
  expect(last.currentPage).toBe(last.totalPages)
  expect(last.items.map(item => item.id)).toEqual(source.slice((last.currentPage - 1) * 12).map(item => item.id))
  expect(credentialPage(source, 0).currentPage).toBe(1)
})

it('全选只改当前页，半选补齐，清页保留其他页，空页未选', () => {
  const partial = new Set([23, 99])
  expect(pageSelection(partial, [23, 1])).toBe('indeterminate')
  const full = togglePageSelection(partial, [23, 1])
  expect([...full]).toEqual([23, 99, 1])
  expect(pageSelection(full, [23, 1])).toBe(true)
  expect([...togglePageSelection(full, [23, 1])]).toEqual([99])
  expect([...partial]).toEqual([23, 99])
  expect(pageSelection(full, [])).toBe(false)
  expect([...togglePageSelection(full, [])]).toEqual([...full])
})

it('成功全量刷新仅移除已不存在ID而非过滤不可见ID', () => {
  expect([...pruneSelection(new Set([23, 1, 99]), items)]).toEqual([23, 1])
  const selected = new Set([23, 1])
  expect(pruneSelection(selected, items)).toBe(selected)
})
