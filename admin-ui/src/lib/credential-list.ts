import type { CredentialStatusItem } from '@/types/api'

export type CredentialFilter = 'all' | 'enabled' | 'disabled'
export const CREDENTIALS_PER_PAGE = 12

export function filterCredentials(items: CredentialStatusItem[], search: string, status: CredentialFilter) {
  const query = search.trim().toLowerCase()
  return items.filter(item => {
    const matchesStatus = status === 'all' || (status === 'disabled' ? item.disabled : !item.disabled)
    const matchesSearch = [item.email, String(item.id), item.proxyName]
      .some(value => value?.toLowerCase().includes(query))
    return matchesStatus && matchesSearch
  })
}

export function credentialPage(items: CredentialStatusItem[], page: number) {
  const totalPages = Math.max(1, Math.ceil(items.length / CREDENTIALS_PER_PAGE))
  const currentPage = Math.min(totalPages, Math.max(1, page))
  const start = (currentPage - 1) * CREDENTIALS_PER_PAGE
  return { totalPages, currentPage, items: items.slice(start, start + CREDENTIALS_PER_PAGE) }
}

export function pruneSelection(selected: Set<number>, items: CredentialStatusItem[]) {
  const existing = new Set(items.map(item => item.id))
  const next = new Set([...selected].filter(id => existing.has(id)))
  return next.size === selected.size ? selected : next
}

export function pageSelection(selected: Set<number>, ids: number[]): boolean | 'indeterminate' {
  const count = ids.filter(id => selected.has(id)).length
  if (count === 0) return false
  return count === ids.length ? true : 'indeterminate'
}

export function togglePageSelection(selected: Set<number>, ids: number[]) {
  const remove = ids.length > 0 && ids.every(id => selected.has(id))
  const next = new Set(selected)
  ids.forEach(id => { if (remove) next.delete(id); else next.add(id) })
  return next
}
