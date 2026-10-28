import { describe, it, expect } from 'vitest'
import { render, screen } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { CredentialCard } from '@/components/credential-card'
import type { CredentialStatusItem } from '@/types/api'

function credential(overrides: Partial<CredentialStatusItem> = {}): CredentialStatusItem {
  return {
    id: 1,
    priority: 0,
    disabled: false,
    failureCount: 0,
    isCurrent: false,
    expiresAt: null,
    authMethod: 'social',
    hasProfileArn: false,
    successCount: 0,
    lastUsedAt: null,
    hasProxy: false,
    proxyMode: 'inherit',
    refreshFailureCount: 0,
    endpoint: 'ide',
    ...overrides,
  }
}

function renderCard(item: CredentialStatusItem) {
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false }, mutations: { retry: false } },
  })
  return render(
    <QueryClientProvider client={queryClient}>
      <CredentialCard
        credential={item}
        onViewBalance={() => {}}
        onEditProxy={() => {}}
        selected={false}
        onToggleSelect={() => {}}
        balance={null}
        loadingBalance={false}
      />
    </QueryClientProvider>
  )
}

it('长标题、代理名称与脱敏地址全文可读，不增加健康结论', () => {
  const email = `${'long-account-'.repeat(12)}@example.test`
  const proxyName = '长代理名称'.repeat(30)
  const url = `http://${'long-host-'.repeat(20)}.test:3128/`
  renderCard(credential({ email, proxyMode: 'pool', proxyName, effectiveProxyUrl: url }))
  expect(screen.getByRole('heading', { name: new RegExp(email) })).toBeInTheDocument()
  const source = screen.getByTestId('credential-proxy-source')
  expect(source).toHaveTextContent(proxyName)
  expect(source).toHaveTextContent(url)
  expect(source).not.toHaveTextContent(/健康|探活/)
})

describe('凭据卡片的代理来源展示', () => {
  it('无实际地址时只显示全局来源，不猜全局状态', () => {
    renderCard(credential({ hasProxy: true, proxyMode: 'inherit' }))

    expect(screen.getByTestId('credential-proxy-source')).toHaveTextContent(
      '代理：使用全局代理配置'
    )
  })

  it('继承全局时显示继承到的脱敏地址', () => {
    renderCard(
      credential({
        hasProxy: true,
        proxyMode: 'inherit',
        effectiveProxyUrl: 'http://global-proxy:3128/',
      })
    )

    expect(screen.getByTestId('credential-proxy-source')).toHaveTextContent(
      '使用全局代理配置 · http://global-proxy:3128/'
    )
  })

  it('池模式显示条目名称，并补上实际脱敏地址', () => {
    renderCard(
      credential({
        hasProxy: true,
        proxyMode: 'pool',
        proxyId: 'p1',
        proxyName: '家庭 SOCKS',
        effectiveProxyUrl: 'socks5h://127.0.0.1:1080/',
      })
    )

    const cell = screen.getByTestId('credential-proxy-source')
    expect(cell).toHaveTextContent('使用指定代理 · 家庭 SOCKS')
    expect(cell).toHaveTextContent('socks5h://127.0.0.1:1080/')
  })

  it('直连与内联分别如实展示', () => {
    const { unmount } = renderCard(credential({ proxyMode: 'direct' }))
    expect(screen.getByTestId('credential-proxy-source')).toHaveTextContent('明确直连')
    unmount()

    renderCard(
      credential({
        proxyMode: 'inline',
        proxyUrl: 'socks5://10.0.0.9:1080/',
        effectiveProxyUrl: 'socks5://10.0.0.9:1080/',
      })
    )
    expect(screen.getByTestId('credential-proxy-source')).toHaveTextContent(
      '高级内联 · socks5://10.0.0.9:1080/'
    )
  })

  it('提供“修改代理”入口', () => {
    renderCard(credential())
    expect(screen.getByRole('button', { name: /修改代理/ })).toBeInTheDocument()
  })
})

 it.each([true, false])('hasProxy=%s 且缺地址不能推断全局配置', (hasProxy) => {
   renderCard(credential({ hasProxy, proxyMode: 'inherit' }))
   expect(screen.getByTestId('credential-proxy-source')).toHaveTextContent(/^代理：使用全局代理配置$/)
 })
 it('内联缺地址时仅显示来源', () => {
   renderCard(credential({ proxyMode: 'inline' }))
   expect(screen.getByTestId('credential-proxy-source')).toHaveTextContent(/^代理：高级内联$/)
 })
 it('旧内联 proxyUrl 脱敏地址仍展示', () => {
   renderCard(credential({ proxyMode: 'inline', proxyUrl: 'http://legacy:8080/' }))
   expect(screen.getByTestId('credential-proxy-source')).toHaveTextContent('高级内联 · http://legacy:8080/')
 })
