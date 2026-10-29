import { describe, it, expect } from 'vitest'
import { fireEvent, render, screen } from '@testing-library/react'
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

function renderCard(item: CredentialStatusItem, expanded = true, mode?: string) {
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false }, mutations: { retry: false } },
  })
  const card = (loadBalancingMode?: string) => (
    <QueryClientProvider client={queryClient}>
      <CredentialCard
        credential={item}
        loadBalancingMode={loadBalancingMode}
        onViewBalance={() => {}}
        onEditProxy={() => {}}
        selected={false}
        onToggleSelect={() => {}}
        balance={null}
        loadingBalance={false}
      />
    </QueryClientProvider>
  )
  const view = render(card(mode))
  if (expanded) fireEvent.click(screen.getByRole('button', { name: `凭据 #${item.id} 详情` }))
  return { ...view, rerenderMode: (nextMode?: string) => view.rerender(card(nextMode)) }
}

it('默认紧凑摘要有稳定行和独立控件，详情按需展开且收起丢弃草稿', () => {
  renderCard(credential({ disabled: true, disabledReason: 'Manual', proxyMode: 'inline', proxyUrl: 'http://private:8080' }), false)
  expect(screen.getByTestId('credential-row-1')).toBeInTheDocument()
  expect(screen.getByTestId('credential-disabled-summary')).toHaveTextContent('人工禁用')
  expect(screen.getByTestId('credential-proxy-summary')).not.toHaveTextContent('http:')
  expect(screen.queryByTestId('credential-proxy-source')).not.toBeInTheDocument()
  const trigger = screen.getByRole('button', { name: '凭据 #1 详情' })
  expect(trigger).toHaveAttribute('aria-expanded', 'false')
  fireEvent.click(screen.getByRole('checkbox', { name: '选择凭据 #1' }))
  expect(trigger).toHaveAttribute('aria-expanded', 'false')
  fireEvent.click(trigger)
  expect(trigger).toHaveAttribute('aria-expanded', 'true')
  expect(screen.getByTestId('credential-proxy-source').parentElement?.parentElement).toHaveAttribute('id', trigger.getAttribute('aria-controls'))
  fireEvent.click(screen.getByRole('button', { name: '编辑优先级' }))
  fireEvent.change(screen.getByRole('spinbutton', { name: '优先级' }), { target: { value: '99' } })
  fireEvent.click(trigger)
  fireEvent.click(trigger)
  fireEvent.click(screen.getByRole('button', { name: '编辑优先级' }))
  expect(screen.getByRole('spinbutton', { name: '优先级' })).toHaveValue(0)
})

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

it.each([true, false])('启停状态只通过有名称的开关表达 disabled=%s，禁用原因仍保留', (disabled) => {
  renderCard(credential({ disabled, disabledReason: 'Manual' }), false)
  const toggle = screen.getByRole('switch', { name: '启用凭据 #1' })
  expect(toggle).toHaveAttribute('aria-checked', String(!disabled))
  expect(toggle).toBeEnabled()
  expect(screen.queryByText(/^(启用|已禁用)$/)).not.toBeInTheDocument()
  if (disabled) expect(screen.getByTestId('credential-disabled-summary')).toHaveTextContent('人工禁用')
})

it('同一isCurrent行跨priority/balanced/未知模式重渲染，不残留当前指示或摘要优先级', () => {
  const { rerenderMode } = renderCard(credential({ isCurrent: true, priority: 4 }), false, 'priority')
  const row = screen.getByTestId('credential-row-1')
  expect(screen.getByText('当前选定')).toBeVisible()
  expect(row).toHaveClass('ring-2', 'ring-primary')
  expect(screen.getByText('优先级 4')).toBeVisible()
  for (const mode of ['balanced', 'future-mode', undefined]) {
    rerenderMode(mode)
    expect(screen.queryByText('当前选定')).not.toBeInTheDocument()
    expect(screen.queryByText('当前')).not.toBeInTheDocument()
    expect(screen.queryByText('优先级 4')).not.toBeInTheDocument()
    expect(row).not.toHaveClass('ring-2')
    fireEvent.click(screen.getByRole('button', { name: '凭据 #1 详情' }))
    expect(screen.getByRole('button', { name: '编辑优先级' })).toHaveTextContent('4（编辑）')
    expect(screen.getByRole('button', { name: '提高优先级' })).toBeEnabled()
    expect(screen.getByRole('button', { name: '降低优先级' })).toBeEnabled()
    if (mode === 'balanced') expect(screen.getByText('负载相同时优先，数字越小越优先')).toBeVisible()
    else expect(screen.queryByText('负载相同时优先，数字越小越优先')).not.toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: '凭据 #1 详情' }))
  }
  rerenderMode('priority')
  expect(screen.getByText('当前选定')).toBeVisible()
  expect(row).toHaveClass('ring-2', 'ring-primary')
  expect(screen.getByText('优先级 4')).toBeVisible()
})

it('priority下非current行不显示选定徽标或描边', () => {
  renderCard(credential({ priority: 3 }), false, 'priority')
  expect(screen.queryByText('当前选定')).not.toBeInTheDocument()
  expect(screen.getByTestId('credential-row-1')).not.toHaveClass('ring-2')
  expect(screen.getByText('优先级 3')).toBeVisible()
})

describe('禁用原因展示', () => {
  it.each(['Manual', 'TemporarilySuspended', '异常原因'.repeat(80)])('收起时完整展示原因 %s，展开后摘要与详情各有唯一入口', (disabledReason) => {
    renderCard(credential({ disabled: true, disabledReason }), false)
    const summary = screen.getByTestId('credential-disabled-summary')
    const reasonText = summary.textContent
    expect(summary).toBeVisible()
    if (disabledReason.startsWith('异常原因')) expect(summary).toHaveTextContent(disabledReason)
    expect(screen.queryByTestId('credential-disabled-reason')).not.toBeInTheDocument()
    const trigger = screen.getByRole('button', { name: '凭据 #1 详情' })
    fireEvent.click(trigger)
    expect(screen.getAllByTestId('credential-disabled-summary')).toHaveLength(1)
    expect(screen.getAllByTestId('credential-disabled-reason')).toHaveLength(1)
    expect(screen.getByTestId('credential-disabled-reason')).toHaveTextContent(reasonText!)
    expect(screen.getAllByTestId('credential-proxy-summary')).toHaveLength(1)
    expect(screen.getAllByTestId('credential-proxy-source')).toHaveLength(1)
    expect(screen.getAllByRole('button', { name: '凭据 #1 详情' })).toHaveLength(1)
    fireEvent.click(trigger)
    expect(summary).toBeVisible()
    expect(screen.queryByTestId('credential-disabled-reason')).not.toBeInTheDocument()
  })

  it.each(['social', 'idc', 'api_key'])('Given %s 暂停，Then 说明事实和人工恢复边界', (authMethod) => {
    renderCard(credential({ disabled: true, disabledReason: 'TemporarilySuspended', authMethod }))
    const reason = screen.getByTestId('credential-disabled-reason')
    expect(reason).toHaveTextContent('上游临时安全锁定')
    expect(reason).toHaveTextContent('TEMPORARILY_SUSPENDED')
    expect(reason).toHaveTextContent('触发原因和恢复时间未知，可联系官方支持')
    expect(reason).toHaveTextContent('人工启用/重置仅解除本地禁用，不代表上游解锁')
  })

  it.each(['Manual', 'FutureReason', undefined, ''])('Given 禁用原因为 %s，Then 保留兼容展示', (disabledReason) => {
    renderCard(credential({ disabled: true, disabledReason }))
    const reason = screen.getByTestId('credential-disabled-reason')
    expect(reason).toHaveTextContent(disabledReason === 'Manual' ? '人工禁用' : disabledReason || '禁用原因未提供')
    expect(reason).not.toHaveTextContent('TEMPORARILY_SUSPENDED')
  })

  it('Given 启用且带陈旧暂停原因，Then 不展示禁用原因', () => {
    renderCard(credential({ disabledReason: 'TemporarilySuspended' }))
    expect(screen.queryByTestId('credential-disabled-reason')).not.toBeInTheDocument()
    expect(screen.queryByText('TemporarilySuspended')).not.toBeInTheDocument()
  })
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
