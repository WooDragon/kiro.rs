import { describe, it, expect, afterEach, vi } from 'vitest'
import { act, fireEvent, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { renderWithQueryClient } from '@/test/harness'
import { installMockServer, proxyItem } from '@/test/mock-server'
import { Dashboard } from '@/components/dashboard'
import type { CredentialStatusItem } from '@/types/api'

let server: ReturnType<typeof installMockServer>
afterEach(() => { server?.restore(); vi.restoreAllMocks() })

function listFixture(count = 25) {
  return Array.from({ length: count }, (_, index) => ({
    ...credential(), id: index + 1, email: `account-${index + 1}@example.test`,
    disabled: index % 2 === 1, proxyName: index === 24 ? 'Office Proxy' : undefined,
  }))
}

it('25项当前页全选与跨页选择，取消仅影响当前页且筛选清选择', async () => {
  mockDashboard(() => response(listFixture(), false))
  const user = userEvent.setup()
  renderWithQueryClient(<Dashboard onLogout={() => {}} />)
  await user.click(await screen.findByRole('checkbox', { name: '选择当前页' }))
  expect(screen.getByText('已选 12 项')).toBeInTheDocument()
  await user.click(screen.getByRole('button', { name: '下一页' }))
  await user.click(screen.getByRole('checkbox', { name: '选择凭据 #13' }))
  expect(screen.getByRole('checkbox', { name: '选择当前页' })).toHaveAttribute('data-state', 'indeterminate')
  expect(screen.getByText('已选 13 项')).toBeInTheDocument()
  await user.click(screen.getByRole('button', { name: '上一页' }))
  await user.click(screen.getByRole('checkbox', { name: '选择当前页' }))
  expect(screen.getByText('已选 1 项')).toBeInTheDocument()
  await user.type(screen.getByRole('searchbox', { name: '搜索凭据' }), ' office ')
  expect(screen.getByTestId('credential-row-25')).toBeInTheDocument()
  expect(screen.getByText('已选 0 项')).toBeInTheDocument()
  expect(screen.getByText(/第 1 \/ 1 页.*命中 1 项/)).toBeInTheDocument()
})

it('后台成功刷新只prune消失ID，保留页码并在越界时夹紧，失败保留列表选择', async () => {
  let items = listFixture()
  let failed = false
  server = installMockServer((request) => {
    if (request.url === '/credentials') return failed ? { status: 500 } : { data: response(items, false) }
    return { data: { mode: 'priority', proxies: [] } }
  })
  const user = userEvent.setup()
  const { queryClient } = renderWithQueryClient(<Dashboard onLogout={() => {}} />)
  await user.click(await screen.findByRole('checkbox', { name: '选择凭据 #1' }))
  await user.click(screen.getByRole('button', { name: '下一页' }))
  await user.click(screen.getByRole('checkbox', { name: '选择凭据 #13' }))
  items = items.filter(item => item.id !== 1)
  await act(async () => { await queryClient.invalidateQueries({ queryKey: ['credentials'] }) })
  await waitFor(() => expect(screen.getByText('已选 1 项')).toBeInTheDocument())
  expect(screen.getByText(/第 2 \/ 2 页/)).toBeInTheDocument()
  failed = true
  await act(async () => { await queryClient.invalidateQueries({ queryKey: ['credentials'] }) })
  expect(screen.getByText('已选 1 项')).toBeInTheDocument()
  expect(screen.queryByText('加载失败')).not.toBeInTheDocument()
  failed = false
  items = items.slice(0, 3)
  await act(async () => { await queryClient.invalidateQueries({ queryKey: ['credentials'] }) })
  await waitFor(() => expect(screen.getByText(/第 1 \/ 1 页/)).toBeInTheDocument())
  expect(screen.getByText('已选 0 项')).toBeInTheDocument()
})

function compactItems() {
  return [
    { ...credential(), id: 1, email: 'alpha@test', authMethod: 'api_key' },
    { ...credential(), id: 2, email: 'beta@test', disabled: true, failureCount: 1 },
    { ...credential(), id: 3, email: 'gamma@test', disabled: true, refreshFailureCount: 1 },
  ]
}

function installListServer(items: CredentialStatusItem[] = compactItems(), mutation?: Parameters<typeof installMockServer>[0]) {
  server = installMockServer(request => {
    if (request.url === '/credentials') return { data: response(items, false) }
    if (request.url === '/proxies') return { data: { proxies: [] } }
    if (request.url === '/config/load-balancing') return { data: { mode: 'priority' } }
    if (mutation) return mutation(request)
    throw new Error(`Unexpected request: ${request.method} ${request.url}`)
  })
}
const balanceResponse = { remaining: 50, usageLimit: 100, currentUsage: 50, usagePercentage: 50 }

it('默认摘要无隐式余额/刷新请求，选择、开关不展开，同行刷新保留展开而翻页重置', async () => {
  const items = listFixture()
  installListServer(items, () => ({ data: { success: true, message: 'ok' } }))
  const user = userEvent.setup()
  const { queryClient } = renderWithQueryClient(<Dashboard onLogout={() => {}} />)
  const row = within(await screen.findByTestId('credential-row-1'))
  const trigger = row.getByRole('button', { name: '凭据 #1 详情' })
  expect(row.queryByRole('button', { name: '修改代理' })).not.toBeInTheDocument()
  await user.click(row.getByRole('checkbox'))
  await user.click(row.getByRole('switch'))
  expect(trigger).toHaveAttribute('aria-expanded', 'false')
  expect(server.find('POST', '/credentials/1/disabled')[0].body).toEqual({ disabled: true })
  await user.click(trigger)
  await act(async () => { await queryClient.invalidateQueries({ queryKey: ['credentials'] }) })
  expect(trigger).toHaveAttribute('aria-expanded', 'true')
  expect(server.requests.filter(request => /balance|refresh/.test(request.url))).toHaveLength(0)
  await user.click(screen.getByRole('button', { name: '下一页' }))
  await user.click(screen.getByRole('button', { name: '上一页' }))
  expect(screen.getByRole('button', { name: '凭据 #1 详情' })).toHaveAttribute('aria-expanded', 'false')
})

it.each(['批量删除', '恢复异常', '批量刷新 Token', '批量验活', '查询当前页信息', '清除全库已禁用凭据（2）'])('%s 与其余五批处理互斥，pending禁止改筛选/选择，结束释放锁', async action => {
  let release!: (value: { data: unknown }) => void
  let first = true
  installListServer(compactItems(), () => {
    if (first) { first = false; return new Promise(resolve => { release = resolve }) }
    return { data: { success: true, message: 'ok', ...balanceResponse } }
  })
  vi.spyOn(window, 'confirm').mockReturnValue(true)
  const user = userEvent.setup()
  renderWithQueryClient(<Dashboard onLogout={() => {}} />)
  const selected = ['批量刷新 Token', '批量验活', '查询当前页信息'].includes(action) ? 1 : 2
  await user.click(await screen.findByRole('checkbox', { name: `选择凭据 #${selected}` }))
  const trigger = screen.getByRole('button', { name: action })
  act(() => { trigger.click(); trigger.click() })
  await waitFor(() => expect(first).toBe(false))
  if (action === '批量验活') {
    await user.click(screen.getByRole('button', { name: '后台运行' }))
    expect(screen.getByRole('button', { name: /验活中/ })).toBeEnabled()
  }
  expect(screen.getByRole('searchbox')).toHaveAttribute('readonly')
  expect(screen.getByLabelText('凭据状态')).toBeDisabled()
  for (const checkbox of screen.getAllByRole('checkbox')) expect(checkbox).toBeDisabled()
  for (const name of ['批量删除', '恢复异常', '批量验活', '清除全库已禁用凭据（2）']) {
    expect(screen.getByRole('button', { name })).toBeDisabled()
  }
  expect(server.requests.filter(request => !['/credentials', '/proxies', '/config/load-balancing'].includes(request.url))).toHaveLength(1)
  await act(async () => { release({ data: { success: true, message: 'ok', ...balanceResponse } }) })
  await waitFor(() => expect(screen.getByRole('searchbox')).not.toHaveAttribute('readonly'))
  expect(screen.getByText(`已选 ${action === '批量验活' || action === '查询当前页信息' ? 1 : 0} 项`)).toBeInTheDocument()
  if (action === '批量刷新 Token') expect(server.find('POST', '/credentials/1/refresh')).toHaveLength(1)
  if (action === '清除全库已禁用凭据（2）') expect(server.requests.filter(request => request.method === 'DELETE').map(request => request.url)).toEqual(['/credentials/2', '/credentials/3'])
})

it('删除确认说明已选/实际/跳过，取消零写入且不占锁，部分失败继续并清选择', async () => {
  installListServer(compactItems(), request => request.url === '/credentials/2'
    ? { status: 500, data: { error: { message: 'failed' } } }
    : { data: { success: true, message: 'ok' } })
  const confirm = vi.spyOn(window, 'confirm').mockReturnValue(false)
  const user = userEvent.setup()
  renderWithQueryClient(<Dashboard onLogout={() => {}} />)
  await user.click(await screen.findByRole('checkbox', { name: '选择当前页' }))
  await user.click(screen.getByRole('button', { name: '批量删除' }))
  expect(confirm).toHaveBeenCalledWith(expect.stringMatching(/已选 3 项.*实际删除 2.*跳过 1/))
  expect(server.requests.filter(request => request.method !== 'GET')).toHaveLength(0)
  expect(screen.getByRole('searchbox')).not.toHaveAttribute('readonly')
  expect(screen.getByText('已选 3 项')).toBeInTheDocument()
  confirm.mockReturnValue(true)
  await user.click(screen.getByRole('button', { name: '批量删除' }))
  await waitFor(() => expect(screen.getByText('已选 0 项')).toBeInTheDocument())
  expect(server.requests.filter(request => request.method === 'DELETE').map(request => request.url)).toEqual(['/credentials/2', '/credentials/3'])
  expect(await screen.findByText(/删除已禁用凭据.*成功 1 个，失败 1 个/)).toBeInTheDocument()
})

it('全库清除不受搜索与选择影响，取消不占锁，确认请求全库disabled快照', async () => {
  installListServer(compactItems(), () => ({ data: { message: 'ok', success: true } }))
  const confirm = vi.spyOn(window, 'confirm').mockReturnValue(false)
  const user = userEvent.setup()
  renderWithQueryClient(<Dashboard onLogout={() => {}} />)
  await user.type(await screen.findByRole('searchbox'), 'alpha')
  await user.click(screen.getByRole('checkbox', { name: '选择凭据 #1' }))
  await user.click(screen.getByRole('button', { name: '清除全库已禁用凭据（2）' }))
  expect(confirm).toHaveBeenCalledWith(expect.stringMatching(/全库 2.*不受搜索、分页或选择限制/))
  expect(server.requests.filter(request => request.method !== 'GET')).toHaveLength(0)
  expect(screen.getByRole('searchbox')).not.toHaveAttribute('readonly')
  confirm.mockReturnValue(true)
  await user.click(screen.getByRole('button', { name: '清除全库已禁用凭据（2）' }))
  await waitFor(() => expect(screen.getByText('已选 0 项')).toBeInTheDocument())
  expect(server.requests.filter(request => request.method === 'DELETE').map(request => request.url)).toEqual(['/credentials/2', '/credentials/3'])
})

it('恢复沿用failureCount资格而不扩展refreshFailureCount，单项APIKey刷新仍禁用', async () => {
  installListServer(compactItems(), () => ({ data: { message: 'ok', success: true } }))
  const user = userEvent.setup()
  renderWithQueryClient(<Dashboard onLogout={() => {}} />)
  await user.click(await screen.findByRole('checkbox', { name: '选择当前页' }))
  await user.click(screen.getByRole('button', { name: '恢复异常' }))
  await waitFor(() => expect(screen.getByText('已选 0 项')).toBeInTheDocument())
  expect(server.requests.filter(request => request.method === 'POST').map(request => request.url)).toEqual(['/credentials/2/reset'])
  await user.click(screen.getByRole('button', { name: '凭据 #1 详情' }))
  expect(within(screen.getByTestId('credential-row-1')).getByRole('button', { name: '刷新 Token' })).toBeDisabled()
})

it('查询当前页按筛选启用快照顺序执行，翻页不换目标，部分失败不清选择', async () => {
  let release!: (value: { data: unknown }) => void
  installListServer(listFixture(), request => request.url === '/credentials/1/balance'
    ? new Promise(resolve => { release = resolve })
    : request.url === '/credentials/3/balance' ? { status: 500 } : { data: balanceResponse })
  const user = userEvent.setup()
  renderWithQueryClient(<Dashboard onLogout={() => {}} />)
  await user.click(await screen.findByRole('checkbox', { name: '选择凭据 #1' }))
  await user.click(screen.getByRole('button', { name: '查询当前页信息' }))
  await waitFor(() => expect(server.find('GET', '/credentials/1/balance')).toHaveLength(1))
  await user.click(screen.getByRole('button', { name: '下一页' }))
  await act(async () => { release({ data: balanceResponse }) })
  await waitFor(() => expect(screen.getByRole('searchbox')).not.toHaveAttribute('readonly'))
  expect(server.requests.filter(request => request.url.endsWith('/balance')).map(request => request.url)).toEqual([1, 3, 5, 7, 9, 11].map(id => `/credentials/${id}/balance`))
  expect(screen.getByText('已选 1 项')).toBeInTheDocument()
  expect(await screen.findByText('查询完成：成功 5 个，失败 1 个')).toBeInTheDocument()
})

it('优先级每次编辑取最新prop，轮询不覆盖编辑草稿，收起丢弃，单项操作保留请求', async () => {
  let items = [{ ...credential(), id: 1, priority: 2, failureCount: 1 }]
  server = installMockServer(request => {
    if (request.url === '/credentials') return { data: response(items, false) }
    if (request.url === '/proxies') return { data: { proxies: [] } }
    if (request.url === '/config/load-balancing') return { data: { mode: 'priority' } }
    return { data: { message: 'ok', success: true, ...balanceResponse } }
  })
  const user = userEvent.setup()
  const { queryClient } = renderWithQueryClient(<Dashboard onLogout={() => {}} />)
  await user.click(await screen.findByRole('button', { name: '凭据 #1 详情' }))
  items = items.map(item => ({ ...item, priority: 5 }))
  await act(async () => { await queryClient.invalidateQueries({ queryKey: ['credentials'] }) })
  await waitFor(() => expect(screen.getByText('优先级 5')).toBeInTheDocument())
  await user.click(screen.getByRole('button', { name: '编辑优先级' }))
  expect(screen.getByRole('spinbutton', { name: '优先级' })).toHaveValue(5)
  await user.clear(screen.getByRole('spinbutton'))
  await user.type(screen.getByRole('spinbutton'), '8')
  items = items.map(item => ({ ...item, priority: 6 }))
  await act(async () => { await queryClient.invalidateQueries({ queryKey: ['credentials'] }) })
  expect(screen.getByRole('spinbutton')).toHaveValue(8)
  await user.click(screen.getByRole('button', { name: '保存优先级' }))
  await waitFor(() => expect(server.find('POST', '/credentials/1/priority')).toHaveLength(1))
  expect(server.find('POST', '/credentials/1/priority')[0].body).toEqual({ priority: 8 })
  await waitFor(() => expect(screen.queryByRole('spinbutton')).not.toBeInTheDocument())
  await user.click(screen.getByRole('button', { name: '提高优先级' }))
  await waitFor(() => expect(server.find('POST', '/credentials/1/priority')).toHaveLength(2))
  expect(server.find('POST', '/credentials/1/priority')[1].body).toEqual({ priority: 5 })
  await user.click(screen.getByRole('button', { name: '降低优先级' }))
  await waitFor(() => expect(server.find('POST', '/credentials/1/priority')).toHaveLength(3))
  expect(server.find('POST', '/credentials/1/priority')[2].body).toEqual({ priority: 7 })
  await user.click(screen.getByRole('button', { name: '重置失败' }))
  await user.click(screen.getByRole('button', { name: '刷新 Token' }))
  await user.click(screen.getByRole('button', { name: '查看余额' }))
  await waitFor(() => expect(server.find('GET', '/credentials/1/balance')).toHaveLength(1))
  expect(server.find('POST', '/credentials/1/reset')).toHaveLength(1)
  expect(server.find('POST', '/credentials/1/refresh')).toHaveLength(1)
})

it('代理触发器消失后焦点回搜索；正常关闭保留展开和优先级草稿', async () => {
  let items = compactItems()
  mockDashboard(() => response(items, false))
  const user = userEvent.setup()
  const { queryClient } = renderWithQueryClient(<Dashboard onLogout={() => {}} />)
  await user.click(await screen.findByRole('button', { name: '凭据 #1 详情' }))
  await user.click(screen.getByRole('button', { name: '编辑优先级' }))
  await user.type(screen.getByRole('spinbutton'), '8')
  const opener = screen.getByRole('button', { name: '修改代理' })
  await user.click(opener)
  await user.keyboard('{Escape}')
  await waitFor(() => expect(opener).toHaveFocus())
  expect(screen.getByRole('spinbutton')).toHaveValue(8)
  await user.click(opener)
  items = items.filter(item => item.id !== 1)
  await act(async () => { await queryClient.invalidateQueries({ queryKey: ['credentials'] }) })
  await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument())
  await waitFor(() => expect(screen.getByRole('searchbox')).toHaveFocus())
})

it('F1 两项deferred删除：第一行消失关闭代理弹窗，第二项pending时搜索实际获焦且不改变筛选选择', async () => {
  let items = compactItems()
  const releases = new Map<number, (value: { data: unknown }) => void>()
  server = installMockServer(request => {
    if (request.url === '/credentials') return { data: response(items, false) }
    if (request.url === '/proxies') return { data: { proxies: [] } }
    if (request.url === '/config/load-balancing') return { data: { mode: 'priority' } }
    if (request.method === 'DELETE') return new Promise(resolve => {
      releases.set(Number(request.url.split('/').pop()), resolve)
    })
    throw new Error(`Unexpected request: ${request.method} ${request.url}`)
  })
  vi.spyOn(window, 'confirm').mockReturnValue(true)
  const user = userEvent.setup()
  renderWithQueryClient(<Dashboard onLogout={() => {}} />)
  await user.click(await screen.findByRole('checkbox', { name: '选择凭据 #2' }))
  await user.click(screen.getByRole('checkbox', { name: '选择凭据 #3' }))
  await user.click(screen.getByRole('button', { name: '凭据 #2 详情' }))
  const opener = screen.getByRole('button', { name: '修改代理' })
  const search = screen.getByRole('searchbox')
  await user.click(screen.getByRole('button', { name: '批量删除' }))
  await waitFor(() => expect(releases.has(2)).toBe(true))
  await user.click(opener)
  expect(screen.getByRole('dialog', { name: '修改代理' })).toBeVisible()
  items = items.filter(item => item.id !== 2)
  await act(async () => { releases.get(2)!({ data: { success: true, message: 'deleted' } }) })
  await waitFor(() => expect(releases.has(3)).toBe(true))
  await waitFor(() => expect(screen.queryByTestId('credential-row-2')).not.toBeInTheDocument())
  await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument())
  expect(opener.isConnected).toBe(false)
  await waitFor(() => expect(search).toHaveFocus())
  expect(search).toHaveAttribute('readonly')
  expect(search).toBeEnabled()
  expect(screen.getByRole('combobox')).toBeDisabled()
  expect(screen.getByRole('checkbox', { name: '选择凭据 #3' })).toBeDisabled()
  expect(screen.getByText('已选 1 项')).toBeInTheDocument()
  await user.type(search, 'alpha')
  // 即使直接派发 change 绕过原生 readOnly，同步执行锁仍必须拒绝筛选变化。
  fireEvent.change(search, { target: { value: 'alpha' } })
  expect(search).toHaveValue('')
  expect(screen.getByTestId('credential-row-3')).toBeInTheDocument()
  expect(screen.getByText('已选 1 项')).toBeInTheDocument()
  expect(server.requests.filter(request => request.method === 'DELETE').map(request => request.url))
    .toEqual(['/credentials/2', '/credentials/3'])
  items = items.filter(item => item.id !== 3)
  await act(async () => { releases.get(3)!({ data: { success: true, message: 'deleted' } }) })
  await waitFor(() => expect(search).not.toHaveAttribute('readonly'))
  expect(screen.getByText('已选 0 项')).toBeInTheDocument()
})

it('搜索与状态无结果区别于全库空，筛选回首页清选择，概览仍全库', async () => {
  mockDashboard(() => response(listFixture(), false))
  const user = userEvent.setup()
  renderWithQueryClient(<Dashboard onLogout={() => {}} />)
  await user.click(await screen.findByRole('button', { name: '下一页' }))
  await user.click(screen.getByRole('checkbox', { name: '选择凭据 #13' }))
  await user.selectOptions(screen.getByRole('combobox', { name: '凭据状态' }), 'disabled')
  expect(screen.getByText(/第 1 \/ 1 页，命中 12 项/)).toBeInTheDocument()
  expect(screen.getByText('已选 0 项')).toBeInTheDocument()
  expect(screen.getAllByTestId(/^credential-row-/).map(row => row.getAttribute('data-testid'))).toEqual(Array.from({ length: 12 }, (_, index) => `credential-row-${(index + 1) * 2}`))
  await user.type(screen.getByRole('searchbox'), 'NO-MATCH')
  expect(screen.getByText('没有匹配的凭据')).toBeInTheDocument()
  expect(screen.queryByText('暂无凭据')).not.toBeInTheDocument()
  expect(screen.getByRole('checkbox', { name: '选择当前页' })).toBeDisabled()
  expect(screen.getByLabelText('凭据概览')).toHaveTextContent('凭据总数 25')
  expect(screen.getByLabelText('凭据概览')).toHaveTextContent('当前选定 无')
})

function installModeServer(modeHandler: Parameters<typeof installMockServer>[0]) {
  server = installMockServer(request => {
    if (request.url === '/credentials') return { data: { ...response([
      { ...credential(), id: 7, isCurrent: true, priority: 4 },
      { ...credential(), id: 2, priority: 1 },
    ], false), currentId: 7 } }
    if (request.url === '/proxies') return { data: { proxies: [] } }
    if (request.url === '/config/load-balancing') return modeHandler(request)
    return { data: { success: true, message: 'ok' } }
  })
}

it.each(['priority', 'balanced', 'future-mode'])('模式%s：概览和摘要只在明确priority显示内部选定，不重排列', async mode => {
  installModeServer(() => ({ data: { mode } }))
  renderWithQueryClient(<Dashboard onLogout={() => {}} />)
  const row = await screen.findByTestId('credential-row-7')
  const nav = await screen.findByRole('button', { name: mode === 'priority' ? '优先级模式' : mode === 'balanced' ? '均衡负载' : '模式未知' })
  if (mode === 'future-mode') expect(nav).toBeDisabled()
  else expect(nav).toBeEnabled()
  expect(screen.getAllByTestId(/^credential-row-/).map(item => item.dataset.testid)).toEqual(['credential-row-7', 'credential-row-2'])
  const overview = screen.getByLabelText('凭据概览')
  expect(overview).not.toHaveTextContent('当前活跃')
  if (mode === 'priority') {
    expect(overview).toHaveTextContent('当前选定 #7')
    expect(within(row).getByText('当前选定')).toBeVisible()
    expect(within(row).getByText('优先级 4')).toBeVisible()
  } else {
    expect(overview).not.toHaveTextContent('当前')
    expect(within(row).queryByText(/当前|优先级/)).not.toBeInTheDocument()
    expect(row).not.toHaveClass('ring-2')
  }
})

it.each(['loading', 'error', 'unknown'])('初始模式%s无缓存不假装balanced/priority且不可切换', async state => {
  let release!: (value: { data: unknown }) => void
  installModeServer(() => state === 'loading' ? new Promise(resolve => { release = resolve })
    : state === 'error' ? { status: 500 } : { data: { mode: 'unknown' } })
  const user = userEvent.setup()
  renderWithQueryClient(<Dashboard onLogout={() => {}} />)
  const row = await screen.findByTestId('credential-row-7')
  const nav = await screen.findByRole('button', { name: state === 'loading' ? '加载中...' : '模式未知' })
  expect(nav).toBeDisabled()
  expect(screen.getByLabelText('凭据概览')).not.toHaveTextContent('当前')
  expect(within(row).queryByText(/当前|优先级/)).not.toBeInTheDocument()
  await user.click(nav)
  expect(server.find('PUT', '/config/load-balancing')).toHaveLength(0)
  if (state === 'loading') {
    await act(async () => { release({ data: { mode: 'balanced' } }) })
    expect(await screen.findByRole('button', { name: '均衡负载' })).toBeEnabled()
  }
})

it.each(['priority', 'balanced'])('已知%s模式后台读取失败保留缓存及原展示，不新增切换协议', async mode => {
  let failed = false
  installModeServer(() => failed ? { status: 500 } : { data: { mode } })
  const { queryClient } = renderWithQueryClient(<Dashboard onLogout={() => {}} />)
  const label = mode === 'priority' ? '优先级模式' : '均衡负载'
  await screen.findByRole('button', { name: label })
  failed = true
  await act(async () => { await queryClient.invalidateQueries({ queryKey: ['loadBalancingMode'] }) })
  expect(screen.getByRole('button', { name: label })).toBeEnabled()
  expect(screen.getByLabelText('凭据概览').textContent?.includes('当前选定 #7')).toBe(mode === 'priority')
})

it.each(['priority', 'balanced'])('从%s切换失败保留已知模式与同一isCurrent展示', async mode => {
  let release!: (value: { status: number }) => void
  installModeServer(request => request.method === 'PUT' ? new Promise(resolve => { release = resolve }) : { data: { mode } })
  const user = userEvent.setup()
  renderWithQueryClient(<Dashboard onLogout={() => {}} />)
  const label = mode === 'priority' ? '优先级模式' : '均衡负载'
  await user.click(await screen.findByRole('button', { name: label }))
  expect(screen.getByRole('button', { name: label })).toBeDisabled()
  expect(server.find('PUT', '/config/load-balancing')[0].body).toEqual({ mode: mode === 'priority' ? 'balanced' : 'priority' })
  await act(async () => { release({ status: 500 }) })
  await waitFor(() => expect(screen.getByRole('button', { name: label })).toBeEnabled())
  expect(screen.getByLabelText('凭据概览').textContent?.includes('当前选定 #7')).toBe(mode === 'priority')
  expect(screen.getByTestId('credential-row-7').textContent?.includes('当前选定')).toBe(mode === 'priority')
})

it('切换成功也等待真实query：priority→balanced→priority，同行展开和isCurrent不变', async () => {
  let mode = 'priority'
  let deferRead = false
  let releaseRead!: (value: { data: unknown }) => void
  let releaseWrite!: (value: { data: unknown }) => void
  installModeServer(request => {
    if (request.method === 'PUT') return new Promise(resolve => { releaseWrite = resolve })
    return deferRead ? new Promise(resolve => { releaseRead = resolve }) : { data: { mode } }
  })
  const user = userEvent.setup()
  renderWithQueryClient(<Dashboard onLogout={() => {}} />)
  await screen.findByRole('button', { name: '优先级模式' })
  await user.click(screen.getByRole('button', { name: '凭据 #7 详情' }))
  const row = screen.getByTestId('credential-row-7')
  for (const next of ['balanced', 'priority']) {
    const oldLabel = mode === 'priority' ? '优先级模式' : '均衡负载'
    await user.click(screen.getByRole('button', { name: oldLabel }))
    expect(screen.getByRole('button', { name: oldLabel })).toBeDisabled()
    deferRead = true
    const before = server.find('GET', '/config/load-balancing').length
    await act(async () => { releaseWrite({ data: { success: true } }) })
    await waitFor(() => expect(server.find('GET', '/config/load-balancing')).toHaveLength(before + 1))
    expect(screen.getByRole('button', { name: oldLabel })).toBeInTheDocument()
    expect(within(row).queryByText('当前选定') !== null).toBe(mode === 'priority')
    mode = next
    await act(async () => { releaseRead({ data: { mode } }) })
    await screen.findByRole('button', { name: mode === 'priority' ? '优先级模式' : '均衡负载' })
    expect(within(row).queryByText('当前选定') !== null).toBe(mode === 'priority')
    expect(screen.getByRole('button', { name: '凭据 #7 详情' })).toHaveAttribute('aria-expanded', 'true')
  }
  expect(server.find('PUT', '/config/load-balancing').map(request => request.body)).toEqual([{ mode: 'balanced' }, { mode: 'priority' }])
})

it('balanced详情保留优先级编辑/上下调原请求与开关，不改变服务端列表顺序', async () => {
  installModeServer(() => ({ data: { mode: 'balanced' } }))
  const user = userEvent.setup()
  renderWithQueryClient(<Dashboard onLogout={() => {}} />)
  await screen.findByRole('button', { name: '均衡负载' })
  await user.click(screen.getByRole('button', { name: '凭据 #7 详情' }))
  expect(screen.getByText('负载相同时优先，数字越小越优先')).toBeVisible()
  await user.click(screen.getByRole('button', { name: '编辑优先级' }))
  await user.clear(screen.getByRole('spinbutton'))
  await user.type(screen.getByRole('spinbutton'), '8')
  await user.click(screen.getByRole('button', { name: '保存优先级' }))
  await waitFor(() => expect(screen.queryByRole('spinbutton')).not.toBeInTheDocument())
  await user.click(screen.getByRole('button', { name: '提高优先级' }))
  await waitFor(() => expect(server.find('POST', '/credentials/7/priority')).toHaveLength(2))
  await waitFor(() => expect(screen.getByRole('button', { name: '降低优先级' })).toBeEnabled())
  await user.click(screen.getByRole('button', { name: '降低优先级' }))
  await waitFor(() => expect(server.find('POST', '/credentials/7/priority')).toHaveLength(3))
  expect(server.find('POST', '/credentials/7/priority').map(request => request.body)).toEqual([{ priority: 8 }, { priority: 3 }, { priority: 5 }])
  await user.click(screen.getByRole('switch', { name: '启用凭据 #7' }))
  await waitFor(() => expect(server.find('POST', '/credentials/7/disabled')).toHaveLength(1))
  expect(server.find('POST', '/credentials/7/disabled')[0].body).toEqual({ disabled: true })
  expect(screen.getAllByTestId(/^credential-row-/).map(item => item.dataset.testid)).toEqual(['credential-row-7', 'credential-row-2'])
})

it('导航主题、刷新、负载切换与退出仍可用且图标可访问', async () => {
  let mode = 'priority'
  server = installMockServer(request => {
    if (request.url === '/credentials') return { data: response([], false) }
    if (request.url === '/proxies') return { data: { proxies: [] } }
    if (request.url === '/config/load-balancing') {
      if (request.method === 'PUT') mode = 'balanced'
      return { data: { mode } }
    }
    throw new Error(request.url)
  })
  const user = userEvent.setup()
  const onLogout = vi.fn()
  renderWithQueryClient(<Dashboard onLogout={onLogout} />)
  await user.click(await screen.findByRole('button', { name: '优先级模式' }))
  expect(await screen.findByRole('button', { name: '均衡负载' })).toBeInTheDocument()
  expect(server.find('PUT', '/config/load-balancing')[0].body).toEqual({ mode: 'balanced' })
  const initial = document.documentElement.classList.contains('dark')
  await user.click(screen.getByRole('button', { name: '切换主题' }))
  expect(document.documentElement.classList.contains('dark')).toBe(!initial)
  await user.click(screen.getByRole('button', { name: '切换主题' }))
  const before = server.find('GET', '/credentials').length
  await user.click(screen.getByRole('button', { name: '刷新凭据列表' }))
  await waitFor(() => expect(server.find('GET', '/credentials').length).toBeGreaterThan(before))
  await user.click(screen.getByRole('button', { name: '退出登录' }))
  expect(onLogout).toHaveBeenCalledOnce()
})

it('后台状态变化令已选项不可见时不prune，清空选择仍可清全部页', async () => {
  let items = listFixture()
  mockDashboard(() => response(items, false))
  const user = userEvent.setup()
  const { queryClient } = renderWithQueryClient(<Dashboard onLogout={() => {}} />)
  await user.selectOptions(await screen.findByRole('combobox'), 'enabled')
  await user.click(screen.getByRole('checkbox', { name: '选择凭据 #1' }))
  await user.click(screen.getByRole('button', { name: '下一页' }))
  await user.click(screen.getByRole('checkbox', { name: '选择凭据 #25' }))
  items = items.map(item => item.id === 1 ? { ...item, disabled: true } : item)
  await act(async () => { await queryClient.invalidateQueries({ queryKey: ['credentials'] }) })
  await waitFor(() => expect(screen.getByText(/第 1 \/ 1 页/)).toBeInTheDocument())
  expect(screen.queryByTestId('credential-row-1')).not.toBeInTheDocument()
  expect(screen.getByText('已选 2 项')).toBeInTheDocument()
  await user.click(screen.getByRole('button', { name: '清空选择' }))
  expect(screen.getByText('已选 0 项')).toBeInTheDocument()
})

it('筛选后当前页查询只请求命中启用项，缓存余额进入摘要且不清选择', async () => {
  installListServer(compactItems(), () => ({ data: balanceResponse }))
  const user = userEvent.setup()
  renderWithQueryClient(<Dashboard onLogout={() => {}} />)
  await user.type(await screen.findByRole('searchbox'), ' alpha ')
  await user.click(screen.getByRole('checkbox', { name: '选择当前页' }))
  await user.click(screen.getByRole('button', { name: '查询当前页信息' }))
  await waitFor(() => expect(screen.getByTestId('credential-row-1')).toHaveTextContent('缓存余额：50.00'))
  expect(server.requests.filter(request => request.url.endsWith('/balance')).map(request => request.url)).toEqual(['/credentials/1/balance'])
  expect(screen.getByText('已选 1 项')).toBeInTheDocument()
})

it('批量刷新部分失败继续，disabled跳过而APIKey不新增排除，结束清选择', async () => {
  const items = compactItems().map(item => item.id === 3 ? { ...item, disabled: false } : item)
  installListServer(items, request => request.url === '/credentials/1/refresh' ? { status: 500 } : { data: { message: 'ok' } })
  const user = userEvent.setup()
  renderWithQueryClient(<Dashboard onLogout={() => {}} />)
  await user.click(await screen.findByRole('checkbox', { name: '选择当前页' }))
  await user.click(screen.getByRole('button', { name: '批量刷新 Token' }))
  await waitFor(() => expect(screen.getByText('已选 0 项')).toBeInTheDocument())
  expect(server.requests.filter(request => request.method === 'POST').map(request => request.url)).toEqual(['/credentials/1/refresh', '/credentials/3/refresh'])
  expect(await screen.findByText('刷新 Token：成功 1 个，失败 1 个')).toBeInTheDocument()
  expect(screen.getByRole('searchbox')).not.toHaveAttribute('readonly')
})

it('验活取消仅停止后续快照项，不在在途请求结束前解锁，失败结果可见且保留选择', async () => {
  let release!: (value: { status: number; data: unknown }) => void
  installListServer(compactItems(), () => new Promise(resolve => { release = resolve }))
  const user = userEvent.setup()
  renderWithQueryClient(<Dashboard onLogout={() => {}} />)
  await user.click(await screen.findByRole('checkbox', { name: '选择凭据 #1' }))
  await user.click(screen.getByRole('checkbox', { name: '选择凭据 #2' }))
  await user.click(screen.getByRole('button', { name: '批量验活' }))
  await waitFor(() => expect(server.find('GET', '/credentials/1/balance')).toHaveLength(1))
  await user.click(screen.getByRole('button', { name: '取消验活' }))
  await user.click(screen.getByRole('button', { name: '后台运行' }))
  expect(screen.getByRole('searchbox')).toHaveAttribute('readonly')
  await user.click(screen.getByRole('button', { name: /验活中/ }))
  await act(async () => { release({ status: 500, data: { error: { message: 'balance unavailable' } } }) })
  expect(await screen.findByText(/balance unavailable/)).toBeInTheDocument()
  await user.keyboard('{Escape}')
  expect(screen.getByRole('searchbox')).not.toHaveAttribute('readonly')
  expect(screen.getByText('已选 2 项')).toBeInTheDocument()
  expect(server.find('GET', '/credentials/2/balance')).toHaveLength(0)
})

it('键盘展开、选择及启停互不触发，独立行不跟随展开', async () => {
  installListServer(compactItems(), () => ({ data: { message: 'ok' } }))
  const user = userEvent.setup()
  renderWithQueryClient(<Dashboard onLogout={() => {}} />)
  const trigger = await screen.findByRole('button', { name: '凭据 #1 详情' })
  trigger.focus()
  await user.keyboard('{Enter}')
  expect(trigger).toHaveAttribute('aria-expanded', 'true')
  expect(screen.getByRole('button', { name: '凭据 #2 详情' })).toHaveAttribute('aria-expanded', 'false')
  screen.getByRole('checkbox', { name: '选择凭据 #1' }).focus()
  await user.keyboard(' ')
  expect(screen.getByText('已选 1 项')).toBeInTheDocument()
  screen.getByRole('switch', { name: '启用凭据 #1' }).focus()
  await user.keyboard(' ')
  await waitFor(() => expect(server.find('POST', '/credentials/1/disabled')).toHaveLength(1))
  expect(trigger).toHaveAttribute('aria-expanded', 'true')
  trigger.focus()
  await user.keyboard('{Enter}')
  expect(trigger).toHaveFocus()
  expect(screen.queryByRole('button', { name: '修改代理' })).not.toBeInTheDocument()
})

it('单项删除仅disabled允许，取消零写入，确认走原DELETE对象', async () => {
  installListServer(compactItems(), () => ({ data: { message: 'ok' } }))
  const user = userEvent.setup()
  renderWithQueryClient(<Dashboard onLogout={() => {}} />)
  await user.click(await screen.findByRole('button', { name: '凭据 #1 详情' }))
  expect(within(screen.getByTestId('credential-row-1')).getByRole('button', { name: '删除' })).toBeDisabled()
  await user.click(screen.getByRole('button', { name: '凭据 #2 详情' }))
  const row = within(screen.getByTestId('credential-row-2'))
  await user.click(row.getByRole('button', { name: '删除' }))
  await user.click(within(screen.getByRole('dialog')).getByRole('button', { name: '取消' }))
  expect(server.find('DELETE', '/credentials/2')).toHaveLength(0)
  await user.click(row.getByRole('button', { name: '删除' }))
  await user.click(within(screen.getByRole('dialog')).getByRole('button', { name: '确认删除' }))
  await waitFor(() => expect(server.find('DELETE', '/credentials/2')).toHaveLength(1))
})

function credential(proxyMode = 'inherit'): CredentialStatusItem {
  return {
    id: 7, priority: 0, disabled: false, failureCount: 0, isCurrent: false,
    expiresAt: null, authMethod: 'social', hasProfileArn: false, successCount: 0,
    lastUsedAt: null, hasProxy: false, proxyMode, refreshFailureCount: 0, endpoint: 'ide',
  }
}

function response(credentials: CredentialStatusItem[], global: unknown) {
  return {
    total: credentials.length, available: credentials.length, currentId: 0, credentials,
    ...(global === undefined ? {} : { globalProxyConfigured: global }),
  }
}

function mockDashboard(getData: () => unknown, proxies = [proxyItem()]) {
  server = installMockServer((request) => {
    if (request.url === '/credentials') return { data: getData() }
    if (request.url === '/proxies') return { data: { proxies } }
    if (request.url === '/config/load-balancing') return { data: { mode: 'priority' } }
    throw new Error(`Unexpected request: ${request.method} ${request.url}`)
  })
}

async function openDialog(user: ReturnType<typeof userEvent.setup>, editing: boolean) {
  if (editing) await user.click(await screen.findByRole('button', { name: '凭据 #7 详情' }))
  await user.click(await screen.findByRole('button', { name: editing ? '修改代理' : '添加凭据' }))
  return screen.getByRole('dialog')
}

const combinations = [true, false].flatMap((global) =>
  ['empty', 'direct', 'inherit'].flatMap((kind) =>
    // 零凭据没有编辑入口；其余组合同时走新增与编辑。
    (kind === 'empty' ? [false] : [false, true]).map((editing) => ({ global, kind, editing }))
  )
)

describe('Dashboard 查询到代理来源选择器的真实连线', () => {
  it.each(['代理列表', '添加凭据', '修改代理'])('%s 关闭恢复开启控件焦点且取消不写入', async (name) => {
    mockDashboard(() => response([credential(), { ...credential(), id: 8 }], false))
    const user = userEvent.setup()
    renderWithQueryClient(<Dashboard onLogout={() => {}} />)
    if (name === '修改代理') await user.click(await screen.findByRole('button', { name: '凭据 #8 详情' }))
    const openers = await screen.findAllByRole('button', { name })
    const opener = openers[openers.length - 1]
    for (const close of ['Escape', 'button']) {
      await user.click(opener)
      const dialog = await screen.findByRole('dialog', { name })
      if (name === '添加凭据') await user.type(within(dialog).getByLabelText(/Refresh Token/), 'cancelled-draft')
      if (name === '修改代理') await user.click(within(dialog).getByRole('radio', { name: '明确直连' }))
      if (close === 'Escape') await user.keyboard('{Escape}')
      else await user.click(within(dialog).getByRole('button', { name: name === '代理列表' ? '关闭' : '取消' }))
      await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument())
      await waitFor(() => expect(opener).toHaveFocus())
    }
    expect(server.requests.filter((request) => request.method !== 'GET')).toHaveLength(0)
  })

  it.each(combinations)('$global / $kind / editing=$editing：只以顶层布尔展示全局状态', async ({ global, kind, editing }) => {
    const credentials = kind === 'empty' ? [] : [credential(kind)]
    // 空代理列表与非空列表都不能决定全局状态。
    mockDashboard(() => response(credentials, global), global ? [] : [proxyItem()])
    const user = userEvent.setup()
    renderWithQueryClient(<Dashboard onLogout={() => {}} />)
    const dialog = await openDialog(user, editing)
    await user.click(within(dialog).getByRole('radio', { name: '使用全局代理配置' }))
    expect(within(dialog).getByText(global ? '已配置全局代理' : '未配置，使用系统默认网络')).toBeInTheDocument()
    // 初次成功后挂载的既有导入对话框复用该 stale 查询并触发一次刷新。
    expect(server.find('GET', '/credentials')).toHaveLength(2)
    expect(server.requests.filter((request) => request.method !== 'GET')).toHaveLength(0)
  })

  it.each([undefined, null, 'false', 'true', 0, 1, {}, []].map((global) => ({ global })))('异常顶层值 $global 不冒充未配置', async ({ global }) => {
    mockDashboard(() => response([credential()], global))
    const user = userEvent.setup()
    renderWithQueryClient(<Dashboard onLogout={() => {}} />)
    for (const editing of [false, true]) {
      const dialog = await openDialog(user, editing)
      expect(within(dialog).getByText('全局代理状态暂不可用')).toBeInTheDocument()
      expect(within(dialog).queryByText('未配置，使用系统默认网络')).not.toBeInTheDocument()
      await user.click(within(dialog).getByRole('button', { name: '取消' }))
    }
  })

  it('首次查询尚未完成时保留加载页，不提前给全局状态结论', async () => {
    let release!: (value: { data: unknown }) => void
    server = installMockServer((request) => request.url === '/credentials'
      ? new Promise((resolve) => { release = resolve })
      : { data: { mode: 'priority', proxies: [] } })
    renderWithQueryClient(<Dashboard onLogout={() => {}} />)
    expect(screen.getByText('加载中...')).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: '添加凭据' })).not.toBeInTheDocument()
    expect(screen.queryByText(/已配置全局代理|未配置，使用系统默认网络/)).not.toBeInTheDocument()
    await waitFor(() => expect(server.find('GET', '/credentials')).toHaveLength(1))
    await act(async () => { release({ data: response([], false) }) })
    expect(await screen.findByRole('button', { name: '添加凭据' })).toBeInTheDocument()
  })

  it('初次失败保留原失败页与重试入口', async () => {
    server = installMockServer((request) => request.url === '/credentials'
      ? { status: 500, data: { error: { message: 'failed' } } }
      : { data: { mode: 'priority', proxies: [] } })
    renderWithQueryClient(<Dashboard onLogout={() => {}} />)
    expect(await screen.findByText('加载失败')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: '重试' })).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: '添加凭据' })).not.toBeInTheDocument()
    expect(screen.queryByText(/已配置全局代理|未配置，使用系统默认网络/)).not.toBeInTheDocument()
  })

  it.each([false, true])('后台刷新更新说明且不重置新增/编辑表单 editing=%s', async (editing) => {
    let global = true
    mockDashboard(() => response([credential()], global))
    const user = userEvent.setup()
    const { queryClient } = renderWithQueryClient(<Dashboard onLogout={() => {}} />)
    const dialog = await openDialog(user, editing)
    const ui = within(dialog)
    expect(ui.getByText('已配置全局代理')).toBeInTheDocument()
    await user.click(ui.getByRole('radio', { name: '使用指定代理' }))
    await user.selectOptions(ui.getByLabelText('选择指定代理'), 'p1')
    await user.click(ui.getByRole('radio', { name: '高级：内联地址' }))
    await user.type(ui.getByLabelText('内联代理地址'), 'http://draft:8080')
    await user.type(ui.getByLabelText('内联代理用户名'), ' user ')
    await user.type(ui.getByLabelText('内联代理密码'), ' secret ')
    global = false
    await act(async () => { await queryClient.invalidateQueries({ queryKey: ['credentials'] }) })
    expect(ui.getByRole('radio', { name: '高级：内联地址' })).toBeChecked()
    expect(ui.getByLabelText('内联代理地址')).toHaveValue('http://draft:8080')
    expect(ui.getByLabelText('内联代理用户名')).toHaveValue(' user ')
    expect(ui.getByLabelText('内联代理密码')).toHaveValue(' secret ')
    await user.click(ui.getByRole('radio', { name: '使用指定代理' }))
    expect(ui.getByLabelText('选择指定代理')).toHaveValue('p1')
    await user.click(ui.getByRole('radio', { name: '使用全局代理配置' }))
    expect(ui.getByText('未配置，使用系统默认网络')).toBeInTheDocument()
    expect(ui.getByRole('radio', { name: '使用全局代理配置' })).toHaveAccessibleDescription('未配置，使用系统默认网络')
    expect(server.find('GET', '/credentials')).toHaveLength(3)
    expect(server.requests.filter((request) => request.method !== 'GET')).toHaveLength(0)
  })

  it('页面代理列表入口、空态与说明一致，创建不绑定凭据且刷新列表', async () => {
    let proxies: ReturnType<typeof proxyItem>[] = []
    server = installMockServer((request) => {
      if (request.url === '/credentials') return { data: response([credential()], true) }
      if (request.url === '/config/load-balancing') return { data: { mode: 'priority' } }
      if (request.url === '/proxies') {
        if (request.method === 'POST') proxies = [proxyItem()]
        return { data: { proxies } }
      }
      throw new Error(`Unexpected request: ${request.method} ${request.url}`)
    })
    const user = userEvent.setup()
    renderWithQueryClient(<Dashboard onLogout={() => {}} />)
    await user.click(await screen.findByRole('button', { name: '代理列表' }))
    expect(await screen.findByText('代理列表为空')).toBeInTheDocument()
    expect(screen.getByText(/添加后不会自动应用，需要在凭据中选择该代理。/)).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: '新增代理' }))
    await user.type(screen.getByLabelText('名称'), '家庭 SOCKS')
    await user.type(screen.getByLabelText('主机:端口'), '127.0.0.1:1080')
    await user.click(screen.getByRole('button', { name: '添加' }))
    expect(await screen.findByText('家庭 SOCKS')).toBeInTheDocument()
    await waitFor(() => expect(screen.getByRole('button', { name: '新增代理' })).toHaveFocus())
    await waitFor(() => expect(server.find('GET', '/proxies').length).toBeGreaterThan(1))
    expect(server.requests.filter((request) => request.method !== 'GET').map(({ method, url }) => ({ method, url })))
      .toEqual([{ method: 'POST', url: '/proxies' }])
  })
})

it('导航提示词入口真实加载配置，键盘关闭后焦点回到触发器', async () => {
  server = installMockServer((request) => {
    if (request.url === '/credentials') return { data: response([], false) }
    if (request.url === '/proxies') return { data: { proxies: [] } }
    if (request.url === '/config/load-balancing') return { data: { mode: 'priority' } }
    if (request.url === '/config/prompt-injection') return { data: { promptInjection: '全局前缀' } }
    throw new Error(`Unexpected request: ${request.method} ${request.url}`)
  })
  const user = userEvent.setup()
  renderWithQueryClient(<Dashboard onLogout={() => {}} />)
  const trigger = await screen.findByRole('button', { name: '提示词注入' })
  expect(trigger.closest('header')).not.toBeNull()
  expect(server.find('GET', '/config/prompt-injection')).toHaveLength(0)
  trigger.focus()
  await user.keyboard('{Enter}')
  const textarea = await screen.findByRole('textbox', { name: '注入提示词' })
  await waitFor(() => expect(textarea).toHaveValue('全局前缀'))
  await user.click(textarea)
  await user.keyboard('{Escape}')
  await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument())
  expect(trigger).toHaveFocus()
  expect(server.find('PUT', '/config/prompt-injection')).toHaveLength(0)
})

it.each([false, true])('后台刷新等待期间保留已有状态与表单，随后 false→true editing=%s', async (editing) => {
  let refreshing = false
  let release!: (value: { data: unknown }) => void
  server = installMockServer((request) => {
    if (request.url === '/credentials') return refreshing
      ? new Promise((resolve) => { release = resolve })
      : { data: response([credential()], false) }
    if (request.url === '/proxies') return { data: { proxies: [] } }
    return { data: { mode: 'priority' } }
  })
  const user = userEvent.setup()
  const { queryClient } = renderWithQueryClient(<Dashboard onLogout={() => {}} />)
  const dialog = await openDialog(user, editing)
  expect(within(dialog).getByText('未配置，使用系统默认网络')).toBeInTheDocument()
  if (!editing) await user.type(within(dialog).getByLabelText(/Refresh Token/), 'draft-token')
  refreshing = true
  let refresh!: Promise<void>
  act(() => { refresh = queryClient.invalidateQueries({ queryKey: ['credentials'] }) })
  await waitFor(() => expect(queryClient.isFetching({ queryKey: ['credentials'] })).toBe(1))
  expect(within(dialog).getByText('未配置，使用系统默认网络')).toBeInTheDocument()
  expect(screen.queryByText('加载失败')).not.toBeInTheDocument()
  await act(async () => { release({ data: response([credential()], true) }); await refresh })
  expect(await within(dialog).findByText('已配置全局代理')).toBeInTheDocument()
  expect(within(dialog).getByRole('radio', { name: '使用全局代理配置' })).toHaveAccessibleDescription('已配置全局代理')
  expect(within(dialog).getByRole('radio', { name: '使用全局代理配置' })).toBeChecked()
  if (!editing) expect(within(dialog).getByLabelText(/Refresh Token/)).toHaveValue('draft-token')
})
