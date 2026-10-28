import { describe, it, expect, afterEach } from 'vitest'
import { act, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { renderWithQueryClient } from '@/test/harness'
import { installMockServer, proxyItem } from '@/test/mock-server'
import { Dashboard } from '@/components/dashboard'
import type { CredentialStatusItem } from '@/types/api'

let server: ReturnType<typeof installMockServer>
afterEach(() => server?.restore())

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
    if (request.url === '/load-balancing-mode') return { data: { mode: 'priority' } }
    throw new Error(`Unexpected request: ${request.method} ${request.url}`)
  })
}

async function openDialog(user: ReturnType<typeof userEvent.setup>, editing: boolean) {
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
  it.each(combinations)('$global / $kind / editing=$editing：只以顶层布尔展示全局状态', async ({ global, kind, editing }) => {
    const credentials = kind === 'empty' ? [] : [credential(kind)]
    // 空代理列表与非空列表都不能决定全局状态。
    mockDashboard(() => response(credentials, global), global ? [] : [proxyItem()])
    const user = userEvent.setup()
    renderWithQueryClient(<Dashboard onLogout={() => {}} />)
    const dialog = await openDialog(user, editing)
    await user.selectOptions(within(dialog).getByLabelText('代理来源'), 'inherit')
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
    await user.selectOptions(ui.getByLabelText('代理来源'), 'pool')
    await user.selectOptions(ui.getByLabelText('选择指定代理'), 'p1')
    await user.selectOptions(ui.getByLabelText('代理来源'), 'inline')
    await user.type(ui.getByLabelText('内联代理地址'), 'http://draft:8080')
    await user.type(ui.getByLabelText('内联代理用户名'), ' user ')
    await user.type(ui.getByLabelText('内联代理密码'), ' secret ')
    global = false
    await act(async () => { await queryClient.invalidateQueries({ queryKey: ['credentials'] }) })
    expect(ui.getByLabelText('代理来源')).toHaveValue('inline')
    expect(ui.getByLabelText('内联代理地址')).toHaveValue('http://draft:8080')
    expect(ui.getByLabelText('内联代理用户名')).toHaveValue(' user ')
    expect(ui.getByLabelText('内联代理密码')).toHaveValue(' secret ')
    await user.selectOptions(ui.getByLabelText('代理来源'), 'pool')
    expect(ui.getByLabelText('选择指定代理')).toHaveValue('p1')
    await user.selectOptions(ui.getByLabelText('代理来源'), 'inherit')
    expect(ui.getByText('未配置，使用系统默认网络')).toBeInTheDocument()
    expect(server.find('GET', '/credentials')).toHaveLength(3)
    expect(server.requests.filter((request) => request.method !== 'GET')).toHaveLength(0)
  })

  it('页面代理列表入口、空态与说明一致，创建不绑定凭据且刷新列表', async () => {
    let proxies: ReturnType<typeof proxyItem>[] = []
    server = installMockServer((request) => {
      if (request.url === '/credentials') return { data: response([credential()], true) }
      if (request.url === '/load-balancing-mode') return { data: { mode: 'priority' } }
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
  expect(within(dialog).getByLabelText('代理来源')).toHaveValue('inherit')
  if (!editing) expect(within(dialog).getByLabelText(/Refresh Token/)).toHaveValue('draft-token')
})
