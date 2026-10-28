import { describe, it, expect, afterEach } from 'vitest'
import { screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { renderWithQueryClient } from '@/test/harness'
import { installMockServer, proxyItem } from '@/test/mock-server'
import { ProxyPoolDialog } from '@/components/proxy-pool-dialog'

let server: ReturnType<typeof installMockServer>

afterEach(() => {
  server?.restore()
})

function renderPanel() {
  return renderWithQueryClient(<ProxyPoolDialog open onOpenChange={() => {}} />)
}

describe('代理池面板', () => {
  it.each([
    { empty: true, editing: false },
    { empty: false, editing: false },
    { empty: false, editing: true },
  ])('子弹窗关闭保留父列表并恢复开启按钮 empty=$empty editing=$editing', async ({ empty, editing }) => {
    server = installMockServer(() => ({ data: { proxies: empty ? [] : [proxyItem()] } }))
    const user = userEvent.setup()
    renderPanel()
    if (empty) await screen.findByText('代理列表为空')
    else await screen.findByText('家庭 SOCKS')
    const opener = screen.getByRole('button', { name: editing ? '编辑 家庭 SOCKS' : '新增代理' })
    for (const close of ['Escape', '取消', '关闭']) {
      await user.click(opener)
      const dialog = await screen.findByRole('dialog', { name: editing ? '编辑代理' : '新增代理' })
      const name = within(dialog).getByRole('textbox', { name: '名称' })
      await user.clear(name)
      await user.type(name, '取消的草稿')
      if (close === 'Escape') await user.keyboard('{Escape}')
      else await user.click(within(dialog).getByRole('button', { name: close }))
      await waitFor(() => expect(screen.queryByRole('dialog', { name: editing ? '编辑代理' : '新增代理' })).not.toBeInTheDocument())
      expect(screen.getByRole('dialog', { name: '代理列表' })).toBeInTheDocument()
      await waitFor(() => expect(opener).toHaveFocus())
    }
    expect(server.requests.filter((request) => request.method !== 'GET')).toHaveLength(0)
  })

  it('编辑保存并刷新名称后仍恢复到同一条目的编辑按钮', async () => {
    let proxy = proxyItem()
    server = installMockServer((request) => {
      if (request.method === 'PATCH') proxy = proxyItem({ name: '新名称' })
      return { data: { proxies: [proxy] } }
    })
    const user = userEvent.setup()
    renderPanel()
    await user.click(await screen.findByRole('button', { name: '编辑 家庭 SOCKS' }))
    const dialog = await screen.findByRole('dialog', { name: '编辑代理' })
    await user.clear(within(dialog).getByRole('textbox', { name: '名称' }))
    await user.type(within(dialog).getByRole('textbox', { name: '名称' }), '新名称')
    await user.click(within(dialog).getByRole('button', { name: '保存' }))
    await waitFor(() => expect(screen.queryByRole('dialog', { name: '编辑代理' })).not.toBeInTheDocument())
    await waitFor(() => expect(screen.getByRole('button', { name: '编辑 新名称' })).toHaveFocus())
    expect(server.find('PATCH', '/proxies/p1')).toHaveLength(1)
  })

  it('列表展示名称、脱敏 url、协议、用户名、是否有密码、被引用数', async () => {
    server = installMockServer(() => ({
      data: {
        proxies: [
          proxyItem({
            username: 'alice',
            hasPassword: true,
            referenceCount: 3,
            url: 'socks5h://127.0.0.1:1080/',
          }),
        ],
      },
    }))

    renderPanel()

    expect(await screen.findByText('家庭 SOCKS')).toBeInTheDocument()
    expect(screen.getByText('socks5h://127.0.0.1:1080/')).toBeInTheDocument()
    expect(screen.getByText('SOCKS5h')).toBeInTheDocument()
    expect(screen.getByText('用户名：alice')).toBeInTheDocument()
    expect(screen.getByText('含密码')).toBeInTheDocument()
    expect(screen.getByText('被 3 个凭据引用')).toBeInTheDocument()
  })

  it('不展示伪造的健康/可用指标，也没有测试按钮', async () => {
    server = installMockServer(() => ({ data: { proxies: [proxyItem()] } }))
    renderPanel()

    await screen.findByText('家庭 SOCKS')
    expect(screen.queryByText(/健康/)).not.toBeInTheDocument()
    expect(screen.queryByText(/可用/)).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: /测试/ })).not.toBeInTheDocument()
  })

  it.each(['Escape', '取消', '关闭'])('删除确认通过 %s 关闭后保留列表、恢复删除按钮且不发 DELETE', async (close) => {
    server = installMockServer(() => ({ data: { proxies: [proxyItem()] } }))
    const user = userEvent.setup()
    renderPanel()
    const opener = await screen.findByRole('button', { name: '删除 家庭 SOCKS' })
    await user.click(opener)
    const dialog = await screen.findByRole('dialog', { name: '删除代理' })
    if (close === 'Escape') await user.keyboard('{Escape}')
    else await user.click(within(dialog).getByRole('button', { name: close }))
    await waitFor(() => expect(screen.queryByRole('dialog', { name: '删除代理' })).not.toBeInTheDocument())
    expect(screen.getByRole('dialog', { name: '代理列表' })).toBeInTheDocument()
    expect(screen.getByRole('listitem')).toHaveTextContent('家庭 SOCKS')
    expect(server.requests.filter((request) => request.method === 'DELETE')).toHaveLength(0)
    await waitFor(() => expect(opener).toHaveFocus())
  })

  it('删除被引用代理收到 409 时保留冲突，取消后恢复删除按钮与原条目', async () => {
    server = installMockServer((request) => {
      if (request.method === 'DELETE') {
        return {
          status: 409,
          data: {
            error: { type: 'conflict', message: '代理仍被 2 个凭据引用，请先解除绑定' },
          },
        }
      }
      return { data: { proxies: [proxyItem({ referenceCount: 2 })] } }
    })

    const user = userEvent.setup()
    renderPanel()

    await user.click(await screen.findByRole('button', { name: '删除 家庭 SOCKS' }))
    const dialog = await screen.findByRole('dialog')
    await user.click(within(dialog).getByRole('button', { name: '确认删除' }))

    const alert = await screen.findByRole('alert')
    expect(alert).toHaveTextContent('代理仍被 2 个凭据引用，请先解除绑定')
    // 对话框仍开着，用户可据此去解绑
    expect(screen.getByRole('dialog')).toBeInTheDocument()
    await user.click(within(dialog).getByRole('button', { name: '取消' }))
    await waitFor(() => expect(screen.queryByRole('dialog', { name: '删除代理' })).not.toBeInTheDocument())
    expect(screen.getByRole('dialog', { name: '代理列表' })).toBeInTheDocument()
    expect(screen.getByRole('listitem')).toHaveTextContent('家庭 SOCKS')
    expect(server.find('DELETE', '/proxies/p1')).toHaveLength(1)
    await waitFor(() => expect(screen.getByRole('button', { name: '删除 家庭 SOCKS' })).toHaveFocus())
  })

  it('删除成功且刷新移除条目后恢复到稳定的新增按钮，请求路径正确', async () => {
    let proxies = [proxyItem()]
    server = installMockServer((request) => {
      if (request.method === 'DELETE') proxies = []
      return { data: { proxies } }
    })

    const user = userEvent.setup()
    renderPanel()

    await user.click(await screen.findByRole('button', { name: '删除 家庭 SOCKS' }))
    const dialog = await screen.findByRole('dialog')
    await user.click(within(dialog).getByRole('button', { name: '确认删除' }))

    await waitFor(() => expect(server.find('DELETE', '/proxies/p1')).toHaveLength(1))
    await waitFor(() => expect(screen.queryByRole('dialog', { name: '删除代理' })).not.toBeInTheDocument())
    expect(await screen.findByText('代理列表为空')).toBeInTheDocument()
    expect(within(screen.getByRole('dialog', { name: '代理列表' })).queryByRole('listitem')).not.toBeInTheDocument()
    expect(screen.getByRole('dialog', { name: '代理列表' })).toBeInTheDocument()
    await waitFor(() => expect(screen.getByRole('button', { name: '新增代理' })).toHaveFocus())
  })

  it.each(['loading', 'error'])('%s 不是成功空池，新增入口禁用且不显示升级警告', async (state) => {
    server = installMockServer(() => state === 'loading'
      ? new Promise(() => {})
      : { status: 500, data: { error: { message: '池查询失败' } } })
    const user = userEvent.setup()
    renderPanel()
    if (state === 'error') await screen.findByText(/加载失败/)
    const add = screen.getByRole('button', { name: '新增代理' })
    expect(add).toBeDisabled()
    await user.click(add)
    expect(screen.queryByRole('note')).not.toBeInTheDocument()
    expect(screen.queryByText('代理列表为空')).not.toBeInTheDocument()
    expect(screen.queryByRole('dialog', { name: '新增代理' })).not.toBeInTheDocument()
  })

  it('空池的唯一新增入口属于空态，非空池保留唯一顶部入口', async () => {
    let proxies: ReturnType<typeof proxyItem>[] = []
    server = installMockServer(() => ({ data: { proxies } }))
    const { queryClient } = renderPanel()
    const empty = await screen.findByText('代理列表为空')
    expect(screen.getAllByRole('button', { name: '新增代理' })).toHaveLength(1)
    expect(within(empty.parentElement!).getByRole('button', { name: '新增代理' })).toBeEnabled()
    proxies = [proxyItem()]
    await queryClient.invalidateQueries({ queryKey: ['proxies'] })
    expect(await screen.findByRole('listitem')).toHaveTextContent('家庭 SOCKS')
    expect(screen.queryByText('代理列表为空')).not.toBeInTheDocument()
    expect(screen.getAllByRole('button', { name: '新增代理' })).toHaveLength(1)
  })

  it('空池时显示空态，并可打开新增对话框（含升级提示）', async () => {
    server = installMockServer(() => ({ data: { proxies: [] } }))
    const user = userEvent.setup()
    renderPanel()

    expect(await screen.findByText('代理列表为空')).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: /新增代理/ }))

    expect(await screen.findByRole('note')).toBeInTheDocument()
  })
})
