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

  it('删除被引用代理收到 409 时，冲突原因留在界面上', async () => {
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
  })

  it('删除成功后请求路径正确', async () => {
    server = installMockServer((request) => {
      if (request.method === 'DELETE') {
        return { data: { proxies: [] } }
      }
      return { data: { proxies: [proxyItem()] } }
    })

    const user = userEvent.setup()
    renderPanel()

    await user.click(await screen.findByRole('button', { name: '删除 家庭 SOCKS' }))
    const dialog = await screen.findByRole('dialog')
    await user.click(within(dialog).getByRole('button', { name: '确认删除' }))

    await waitFor(() => expect(server.find('DELETE', '/proxies/p1')).toHaveLength(1))
  })

  it('空池时显示空态，并可打开新增对话框（含升级提示）', async () => {
    server = installMockServer(() => ({ data: { proxies: [] } }))
    const user = userEvent.setup()
    renderPanel()

    expect(await screen.findByText('暂无代理')).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: /新增代理/ }))

    expect(await screen.findByRole('note')).toBeInTheDocument()
  })
})
