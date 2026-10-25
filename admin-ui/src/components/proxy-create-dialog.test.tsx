import { describe, it, expect, beforeEach, afterEach } from 'vitest'
import { screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { renderWithQueryClient } from '@/test/harness'
import { installMockServer, proxyItem } from '@/test/mock-server'
import { ProxyCreateDialog, ENVELOPE_NOTICE } from '@/components/proxy-create-dialog'

let server: ReturnType<typeof installMockServer>

afterEach(() => {
  server?.restore()
})

function renderDialog(isFirstProxy: boolean) {
  return renderWithQueryClient(
    <ProxyCreateDialog open onOpenChange={() => {}} isFirstProxy={isFirstProxy} />
  )
}

describe('新增代理对话框', () => {
  beforeEach(() => {
    server = installMockServer(() => ({ data: { proxies: [proxyItem()] } }))
  })

  it('默认协议是 SOCKS5h 并说明由代理端解析域名', async () => {
    renderDialog(true)

    expect(screen.getByLabelText('协议')).toHaveValue('socks5h')
    expect(screen.getByText(/域名由代理端解析/)).toBeInTheDocument()
  })

  it('池为空时展示封套升级提示，非首个代理时不展示', () => {
    const { unmount } = renderDialog(true)
    expect(screen.getByRole('note')).toHaveTextContent(ENVELOPE_NOTICE)
    unmount()

    renderDialog(false)
    expect(screen.queryByRole('note')).not.toBeInTheDocument()
  })

  it('提交时只发送 name/url/认证，不发送 id', async () => {
    const user = userEvent.setup()
    renderDialog(false)

    await user.type(screen.getByLabelText('名称'), '家庭 SOCKS')
    await user.clear(screen.getByLabelText('主机:端口'))
    await user.type(screen.getByLabelText('主机:端口'), '127.0.0.1:1080')
    await user.click(screen.getByRole('button', { name: '添加' }))

    await waitFor(() => expect(server.find('POST', '/proxies')).toHaveLength(1))
    expect(server.find('POST', '/proxies')[0].body).toEqual({
      name: '家庭 SOCKS',
      url: 'socks5h://127.0.0.1:1080',
      username: undefined,
      password: undefined,
    })
    expect(server.find('POST', '/proxies')[0].body).not.toHaveProperty('id')
  })

  it('密码逐字发送：含空格不被 trim', async () => {
    const user = userEvent.setup()
    renderDialog(false)

    await user.type(screen.getByLabelText('名称'), 'P')
    await user.type(screen.getByLabelText('主机:端口'), 'h:1')
    await user.type(screen.getByLabelText('代理用户名'), 'user')
    await user.type(screen.getByLabelText('代理密码'), ' pa ss ')
    await user.click(screen.getByRole('button', { name: '添加' }))

    await waitFor(() => expect(server.find('POST', '/proxies')).toHaveLength(1))
    expect(server.find('POST', '/proxies')[0].body).toMatchObject({
      username: 'user',
      password: ' pa ss ',
    })
  })

  it('用户名与密码只填其一时阻止提交并提示成对', async () => {
    const user = userEvent.setup()
    renderDialog(false)

    await user.type(screen.getByLabelText('名称'), 'P')
    await user.type(screen.getByLabelText('主机:端口'), 'h:1')
    await user.type(screen.getByLabelText('代理用户名'), 'only-user')
    await user.click(screen.getByRole('button', { name: '添加' }))

    expect(await screen.findByText(/必须同时填写/)).toBeInTheDocument()
    expect(server.find('POST', '/proxies')).toHaveLength(0)
  })

  it('失败时保留已填输入并展示后端 message', async () => {
    server.restore()
    server = installMockServer(() => ({
      status: 400,
      data: { error: { type: 'invalid_request', message: '代理 URL 缺少主机名' } },
    }))

    const user = userEvent.setup()
    renderDialog(false)

    await user.type(screen.getByLabelText('名称'), '保留我')
    await user.type(screen.getByLabelText('主机:端口'), 'bad')
    await user.click(screen.getByRole('button', { name: '添加' }))

    expect(await screen.findByText(/代理 URL 缺少主机名/)).toBeInTheDocument()
    expect(screen.getByLabelText('名称')).toHaveValue('保留我')
    expect(screen.getByLabelText('主机:端口')).toHaveValue('bad')
  })

  it('提交中重复点击只发一次请求', async () => {
    let release: (() => void) | undefined
    const gate = new Promise<void>((resolve) => {
      release = resolve
    })
    server.restore()
    server = installMockServer(async () => {
      await gate
      return { data: { proxies: [proxyItem()] } }
    })

    const user = userEvent.setup()
    renderDialog(false)

    await user.type(screen.getByLabelText('名称'), 'P')
    await user.type(screen.getByLabelText('主机:端口'), 'h:1')

    const submit = screen.getByRole('button', { name: '添加' })
    await user.click(submit)
    await user.click(submit)
    await user.click(submit)

    release?.()

    await waitFor(() => expect(server.find('POST', '/proxies')).toHaveLength(1))
  })
})
