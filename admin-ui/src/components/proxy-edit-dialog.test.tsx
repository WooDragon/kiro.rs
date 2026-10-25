import { describe, it, expect, afterEach } from 'vitest'
import { screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { renderWithQueryClient } from '@/test/harness'
import { installMockServer } from '@/test/mock-server'
import { ProxyEditDialog } from '@/components/proxy-edit-dialog'
import type { ProxyItem } from '@/types/proxy'

let server: ReturnType<typeof installMockServer>

afterEach(() => {
  server?.restore()
})

const existing: ProxyItem = {
  id: 'p1',
  name: '家庭 SOCKS',
  url: 'socks5h://127.0.0.1:1080/',
  username: 'alice',
  hasPassword: true,
  referenceCount: 2,
}

function renderEdit(proxy: ProxyItem = existing) {
  return renderWithQueryClient(<ProxyEditDialog proxy={proxy} onClose={() => {}} />)
}

/** 断言 PATCH 请求体只包含期望的键 */
async function patchedBody() {
  await waitFor(() => expect(server.find('PATCH', '/proxies/p1')).toHaveLength(1))
  return server.find('PATCH', '/proxies/p1')[0].body as Record<string, unknown>
}

describe('编辑代理：密码三态', () => {
  it('默认“保持不变”：请求体里根本不出现 username/password 键', async () => {
    server = installMockServer(() => ({ data: { proxies: [] } }))
    const user = userEvent.setup()
    renderEdit()

    expect(screen.getByLabelText('密码操作')).toHaveValue('keep')
    await user.click(screen.getByRole('button', { name: '保存' }))

    const body = await patchedBody()
    expect(body).not.toHaveProperty('password')
    expect(body).not.toHaveProperty('username')
    expect(body).toEqual({ name: '家庭 SOCKS' })
  })

  it('保持密码时单独改用户名：只发 username，不发 password', async () => {
    server = installMockServer(() => ({ data: { proxies: [] } }))
    const user = userEvent.setup()
    renderEdit()

    const usernameInput = screen.getByLabelText('认证')
    await user.clear(usernameInput)
    await user.type(usernameInput, 'bob')
    await user.click(screen.getByRole('button', { name: '保存' }))

    const body = await patchedBody()
    expect(body).toEqual({ name: '家庭 SOCKS', username: 'bob' })
    expect(body).not.toHaveProperty('password')
    expect(body).not.toHaveProperty('url')
  })

  it('密码输入框留空不会隐式清除：改 name 且不动密码 → 无 password 键', async () => {
    server = installMockServer(() => ({ data: { proxies: [] } }))
    const user = userEvent.setup()
    renderEdit()

    const nameInput = screen.getByLabelText('名称')
    await user.clear(nameInput)
    await user.type(nameInput, '改名后')
    await user.click(screen.getByRole('button', { name: '保存' }))

    const body = await patchedBody()
    expect(body.name).toBe('改名后')
    expect(body).not.toHaveProperty('password')
  })

  it('“替换密码”发送新值，含空格逐字保留', async () => {
    server = installMockServer(() => ({ data: { proxies: [] } }))
    const user = userEvent.setup()
    renderEdit()

    await user.selectOptions(screen.getByLabelText('密码操作'), 'replace')
    await user.type(screen.getByLabelText('新密码'), ' new pass ')
    await user.click(screen.getByRole('button', { name: '保存' }))

    const body = await patchedBody()
    expect(body.username).toBe('alice')
    expect(body.password).toBe(' new pass ')
  })

  it('“替换密码”下空密码发送空串（明确的空密码）', async () => {
    server = installMockServer(() => ({ data: { proxies: [] } }))
    const user = userEvent.setup()
    renderEdit()

    await user.selectOptions(screen.getByLabelText('密码操作'), 'replace')
    await user.click(screen.getByRole('button', { name: '保存' }))

    const body = await patchedBody()
    expect(body).toHaveProperty('password')
    expect(body.password).toBe('')
  })

  it('“清除认证”同时发送 username 与 password 的 null', async () => {
    server = installMockServer(() => ({ data: { proxies: [] } }))
    const user = userEvent.setup()
    renderEdit()

    await user.selectOptions(screen.getByLabelText('密码操作'), 'clear')
    await user.click(screen.getByRole('button', { name: '保存' }))

    const body = await patchedBody()
    expect(body).toHaveProperty('username')
    expect(body).toHaveProperty('password')
    expect(body.username).toBeNull()
    expect(body.password).toBeNull()
  })

  it('改协议与主机端口会拼进 url', async () => {
    server = installMockServer(() => ({ data: { proxies: [] } }))
    const user = userEvent.setup()
    renderEdit()

    await user.selectOptions(screen.getByLabelText('协议'), 'http')
    const host = screen.getByLabelText('主机:端口')
    await user.clear(host)
    await user.type(host, '10.0.0.5:3128')
    await user.click(screen.getByRole('button', { name: '保存' }))

    const body = await patchedBody()
    expect(body.url).toBe('http://10.0.0.5:3128')
  })

  it('失败时保留输入并展示后端 message', async () => {
    server = installMockServer(() => ({
      status: 400,
      data: { error: { type: 'invalid_request', message: '代理 URL 不能包含路径' } },
    }))
    const user = userEvent.setup()
    renderEdit()

    const nameInput = screen.getByLabelText('名称')
    await user.clear(nameInput)
    await user.type(nameInput, '会失败的改名')
    await user.click(screen.getByRole('button', { name: '保存' }))

    expect(await screen.findByText(/代理 URL 不能包含路径/)).toBeInTheDocument()
    expect(screen.getByLabelText('名称')).toHaveValue('会失败的改名')
  })
})

describe('编辑代理：地址未改动时不回传 url', () => {
  /** 后端回显的规范化形式：http 无路径时带尾 `/` */
  const httpProxy: ProxyItem = {
    id: 'p1',
    name: '家庭 HTTP',
    url: 'http://127.0.0.1:13128/',
    username: 'alice',
    hasPassword: true,
    referenceCount: 2,
  }

  it('http 代理只改名不发送 url', async () => {
    server = installMockServer(() => ({ data: { proxies: [] } }))
    const user = userEvent.setup()
    renderEdit(httpProxy)

    const nameInput = screen.getByLabelText('名称')
    await user.clear(nameInput)
    await user.type(nameInput, '只改名的 HTTP')
    await user.click(screen.getByRole('button', { name: '保存' }))

    const body = await patchedBody()
    expect(body).toEqual({ name: '只改名的 HTTP' })
    expect(Object.prototype.hasOwnProperty.call(body, 'url')).toBe(false)
  })

  it('改主机端口才发送 url', async () => {
    server = installMockServer(() => ({ data: { proxies: [] } }))
    const user = userEvent.setup()
    renderEdit(httpProxy)

    const host = screen.getByLabelText('主机:端口')
    await user.clear(host)
    await user.type(host, '10.0.0.5:3128')
    await user.click(screen.getByRole('button', { name: '保存' }))

    const body = await patchedBody()
    expect(body.url).toBe('http://10.0.0.5:3128')
  })
})
