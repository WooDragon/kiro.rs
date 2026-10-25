import { describe, it, expect, afterEach } from 'vitest'
import { screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { renderWithQueryClient } from '@/test/harness'
import { installMockServer, proxyItem } from '@/test/mock-server'
import { CredentialProxyDialog } from '@/components/credential-proxy-dialog'
import type { CredentialStatusItem } from '@/types/api'

let server: ReturnType<typeof installMockServer>

afterEach(() => {
  server?.restore()
})

function credential(overrides: Partial<CredentialStatusItem> = {}): CredentialStatusItem {
  return {
    id: 7,
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

function renderDialog(item: CredentialStatusItem) {
  return renderWithQueryClient(<CredentialProxyDialog credential={item} onClose={() => {}} />)
}

async function boundBody() {
  await waitFor(() => expect(server.find('PUT', '/credentials/7/proxy')).toHaveLength(1))
  return server.find('PUT', '/credentials/7/proxy')[0].body
}

function preloadProxies() {
  server = installMockServer((request) => {
    if (request.method === 'GET' && request.url === '/proxies') {
      return { data: { proxies: [proxyItem()] } }
    }
    return { data: { proxies: [proxyItem({ referenceCount: 1 })] } }
  })
}

describe('凭据代理选择：四种模式发出的请求体', () => {
  it('继承全局 → {"mode":"inherit"}', async () => {
    preloadProxies()
    const user = userEvent.setup()
    renderDialog(credential({ proxyMode: 'direct' }))

    await user.selectOptions(screen.getByLabelText('代理来源'), 'inherit')
    await user.click(screen.getByRole('button', { name: '保存' }))

    expect(await boundBody()).toEqual({ mode: 'inherit' })
  })

  it('明确直连 → {"mode":"direct"}', async () => {
    preloadProxies()
    const user = userEvent.setup()
    renderDialog(credential())

    await user.selectOptions(screen.getByLabelText('代理来源'), 'direct')
    await user.click(screen.getByRole('button', { name: '保存' }))

    expect(await boundBody()).toEqual({ mode: 'direct' })
  })

  it('代理池 → {"mode":"pool","proxyId":...}', async () => {
    preloadProxies()
    const user = userEvent.setup()
    renderDialog(credential())

    await user.selectOptions(screen.getByLabelText('代理来源'), 'pool')
    await waitFor(() => expect(screen.getByLabelText('选择池代理')).toBeInTheDocument())
    await user.selectOptions(screen.getByLabelText('选择池代理'), 'p1')
    await user.click(screen.getByRole('button', { name: '保存' }))

    expect(await boundBody()).toEqual({ mode: 'pool', proxyId: 'p1' })
  })

  it('高级内联 → {"mode":"inline",url,...}，密码含空格不被 trim', async () => {
    preloadProxies()
    const user = userEvent.setup()
    renderDialog(credential())

    await user.selectOptions(screen.getByLabelText('代理来源'), 'inline')
    await user.type(screen.getByLabelText('内联代理地址'), 'socks5://10.0.0.9:1080')
    await user.type(screen.getByLabelText('内联代理用户名'), 'bob')
    await user.type(screen.getByLabelText('内联代理密码'), ' pw ')
    await user.click(screen.getByRole('button', { name: '保存' }))

    expect(await boundBody()).toEqual({
      mode: 'inline',
      url: 'socks5://10.0.0.9:1080',
      username: 'bob',
      password: ' pw ',
    })
  })
})

describe('凭据代理选择：界面与失败处理', () => {
  it('展示实际代理来源（继承全局并显示继承到的地址）', () => {
    preloadProxies()
    renderDialog(
      credential({
        proxyMode: 'inherit',
        hasProxy: true,
        effectiveProxyUrl: 'http://global-proxy:3128/',
      })
    )

    expect(screen.getByTestId('effective-proxy-url')).toHaveTextContent(
      '实际地址：http://global-proxy:3128/'
    )
  })

  it('池模式展示条目名称与脱敏地址，且不出现密码回显', () => {
    preloadProxies()
    renderDialog(
      credential({
        proxyMode: 'pool',
        proxyId: 'p1',
        proxyName: '家庭 SOCKS',
        effectiveProxyUrl: 'socks5h://127.0.0.1:1080/',
      })
    )

    expect(screen.getByText(/代理池 · 家庭 SOCKS/)).toBeInTheDocument()
    expect(screen.getByText(/socks5h:\/\/127\.0\.0\.1:1080\//)).toBeInTheDocument()
    // 界面上不存在可提交的密码字面值，也没有星号占位
    expect(screen.queryByDisplayValue('******')).not.toBeInTheDocument()
  })

  it('池模式未选条目时阻止提交并提示', async () => {
    preloadProxies()
    const user = userEvent.setup()
    renderDialog(credential())

    await user.selectOptions(screen.getByLabelText('代理来源'), 'pool')
    await user.click(screen.getByRole('button', { name: '保存' }))

    expect(await screen.findByText('请选择代理池条目')).toBeInTheDocument()
    expect(server.find('PUT', '/credentials/7/proxy')).toHaveLength(0)
  })

  it('失败时展示后端 message 并保留表单', async () => {
    server = installMockServer((request) => {
      if (request.method === 'GET' && request.url === '/proxies') {
        return { data: { proxies: [proxyItem()] } }
      }
      return {
        status: 400,
        data: {
          error: {
            type: 'invalid_request',
            message: '凭据文件不可回写（单对象格式或无保存路径），代理池操作被拒绝',
          },
        },
      }
    })
    const user = userEvent.setup()
    renderDialog(credential())

    await user.selectOptions(screen.getByLabelText('代理来源'), 'direct')
    await user.click(screen.getByRole('button', { name: '保存' }))

    expect(await screen.findByText(/代理池操作被拒绝/)).toBeInTheDocument()
    // 表单仍在，选择未被重置
    expect(screen.getByLabelText('代理来源')).toHaveValue('direct')
  })

  it('提交中重复点击只发一次请求', async () => {
    let release: (() => void) | undefined
    const gate = new Promise<void>((resolve) => {
      release = resolve
    })
    server = installMockServer(async (request) => {
      if (request.method === 'GET' && request.url === '/proxies') {
        return { data: { proxies: [proxyItem()] } }
      }
      await gate
      return { data: { proxies: [proxyItem()] } }
    })

    const user = userEvent.setup()
    renderDialog(credential())

    await user.selectOptions(screen.getByLabelText('代理来源'), 'direct')
    const submit = screen.getByRole('button', { name: '保存' })
    await user.click(submit)
    await user.click(submit)
    await user.click(submit)

    release?.()
    await waitFor(() => expect(server.find('PUT', '/credentials/7/proxy')).toHaveLength(1))
  })
})
