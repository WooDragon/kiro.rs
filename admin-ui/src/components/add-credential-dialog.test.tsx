import { describe, it, expect, afterEach } from 'vitest'
import { screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { renderWithQueryClient } from '@/test/harness'
import { installMockServer, proxyItem } from '@/test/mock-server'
import { AddCredentialDialog } from '@/components/add-credential-dialog'

let server: ReturnType<typeof installMockServer>

afterEach(() => {
  server?.restore()
})

function renderDialog() {
  return renderWithQueryClient(<AddCredentialDialog open onOpenChange={() => {}} />)
}

async function postBody() {
  await waitFor(() => expect(server.find('POST', '/credentials')).toHaveLength(1))
  const body = server.find('POST', '/credentials')[0].body as Record<string, unknown>
  for (const field of ['proxyUrl', 'proxyUsername', 'proxyPassword']) {
    expect(body).not.toHaveProperty(field)
  }
  return body
}

function preloadProxies() {
  server = installMockServer((request) => {
    if (request.method === 'GET' && request.url === '/proxies') {
      return { data: { proxies: [proxyItem()] } }
    }
    return {
      data: { success: true, message: '凭据添加成功', credentialId: 1 },
    }
  })
}

/** 填最小必填项：API Key 模式避免触发 OAuth 校验 */
async function fillApiKey(user: ReturnType<typeof userEvent.setup>) {
  await user.selectOptions(screen.getByLabelText('认证方式'), 'api_key')
  await user.type(screen.getByLabelText(/Kiro API Key/), 'ksk_test')
}

describe('新增凭据：代理绑定新写法', () => {
  it('默认继承：只发 proxy，不出现旧三字段', async () => {
    preloadProxies()
    const user = userEvent.setup()
    renderDialog()

    await fillApiKey(user)
    await user.click(screen.getByRole('button', { name: '添加' }))

    const body = await postBody()
    expect(body.proxy).toEqual({ mode: 'inherit' })
    // 后端把新旧写法同现判 400，因此旧三字段一个都不能出现
    expect(body).not.toHaveProperty('proxyUrl')
    expect(body).not.toHaveProperty('proxyUsername')
    expect(body).not.toHaveProperty('proxyPassword')
  })

  it('选池代理：发 mode=pool 与 proxyId，旧字段仍不出现', async () => {
    preloadProxies()
    const user = userEvent.setup()
    renderDialog()

    await fillApiKey(user)
    await user.click(screen.getByRole('radio', { name: '使用指定代理' }))
    await waitFor(() => expect(screen.getByLabelText('选择指定代理')).toBeInTheDocument())
    await user.selectOptions(screen.getByLabelText('选择指定代理'), 'p1')
    await user.click(screen.getByRole('button', { name: '添加' }))

    const body = await postBody()
    expect(body.proxy).toEqual({ mode: 'pool', proxyId: 'p1' })
    expect(body).not.toHaveProperty('proxyUrl')
  })

  it('高级内联：密码逐字发送，含空格不被 trim', async () => {
    preloadProxies()
    const user = userEvent.setup()
    renderDialog()

    await fillApiKey(user)
    await user.click(screen.getByRole('radio', { name: '高级：内联地址' }))
    await user.type(screen.getByLabelText('内联代理地址'), 'socks5://10.0.0.9:1080')
    await user.type(screen.getByLabelText('内联代理用户名'), 'carol')
    await user.type(screen.getByLabelText('内联代理密码'), ' a b ')
    await user.click(screen.getByRole('button', { name: '添加' }))

    const body = await postBody()
    expect(body.proxy).toEqual({
      mode: 'inline',
      url: 'socks5://10.0.0.9:1080',
      username: 'carol',
      password: ' a b ',
    })
  })

  it('明确直连：发 mode=direct', async () => {
    preloadProxies()
    const user = userEvent.setup()
    renderDialog()

    await fillApiKey(user)
    await user.click(screen.getByRole('radio', { name: '明确直连' }))
    await user.click(screen.getByRole('button', { name: '添加' }))

    expect((await postBody()).proxy).toEqual({ mode: 'direct' })
  })

  it('失败时保留输入并展示后端 message', async () => {
    server = installMockServer((request) => {
      if (request.method === 'GET' && request.url === '/proxies') {
        return { data: { proxies: [] } }
      }
      return {
        status: 400,
        data: { error: { type: 'invalid_request', message: '未知端点 "nope"' } },
      }
    })
    const user = userEvent.setup()
    renderDialog()

    await fillApiKey(user)
    await user.click(screen.getByRole('button', { name: '添加' }))

    expect(await screen.findByText(/未知端点/)).toBeInTheDocument()
    expect(screen.getByLabelText(/Kiro API Key/)).toHaveValue('ksk_test')
  })

  it('提交中重复点击只发一次请求', async () => {
    let release: (() => void) | undefined
    const gate = new Promise<void>((resolve) => {
      release = resolve
    })
    server = installMockServer(async (request) => {
      if (request.method === 'GET' && request.url === '/proxies') {
        return { data: { proxies: [] } }
      }
      await gate
      return { data: { success: true, message: 'ok', credentialId: 1 } }
    })

    const user = userEvent.setup()
    renderDialog()

    await fillApiKey(user)
    const submit = screen.getByRole('button', { name: '添加' })
    await user.click(submit)
    await user.click(submit)
    await user.click(submit)

    release?.()
    await waitFor(() => expect(server.find('POST', '/credentials')).toHaveLength(1))
  })
})

it('未选指定代理拒绝新增并保留认证输入', async () => {
  preloadProxies()
  const user = userEvent.setup()
  renderDialog()
  await fillApiKey(user)
  await user.click(screen.getByRole('radio', { name: '使用指定代理' }))
  expect(screen.getByText('从代理列表选择一条代理，仅作用于本凭据')).toBeInTheDocument()
  await user.click(screen.getByRole('button', { name: '添加' }))
  expect(await screen.findByText('请从代理列表选择一条代理')).toBeInTheDocument()
  expect(server.find('POST', '/credentials')).toHaveLength(0)
  expect(screen.getByLabelText(/Kiro API Key/)).toHaveValue('ksk_test')
})

it('模式名称、顺序与空列表说明不暗示自动分配', async () => {
  server = installMockServer(() => ({ data: { proxies: [] } }))
  const user = userEvent.setup()
  renderDialog()
  const radios = screen.getAllByRole('radio') as HTMLInputElement[]
  expect(radios.map((radio) => [radio.value, radio.labels?.[0].querySelector('[id$="-title"]')?.textContent])).toEqual([
    ['inherit', '使用全局代理配置'], ['direct', '明确直连'],
    ['pool', '使用指定代理'], ['inline', '高级：内联地址'],
  ])
  await user.click(screen.getByRole('radio', { name: '使用指定代理' }))
  expect(await screen.findByText('代理列表为空，请先在“代理列表”中新增条目')).toBeInTheDocument()
  expect(screen.getByText('从代理列表选择一条代理，仅作用于本凭据')).toBeInTheDocument()
})

it('新增失败保留内联地址、认证原文及凭据输入', async () => {
  server = installMockServer((request) => request.method === 'GET'
    ? { data: { proxies: [] } }
    : { status: 400, data: { error: { message: '保存失败' } } })
  const user = userEvent.setup()
  renderDialog()
  await fillApiKey(user)
  await user.click(screen.getByRole('radio', { name: '高级：内联地址' }))
  await user.type(screen.getByLabelText('内联代理地址'), 'http://draft:8080')
  await user.type(screen.getByLabelText('内联代理用户名'), ' user ')
  await user.type(screen.getByLabelText('内联代理密码'), ' password ')
  await user.click(screen.getByRole('button', { name: '添加' }))
  expect(await screen.findByText(/保存失败/)).toBeInTheDocument()
  expect(screen.getByRole('radio', { name: '高级：内联地址' })).toBeChecked()
  expect(screen.getByLabelText('内联代理地址')).toHaveValue('http://draft:8080')
  expect(screen.getByLabelText('内联代理用户名')).toHaveValue(' user ')
  expect(screen.getByLabelText('内联代理密码')).toHaveValue(' password ')
  expect(screen.getByLabelText(/Kiro API Key/)).toHaveValue('ksk_test')
})
