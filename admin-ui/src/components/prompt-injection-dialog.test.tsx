import { useState } from 'react'
import { afterEach, describe, expect, it } from 'vitest'
import { act, fireEvent, render, screen, waitFor } from '@testing-library/react'
import { onlineManager, QueryClientProvider } from '@tanstack/react-query'
import { getAdapter, type GenericAbortSignal } from 'axios'
import userEvent from '@testing-library/user-event'
import { createTestQueryClient } from '@/test/harness'
import { Toaster } from '@/components/ui/sonner'
import { installMockServer } from '@/test/mock-server'
import { PromptInjectionDialog } from '@/components/prompt-injection-dialog'
import { Button } from '@/components/ui/button'
import { api } from '@/api/client'

const endpoint = '/config/prompt-injection'
let server: ReturnType<typeof installMockServer>
afterEach(() => server?.restore())

function Harness() {
  const [open, setOpen] = useState(true)
  return <PromptInjectionDialog open={open} onOpenChange={setOpen}
    trigger={<Button>打开提示词设置</Button>} />
}

function setup(handler: Parameters<typeof installMockServer>[0] = () => ({ data: { promptInjection: '已生效' } })) {
  server = installMockServer(handler)
  const user = userEvent.setup()
  const queryClient = createTestQueryClient()
  // 此场景要验证关闭后的缓存及重开时的陈旧缓存，不能用共享 harness 的 gcTime: 0。
  queryClient.setQueryDefaults(['promptInjection'], { gcTime: Infinity })
  return { user, queryClient, ...render(
    <QueryClientProvider client={queryClient}><Harness /><Toaster /></QueryClientProvider>
  ) }
}

async function editor() {
  const textarea = await screen.findByRole('textbox', { name: '注入提示词' })
  await waitFor(() => expect(textarea).toBeEnabled())
  return textarea
}

function deferred() {
  let resolve!: (value: { data: { promptInjection: string } }) => void
  const promise = new Promise<{ data: { promptInjection: string } }>((done) => { resolve = done })
  return { promise, resolve }
}

describe('全局提示词配置的真实客户端场景', () => {
  it('读取完成前不能编辑或保存，成功后按实际值初始化并说明范围', async () => {
    const get = deferred()
    setup(() => get.promise)
    expect(screen.getByText('正在读取提示词配置...')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: '保存' })).toBeDisabled()
    expect(screen.queryByRole('textbox')).not.toBeInTheDocument()
    await act(async () => get.resolve({ data: { promptInjection: ' 原文\n' } }))
    expect(await editor()).toHaveValue(' 原文\n')
    expect(server.requests).toEqual([{ method: 'GET', url: endpoint, body: undefined }])
    expect(api.defaults.baseURL).toBe('/api/admin')
    for (const text of [/全部常规模型请求/, /纯 WebSearch 不注入/, /已有对话的后续请求/, /消息段缓存/, /空白关闭/, /不保证上游服从/, /不要填写凭据/]) {
      expect(screen.getByText(text)).toBeInTheDocument()
    }
  })

  it('读取失败不是默认关闭，禁止保存未知值且可明确重试', async () => {
    let failed = true
    const { user } = setup(() => failed
      ? { status: 500, data: { error: { message: '读取失败详情' } } }
      : { data: { promptInjection: '重试后的值' } })
    expect(await screen.findByRole('alert')).toHaveTextContent('读取失败详情')
    expect(screen.queryByRole('textbox')).not.toBeInTheDocument()
    expect(screen.getByRole('button', { name: '保存' })).toBeDisabled()
    failed = false
    await user.click(screen.getByRole('button', { name: '重试' }))
    expect(await editor()).toHaveValue('重试后的值')
    expect(server.find('GET', endpoint)).toHaveLength(2)
    expect(server.find('PUT', endpoint)).toHaveLength(0)
  })

  it.each([
    { value: '中'.repeat(5461), bytes: 16383, over: false },
    { value: '中'.repeat(5461) + 'a', bytes: 16384, over: false },
    { value: '中'.repeat(5461) + 'ab', bytes: 16385, over: true },
    { value: ' '.repeat(16385), bytes: 16385, over: true },
    { value: '😀', bytes: 4, over: false },
  ])('按原始 UTF-8 字节判断边界（$bytes bytes，over=$over）', async ({ value, bytes, over }) => {
    const { user } = setup((request) => ({ data: { promptInjection: request.method === 'PUT' ? value : '' } }))
    fireEvent.change(await editor(), { target: { value } })
    expect(screen.getByText(`${bytes} / 16384 字节（UTF-8）`)).toBeInTheDocument()
    const save = screen.getByRole('button', { name: '保存' })
    expect(save.hasAttribute('disabled')).toBe(over)
    await user.click(save)
    expect(server.find('PUT', endpoint)).toHaveLength(over ? 0 : 1)
    if (!over) expect(server.find('PUT', endpoint)[0].body).toEqual({ promptInjection: value })
  })

  it('保存只发提示词字段，保留原字节；成功以服务器实际值更新缓存、关闭并通知', async () => {
    const { user, queryClient } = setup((request) => ({ data: { promptInjection: request.method === 'PUT' ? '' : '之前的值' } }))
    fireEvent.change(await editor(), { target: { value: ' \t\n' } })
    await user.click(screen.getByRole('button', { name: '保存' }))
    await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument())
    expect(server.find('PUT', endpoint)).toEqual([{ method: 'PUT', url: endpoint, body: { promptInjection: ' \t\n' } }])
    expect(queryClient.getQueryData(['promptInjection'])).toEqual({ promptInjection: '' })
    expect(await screen.findByText('提示词注入已保存')).toBeInTheDocument()
  })

  it('保存失败展示后端错误并保留草稿，可修正后重试', async () => {
    let failed = true
    const { user } = setup((request) => request.method === 'PUT' && failed
      ? { status: 500, data: { error: { message: '配置文件不可写' } } }
      : { data: { promptInjection: '实际值' } })
    fireEvent.change(await editor(), { target: { value: ' 草稿\n' } })
    await user.click(screen.getByRole('button', { name: '保存' }))
    expect(await screen.findByRole('alert')).toHaveTextContent('配置文件不可写')
    expect(screen.getByRole('textbox')).toHaveValue(' 草稿\n')
    failed = false
    await user.click(screen.getByRole('button', { name: '保存' }))
    await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument())
    expect(server.find('PUT', endpoint)).toHaveLength(2)
  })

  it('清空仅改草稿，取消不发 PUT，重开重新读取已生效值', async () => {
    const { user } = setup()
    await editor()
    await user.click(screen.getByRole('button', { name: '清空草稿' }))
    expect(screen.getByRole('textbox')).toHaveValue('')
    expect(server.find('PUT', endpoint)).toHaveLength(0)
    await user.click(screen.getByRole('button', { name: '取消' }))
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: '打开提示词设置' }))
    expect(await editor()).toHaveValue('已生效')
    expect(server.find('PUT', endpoint)).toHaveLength(0)
    expect(server.find('GET', endpoint)).toHaveLength(2)
  })

  it('清空后只有保存才发送空串关闭功能', async () => {
    const { user } = setup((request) => ({ data: { promptInjection: request.method === 'PUT' ? '' : '已生效' } }))
    await editor()
    await user.click(screen.getByRole('button', { name: '清空草稿' }))
    expect(server.find('PUT', endpoint)).toHaveLength(0)
    await user.click(screen.getByRole('button', { name: '保存' }))
    await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument())
    expect(server.find('PUT', endpoint)[0].body).toEqual({ promptInjection: '' })
  })

  it('保存中重复点击/提交只发一条请求，取消、X、Escape、外部点击不能关闭', async () => {
    const put = deferred()
    const { user } = setup((request) => request.method === 'PUT' ? put.promise : { data: { promptInjection: '旧值' } })
    fireEvent.change(await editor(), { target: { value: '新值' } })
    const save = screen.getByRole('button', { name: '保存' })
    fireEvent.click(save)
    fireEvent.click(save)
    fireEvent.submit(save.closest('form')!)
    await waitFor(() => expect(server.find('PUT', endpoint)).toHaveLength(1))
    expect(screen.getByRole('button', { name: '保存中...' })).toBeDisabled()
    expect(screen.getByRole('button', { name: '取消' })).toBeDisabled()
    expect(screen.getByRole('button', { name: '清空草稿' })).toBeDisabled()
    expect(screen.getByRole('textbox')).toBeDisabled()
    await user.click(screen.getByRole('button', { name: '取消' }))
    await user.click(screen.getByRole('button', { name: '关闭' }))
    await user.keyboard('{Escape}')
    fireEvent.pointerDown(document.querySelector('[data-state="open"][class*="bg-black"]')!)
    expect(screen.getByRole('dialog')).toBeInTheDocument()
    expect(server.find('PUT', endpoint)).toHaveLength(1)
    await act(async () => put.resolve({ data: { promptInjection: '新值' } }))
    await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument())
  })

  it('后台 refetch 不覆盖编辑草稿，重开等待新读取而非展示过期缓存', async () => {
    let value = '原值'
    const { user, queryClient } = setup(() => ({ data: { promptInjection: value } }))
    fireEvent.change(await editor(), { target: { value: '编辑草稿' } })
    value = '外部更新值'
    await act(async () => { await queryClient.invalidateQueries({ queryKey: ['promptInjection'] }) })
    expect(screen.getByRole('textbox')).toHaveValue('编辑草稿')
    await user.click(screen.getByRole('button', { name: '取消' }))
    await user.click(screen.getByRole('button', { name: '打开提示词设置' }))
    expect(await editor()).toHaveValue('外部更新值')
  })

  it.each(['PUT 前', 'PUT 在途'] as const)('取消%s启动且已读到旧值的 GET，保存重开后迟返不能污染缓存或回写', async (timing) => {
    const oldGet = deferred()
    const put = deferred()
    const freshGet = deferred()
    let stored = '旧值 A'
    let oldSnapshot: string | undefined
    let getCount = 0
    let oldSignal: GenericAbortSignal | undefined
    const { user, queryClient } = setup((request) => {
      if (request.method === 'PUT') return put.promise
      getCount += 1
      if (getCount === 2) {
        // 服务端已读取 A，只延迟交付响应；PUT 完成后不能把它伪装成新值。
        oldSnapshot = stored
        return oldGet.promise
      }
      if (getCount === 3) return freshGet.promise
      return { data: { promptInjection: stored } }
    })
    const adapter = getAdapter(api.defaults.adapter)
    api.defaults.adapter = (config) => {
      if (config.method === 'get' && getCount === 1) oldSignal = config.signal
      return adapter(config)
    }
    fireEvent.change(await editor(), { target: { value: '保存值 B' } })
    if (timing === 'PUT 在途') {
      await user.click(screen.getByRole('button', { name: '保存' }))
      await waitFor(() => expect(server.find('PUT', endpoint)).toHaveLength(1))
    }
    // 模拟真实 reconnect 后台读取，而不是替换 queryFn 或 mock hook。
    act(() => { onlineManager.setOnline(false); onlineManager.setOnline(true) })
    await waitFor(() => expect(oldSnapshot).toBe('旧值 A'))
    expect(queryClient.isFetching({ queryKey: ['promptInjection'] })).toBe(1)
    if (timing === 'PUT 前') await user.click(screen.getByRole('button', { name: '保存' }))
    stored = '保存值 B'
    await act(async () => put.resolve({ data: { promptInjection: stored } }))
    await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument())
    expect(queryClient.getQueryData(['promptInjection'])).toEqual({ promptInjection: stored })
    await user.click(screen.getByRole('button', { name: '打开提示词设置' }))
    expect(screen.queryByRole('textbox')).not.toBeInTheDocument()
    await act(async () => oldGet.resolve({ data: { promptInjection: oldSnapshot! } }))
    await waitFor(() => expect(queryClient.getQueryData(['promptInjection'])).toEqual({ promptInjection: stored }))
    expect(screen.queryByDisplayValue('旧值 A')).not.toBeInTheDocument()
    expect(screen.queryByRole('textbox')).not.toBeInTheDocument()
    expect(oldSignal?.aborted).toBe(true)
    expect(server.find('GET', endpoint)).toHaveLength(3)
    await act(async () => freshGet.resolve({ data: { promptInjection: stored } }))
    expect(await editor()).toHaveValue(stored)
    await user.click(screen.getByRole('button', { name: '保存' }))
    await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument())
    expect(server.find('PUT', endpoint).map((request) => request.body)).toEqual([
      { promptInjection: '保存值 B' }, { promptInjection: '保存值 B' },
    ])
  })

  it('有旧缓存但重新读取失败时仍不允许保存未知值', async () => {
    let failed = false
    const { user } = setup(() => failed
      ? { status: 500, data: { error: { message: '重开读取失败' } } }
      : { data: { promptInjection: '旧缓存' } })
    await editor()
    await user.click(screen.getByRole('button', { name: '取消' }))
    failed = true
    await user.click(screen.getByRole('button', { name: '打开提示词设置' }))
    expect(await screen.findByRole('alert')).toHaveTextContent('重开读取失败')
    expect(screen.queryByRole('textbox')).not.toBeInTheDocument()
    expect(screen.getByRole('button', { name: '保存' })).toBeDisabled()
  })
})
