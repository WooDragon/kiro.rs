import { describe, it, expect, afterEach, vi } from 'vitest'
import type { ReactNode } from 'react'
import { act, renderHook, waitFor } from '@testing-library/react'
import { QueryClientProvider } from '@tanstack/react-query'
import { createTestQueryClient } from '@/test/harness'
import { installMockServer, proxyItem } from '@/test/mock-server'
import type { RecordedRequest } from '@/test/mock-server'
import {
  useAddCredential,
  useDeleteCredential,
} from '@/hooks/use-credentials'
import {
  useBindCredentialProxy,
  useCreateProxy,
  useDeleteProxy,
  useUpdateProxy,
} from '@/hooks/use-proxies'

let server: ReturnType<typeof installMockServer>

afterEach(() => {
  server?.restore()
})

/**
 * 各接口的合法成功响应体。
 *
 * 失效清单是 onSuccess 的行为，因此每个请求都必须真正成功，
 * 否则断言到的是错误分支而不是本次要验的刷新行为。
 */
function respond(request: RecordedRequest) {
  switch (request.method) {
    case 'POST':
      return request.url === '/credentials'
        ? { data: { success: true, message: 'ok', credentialId: 1 } }
        : { data: { proxies: [proxyItem()] } }
    case 'PATCH':
      return { data: { proxies: [proxyItem()] } }
    case 'DELETE':
      return request.url.startsWith('/credentials')
        ? { data: { success: true, message: 'ok' } }
        : { data: { proxies: [] } }
    case 'PUT':
      return { data: { proxies: [proxyItem({ referenceCount: 1 })] } }
    default:
      return { data: { proxies: [proxyItem()] } }
  }
}

function createClientWithSpy() {
  const queryClient = createTestQueryClient()
  const invalidateSpy = vi.spyOn(queryClient, 'invalidateQueries')
  return { queryClient, invalidateSpy }
}

type InvalidateSpy = ReturnType<typeof createClientWithSpy>['invalidateSpy']

/** 断言两次失效都发生：代理列表与凭据列表缺一不可 */
function assertBothInvalidated(spy: InvalidateSpy) {
  const calls = spy.mock.calls.map((call) => call[0])
  expect(calls).toEqual(
    expect.arrayContaining([
      { queryKey: ['proxies'] },
      { queryKey: ['credentials'] },
    ])
  )
}

function renderHookWithQueryClient<T>(callback: () => T) {
  const { queryClient, invalidateSpy } = createClientWithSpy()
  const view = renderHook(callback, {
    wrapper: ({ children }: { children: ReactNode }) => (
      <QueryClientProvider client={queryClient}>{children}</QueryClientProvider>
    ),
  })
  return { ...view, queryClient, invalidateSpy }
}

describe('hooks 失效：代理与凭据查询必须同步刷新', () => {
  it('useAddCredential 成功后', async () => {
    server = installMockServer(respond)
    const { result, invalidateSpy } = renderHookWithQueryClient(() => useAddCredential())

    await act(async () => {
      await result.current.mutateAsync({ refreshToken: 'rt-1' })
    })

    await waitFor(() => expect(invalidateSpy).toHaveBeenCalled())
    assertBothInvalidated(invalidateSpy)
  })

  it('useDeleteCredential 成功后', async () => {
    server = installMockServer(respond)
    const { result, invalidateSpy } = renderHookWithQueryClient(() => useDeleteCredential())

    await act(async () => {
      await result.current.mutateAsync(7)
    })

    await waitFor(() => expect(invalidateSpy).toHaveBeenCalled())
    assertBothInvalidated(invalidateSpy)
  })

  it('useCreateProxy 成功后', async () => {
    server = installMockServer(respond)
    const { result, invalidateSpy } = renderHookWithQueryClient(() => useCreateProxy())

    await act(async () => {
      await result.current.mutateAsync({
        name: '家庭 SOCKS',
        url: 'socks5h://127.0.0.1:1080',
      })
    })

    await waitFor(() => expect(invalidateSpy).toHaveBeenCalled())
    assertBothInvalidated(invalidateSpy)
  })

  it('useUpdateProxy 成功后', async () => {
    server = installMockServer(respond)
    const { result, invalidateSpy } = renderHookWithQueryClient(() => useUpdateProxy())

    await act(async () => {
      await result.current.mutateAsync({ id: 'p1', patch: { name: '改名后' } })
    })

    await waitFor(() => expect(invalidateSpy).toHaveBeenCalled())
    assertBothInvalidated(invalidateSpy)
  })

  it('useDeleteProxy 成功后', async () => {
    server = installMockServer(respond)
    const { result, invalidateSpy } = renderHookWithQueryClient(() => useDeleteProxy())

    await act(async () => {
      await result.current.mutateAsync('p1')
    })

    await waitFor(() => expect(invalidateSpy).toHaveBeenCalled())
    assertBothInvalidated(invalidateSpy)
  })

  it('useBindCredentialProxy 成功后', async () => {
    server = installMockServer(respond)
    const { result, invalidateSpy } = renderHookWithQueryClient(() => useBindCredentialProxy())

    await act(async () => {
      await result.current.mutateAsync({ id: 7, binding: { mode: 'direct' } })
    })

    await waitFor(() => expect(invalidateSpy).toHaveBeenCalled())
    assertBothInvalidated(invalidateSpy)
  })
})
