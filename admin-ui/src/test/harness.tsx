import type { ReactElement } from 'react'
import { render } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { Toaster } from '@/components/ui/sonner'

/**
 * 测试用 React Query 客户端。
 *
 * 关闭重试并把 gcTime 设为 0：失败用例必须立刻进入 error 态，
 * 否则用例会等待默认的重试退避，既慢又掩盖真实状态。
 */
export function createTestQueryClient() {
  return new QueryClient({
    defaultOptions: {
      queries: {
        retry: false,
        gcTime: 0,
        staleTime: 0,
      },
      mutations: {
        retry: false,
      },
    },
  })
}

export function renderWithQueryClient(ui: ReactElement) {
  const queryClient = createTestQueryClient()
  return {
    queryClient,
    ...render(
      <QueryClientProvider client={queryClient}>
        {ui}
        {/* 真实应用在 App 根部挂了 Toaster；错误提示必须能被断言到 */}
        <Toaster position="top-right" />
      </QueryClientProvider>
    ),
  }
}
