import { vi } from 'vitest'
import type { AxiosRequestConfig } from 'axios'
import { api } from '@/api/client'

/** 记录一次被拦截的请求 */
export interface RecordedRequest {
  method: string
  url: string
  body: unknown
}

interface MockResponse {
  status?: number
  data?: unknown
}

type Handler = (request: RecordedRequest) => MockResponse | Promise<MockResponse>

/**
 * 把共享 axios 实例的 adapter 换成内存桩件。
 *
 * 这样断言的是**真正会发出的请求**（方法、路径、请求体 JSON），
 * 而不是组件内部状态的某种模拟；密码三态这类语义只有在请求体层面
 * 才能验真。
 */
export function installMockServer(handler: Handler) {
  const requests: RecordedRequest[] = []

  const adapter = async (config: AxiosRequestConfig) => {
    const request: RecordedRequest = {
      method: (config.method || 'get').toUpperCase(),
      url: config.url || '',
      // axios adapter 拿到的 data 可能已是字符串；统一还原成对象便于断言
      body: parseBody(config.data),
    }
    requests.push(request)

    const response = await handler(request)
    const status = response.status ?? 200
    const payload = {
      data: response.data,
      status,
      statusText: String(status),
      headers: {},
      config,
    }
    if (status >= 400) {
      // 与 axios 的真实行为一致：非 2xx 抛错，错误里带 response.data
      const error = Object.assign(new Error(`Request failed with status code ${status}`), {
        isAxiosError: true,
        response: payload,
      })
      throw error
    }
    return payload
  }

  const original = api.defaults.adapter
  api.defaults.adapter = adapter as never

  return {
    requests,
    /** 按方法+路径筛选，便于断言“重复点击只发一次” */
    find: (method: string, url: string) =>
      requests.filter(
        (request) => request.method === method.toUpperCase() && request.url === url
      ),
    restore: () => {
      api.defaults.adapter = original
    },
  }
}

function parseBody(data: unknown): unknown {
  if (typeof data === 'string') {
    try {
      return JSON.parse(data)
    } catch {
      return data
    }
  }
  return data
}

/** 生成一个合法池代理响应 */
export function proxyItem(overrides: Partial<Record<string, unknown>> = {}) {
  return {
    id: 'p1',
    name: '家庭 SOCKS',
    url: 'socks5h://127.0.0.1:1080/',
    username: undefined,
    hasPassword: false,
    referenceCount: 0,
    ...overrides,
  }
}

export const mock = vi.fn
