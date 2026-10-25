import { api } from '@/api/client'
import { compactPatch } from '@/lib/proxies'
import type {
  CreateProxyRequest,
  ProxyListResponse,
  UpdateProxyRequest,
} from '@/types/proxy'

/** 列出代理池 */
export async function getProxies(): Promise<ProxyListResponse> {
  const { data } = await api.get<ProxyListResponse>('/proxies')
  return data
}

/**
 * 新增池代理。
 *
 * 不传 id：由服务端生成，前端不参与 ID 分配。
 *
 * 注意：`password` 原样发送，绝不 trim——空串是明确的空密码，含空格也是
 * 用户输入的一部分。
 */
export async function createProxy(
  req: CreateProxyRequest
): Promise<ProxyListResponse> {
  const { data } = await api.post<ProxyListResponse>('/proxies', req)
  return data
}

/**
 * 编辑池代理。
 *
 * `undefined` 字段被剔除（= 保留原值），`null` 显式保留（= 清除）。
 */
export async function updateProxy(
  id: string,
  patch: UpdateProxyRequest
): Promise<ProxyListResponse> {
  const { data } = await api.patch<ProxyListResponse>(
    `/proxies/${encodeURIComponent(id)}`,
    compactPatch(patch)
  )
  return data
}

/** 删除池代理；成功后返回剩余列表（仍被引用时 409） */
export async function deleteProxy(id: string): Promise<ProxyListResponse> {
  const { data } = await api.delete<ProxyListResponse>(
    `/proxies/${encodeURIComponent(id)}`
  )
  return data
}
