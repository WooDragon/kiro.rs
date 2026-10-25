import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import {
  getProxies,
  createProxy,
  updateProxy,
  deleteProxy,
} from '@/api/proxies'
import { bindCredentialProxy } from '@/api/credentials'
import type {
  CreateProxyRequest,
  ProxyBinding,
  UpdateProxyRequest,
} from '@/types/proxy'

/** 代理池查询键：绑定/增删改后凭据列表也要刷新 */
export const PROXIES_QUERY_KEY = ['proxies'] as const
const CREDENTIALS_QUERY_KEY = ['credentials'] as const

/**
 * 代理与凭据两个查询一起失效。
 *
 * 池的增删改会改变凭据卡片上的“引用数/实际来源”，绑定会改变引用数，
 * 所以两者必须同步刷新，否则界面会停留在旧引用数上。
 */
function invalidateProxyAndCredentials(queryClient: ReturnType<typeof useQueryClient>) {
  queryClient.invalidateQueries({ queryKey: PROXIES_QUERY_KEY })
  queryClient.invalidateQueries({ queryKey: CREDENTIALS_QUERY_KEY })
}

/** 查询代理池 */
export function useProxies() {
  return useQuery({
    queryKey: PROXIES_QUERY_KEY,
    queryFn: getProxies,
  })
}

/** 新增池代理 */
export function useCreateProxy() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: (req: CreateProxyRequest) => createProxy(req),
    onSuccess: () => invalidateProxyAndCredentials(queryClient),
  })
}

/** 编辑池代理 */
export function useUpdateProxy() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: ({ id, patch }: { id: string; patch: UpdateProxyRequest }) =>
      updateProxy(id, patch),
    onSuccess: () => invalidateProxyAndCredentials(queryClient),
  })
}

/** 删除池代理（被引用时后端 409） */
export function useDeleteProxy() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: (id: string) => deleteProxy(id),
    onSuccess: () => invalidateProxyAndCredentials(queryClient),
  })
}

/** 绑定凭据的代理来源 */
export function useBindCredentialProxy() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: ({ id, binding }: { id: number; binding: ProxyBinding }) =>
      bindCredentialProxy(id, binding),
    onSuccess: () => invalidateProxyAndCredentials(queryClient),
  })
}
