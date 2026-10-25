import axios from 'axios'
import { storage } from '@/lib/storage'

/**
 * Admin API 的共享 axios 实例。
 *
 * 所有 admin 接口共用同一 baseURL 与认证头，避免每个 API 模块各建一份实例、
 * 各自维护拦截器。
 */
export const api = axios.create({
  baseURL: '/api/admin',
  headers: {
    'Content-Type': 'application/json',
  },
})

api.interceptors.request.use((config) => {
  const apiKey = storage.getApiKey()
  if (apiKey) {
    config.headers['x-api-key'] = apiKey
  }
  return config
})
