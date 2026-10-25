import { defineConfig } from 'vitest/config'
import react from '@vitejs/plugin-react-swc'
import path from 'path'

// 独立的测试配置：覆盖本功能新增的 UI 行为，不改动生产构建配置。
export default defineConfig({
  plugins: [react()],
  resolve: {
    alias: {
      '@': path.resolve(__dirname, './src'),
    },
  },
  test: {
    environment: 'jsdom',
    globals: true,
    setupFiles: ['./src/test/setup.ts'],
    include: ['src/**/*.test.{ts,tsx}'],
    // 组件测试不依赖真实定时器；React Query 的重试会让失败路径变慢且掩盖真实状态
    restoreMocks: true,
  },
})
