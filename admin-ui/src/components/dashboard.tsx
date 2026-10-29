import { useState, useEffect, useRef } from 'react'
import { RefreshCw, LogOut, Moon, Sun, Server, Plus, Upload, FileUp, Trash2, RotateCcw, CheckCircle2, Network } from 'lucide-react'
import { useQueryClient } from '@tanstack/react-query'
import { toast } from 'sonner'
import { storage } from '@/lib/storage'
import { Card, CardContent } from '@/components/ui/card'
import { CredentialListToolbar } from '@/components/credential-list-toolbar'
import { credentialPage, filterCredentials, pageSelection, pruneSelection, togglePageSelection, type CredentialFilter } from '@/lib/credential-list'
import { Button } from '@/components/ui/button'
import { CredentialCard } from '@/components/credential-card'
import { BalanceDialog } from '@/components/balance-dialog'
import { AddCredentialDialog } from '@/components/add-credential-dialog'
import { BatchImportDialog } from '@/components/batch-import-dialog'
import { KamImportDialog } from '@/components/kam-import-dialog'
import { BatchVerifyDialog, type VerifyResult } from '@/components/batch-verify-dialog'
import { ProxyPoolDialog } from '@/components/proxy-pool-dialog'
import { PromptInjectionDialog } from '@/components/prompt-injection-dialog'
import { CredentialProxyDialog } from '@/components/credential-proxy-dialog'
import { useCredentials, useDeleteCredential, useResetFailure, useLoadBalancingMode, useSetLoadBalancingMode } from '@/hooks/use-credentials'
import { getCredentialBalance, forceRefreshToken } from '@/api/credentials'
import { extractErrorMessage } from '@/lib/utils'
import type { BalanceResponse } from '@/types/api'

interface DashboardProps {
  onLogout: () => void
}

export function Dashboard({ onLogout }: DashboardProps) {
  const [selectedCredentialId, setSelectedCredentialId] = useState<number | null>(null)
  const [balanceDialogOpen, setBalanceDialogOpen] = useState(false)
  const [addDialogOpen, setAddDialogOpen] = useState(false)
  const [batchImportDialogOpen, setBatchImportDialogOpen] = useState(false)
  const [proxyPoolOpen, setProxyPoolOpen] = useState(false)
  const [promptInjectionOpen, setPromptInjectionOpen] = useState(false)
  const dialogTriggerRef = useRef<HTMLButtonElement | null>(null)
  const searchRef = useRef<HTMLInputElement | null>(null)
  const restoreDialogFocus = (event: Event) => {
    event.preventDefault()
    const target = dialogTriggerRef.current?.isConnected ? dialogTriggerRef.current : searchRef.current
    target?.focus()
  }
  const [editingProxyCredential, setEditingProxyCredential] = useState<number | null>(null)
  const [kamImportDialogOpen, setKamImportDialogOpen] = useState(false)
  const [selectedIds, setSelectedIds] = useState<Set<number>>(new Set())
  const [verifyDialogOpen, setVerifyDialogOpen] = useState(false)
  const [verifying, setVerifying] = useState(false)
  const [verifyProgress, setVerifyProgress] = useState({ current: 0, total: 0 })
  const [verifyResults, setVerifyResults] = useState<Map<number, VerifyResult>>(new Map())
  const [balanceMap, setBalanceMap] = useState<Map<number, BalanceResponse>>(new Map())
  const [loadingBalanceIds, setLoadingBalanceIds] = useState<Set<number>>(new Set())
  const [queryingInfo, setQueryingInfo] = useState(false)
  const [queryInfoProgress, setQueryInfoProgress] = useState({ current: 0, total: 0 })
  const [batchRefreshing, setBatchRefreshing] = useState(false)
  const [batchRefreshProgress, setBatchRefreshProgress] = useState({ current: 0, total: 0 })
  const cancelVerifyRef = useRef(false)
  const [currentPage, setCurrentPage] = useState(1)
  const [search, setSearch] = useState('')
  const [status, setStatus] = useState<CredentialFilter>('all')
  const batchLockRef = useRef(false)
  const [batchPending, setBatchPending] = useState(false)
  const runBatch = async (operation: () => Promise<void>) => {
    if (batchLockRef.current) return
    batchLockRef.current = true
    setBatchPending(true)
    try { await operation() }
    finally { batchLockRef.current = false; setBatchPending(false) }
  }
  const [darkMode, setDarkMode] = useState(() => {
    if (typeof window !== 'undefined') {
      return document.documentElement.classList.contains('dark')
    }
    return false
  })

  const queryClient = useQueryClient()
  const { data, isLoading, error, refetch } = useCredentials()
  const globalProxyConfigured = typeof data?.globalProxyConfigured === 'boolean'
    ? data.globalProxyConfigured
    : undefined
  const { mutateAsync: deleteCredential } = useDeleteCredential()
  const { mutateAsync: resetFailure } = useResetFailure()
  const { data: loadBalancingData, isLoading: isLoadingMode, refetch: refetchMode } = useLoadBalancingMode()
  const { mutateAsync: setLoadBalancingMode } = useSetLoadBalancingMode()
  const modeLockRef = useRef(false)
  const [isSettingMode, setIsSettingMode] = useState(false)
  const [modeReadFailed, setModeReadFailed] = useState(false)
  const loadBalancingMode = !modeReadFailed && (loadBalancingData?.mode === 'priority' || loadBalancingData?.mode === 'balanced')
    ? loadBalancingData.mode : undefined

  const filteredCredentials = filterCredentials(data?.credentials || [], search, status)
  const page = credentialPage(filteredCredentials, currentPage)
  const totalPages = page.totalPages
  const currentCredentials = page.items
  const currentIds = currentCredentials.map(item => item.id)
  const changeFilter = (nextSearch: string, nextStatus: CredentialFilter) => {
    if (batchLockRef.current) return
    setSearch(nextSearch)
    setStatus(nextStatus)
    setCurrentPage(1)
    setSelectedIds(new Set())
  }
  const disabledCredentialCount = data?.credentials.filter(credential => credential.disabled).length || 0
  const selectedDisabledCount = Array.from(selectedIds).filter(id => {
    const credential = data?.credentials.find(c => c.id === id)
    return Boolean(credential?.disabled)
  }).length

  useEffect(() => {
    setCurrentPage(previous => Math.min(previous, totalPages))
  }, [totalPages])

  useEffect(() => {
    if (data?.credentials) setSelectedIds(previous => pruneSelection(previous, data.credentials))
  }, [data?.credentials])

  // 只保留当前仍存在的凭据缓存，避免删除后残留旧数据
  useEffect(() => {
    if (!data?.credentials) {
      setBalanceMap(new Map())
      setLoadingBalanceIds(new Set())
      return
    }

    const validIds = new Set(data.credentials.map(credential => credential.id))

    setBalanceMap(prev => {
      const next = new Map<number, BalanceResponse>()
      prev.forEach((value, id) => {
        if (validIds.has(id)) {
          next.set(id, value)
        }
      })
      return next.size === prev.size ? prev : next
    })

    setLoadingBalanceIds(prev => {
      if (prev.size === 0) {
        return prev
      }
      const next = new Set<number>()
      prev.forEach(id => {
        if (validIds.has(id)) {
          next.add(id)
        }
      })
      return next.size === prev.size ? prev : next
    })
  }, [data?.credentials])

  const toggleDarkMode = () => {
    setDarkMode(!darkMode)
    document.documentElement.classList.toggle('dark')
  }

  const handleViewBalance = (id: number) => {
    setSelectedCredentialId(id)
    setBalanceDialogOpen(true)
  }

  const handleRefresh = () => {
    refetch()
    toast.success('已刷新凭据列表')
  }

  const handleLogout = () => {
    storage.removeApiKey()
    queryClient.clear()
    onLogout()
  }

  // 通过 id 从最新查询结果解析，保证对话框拿到的是最新代理来源
  const editingProxyCredentialItem =
    data?.credentials.find((credential) => credential.id === editingProxyCredential) || null

  // 选择管理
  const toggleSelect = (id: number) => {
    if (batchLockRef.current) return
    const newSelected = new Set(selectedIds)
    if (newSelected.has(id)) {
      newSelected.delete(id)
    } else {
      newSelected.add(id)
    }
    setSelectedIds(newSelected)
  }

  const deselectAll = () => {
    setSelectedIds(new Set())
  }

  // mutateAsync 保证每个快照目标都等待完成，不依赖重渲染后被替换的单次回调。
  const runSelectedMutation = async (ids: number[], mutate: (id: number) => Promise<unknown>, label: string) => {
    let success = 0
    let failed = 0
    for (const id of ids) {
      try { await mutate(id); success++ }
      catch { failed++ }
    }
    const message = `${label}：成功 ${success} 个，失败 ${failed} 个`
    if (failed) toast.warning(message)
    else toast.success(message)
    deselectAll()
  }

  const handleBatchDelete = async () => {
    if (batchLockRef.current) return
    const ids = [...selectedIds].filter(id => data?.credentials.some(item => item.id === id && item.disabled))
    if (!ids.length) { toast.error('选中的凭据中没有已禁用项'); return }
    const skipped = selectedIds.size - ids.length
    if (!confirm(`已选 ${selectedIds.size} 项，实际删除 ${ids.length} 个已禁用凭据，跳过 ${skipped} 个未禁用凭据。此操作无法撤销。`)) return
    await runBatch(() => runSelectedMutation(ids, deleteCredential, `删除已禁用凭据（跳过 ${skipped} 个）`))
  }

  const handleBatchResetFailure = async () => {
    if (batchLockRef.current) return
    const ids = [...selectedIds].filter(id => data?.credentials.some(item => item.id === id && item.failureCount > 0))
    if (!ids.length) { toast.error('选中的凭据中没有失败的凭据'); return }
    await runBatch(() => runSelectedMutation(ids, resetFailure, '恢复异常'))
  }

  // 批量刷新 Token
  const handleBatchForceRefresh = async () => {
    if (batchLockRef.current) return
    if (selectedIds.size === 0) {
      toast.error('请先选择要刷新的凭据')
      return
    }

    const enabledIds = Array.from(selectedIds).filter(id => {
      const cred = data?.credentials.find(c => c.id === id)
      return cred && !cred.disabled
    })

    if (enabledIds.length === 0) {
      toast.error('选中的凭据中没有启用的凭据')
      return
    }

    await runBatch(async () => {
    setBatchRefreshing(true)
    try {
    setBatchRefreshProgress({ current: 0, total: enabledIds.length })

    let successCount = 0
    let failCount = 0

    for (let i = 0; i < enabledIds.length; i++) {
      try {
        await forceRefreshToken(enabledIds[i])
        successCount++
      } catch {
        failCount++
      }
      setBatchRefreshProgress({ current: i + 1, total: enabledIds.length })
    }

    queryClient.invalidateQueries({ queryKey: ['credentials'] })

    if (failCount === 0) {
      toast.success(`成功刷新 ${successCount} 个凭据的 Token`)
    } else {
      toast.warning(`刷新 Token：成功 ${successCount} 个，失败 ${failCount} 个`)
    }

    deselectAll()
    } finally { setBatchRefreshing(false) }
    })
  }

  const handleClearAll = async () => {
    if (batchLockRef.current) return
    const ids = data?.credentials.filter(item => item.disabled).map(item => item.id) || []
    if (!ids.length) { toast.error('没有可清除的已禁用凭据'); return }
    if (!confirm(`确定清除全库 ${ids.length} 个已禁用凭据？不受搜索、分页或选择限制。此操作无法撤销。`)) return
    await runBatch(() => runSelectedMutation(ids, deleteCredential, '清除全库已禁用凭据'))
  }

  // 查询当前页凭据信息（逐个查询，避免瞬时并发）
  const handleQueryCurrentPageInfo = async () => {
    if (batchLockRef.current) return
    if (currentCredentials.length === 0) {
      toast.error('当前页没有可查询的凭据')
      return
    }

    const ids = currentCredentials
      .filter(credential => !credential.disabled)
      .map(credential => credential.id)

    if (ids.length === 0) {
      toast.error('当前页没有可查询的启用凭据')
      return
    }

    await runBatch(async () => {
    setQueryingInfo(true)
    try {
    setQueryInfoProgress({ current: 0, total: ids.length })

    let successCount = 0
    let failCount = 0

    for (let i = 0; i < ids.length; i++) {
      const id = ids[i]

      setLoadingBalanceIds(prev => {
        const next = new Set(prev)
        next.add(id)
        return next
      })

      try {
        const balance = await getCredentialBalance(id)
        successCount++

        setBalanceMap(prev => {
          const next = new Map(prev)
          next.set(id, balance)
          return next
        })
      } catch (error) {
        failCount++
      } finally {
        setLoadingBalanceIds(prev => {
          const next = new Set(prev)
          next.delete(id)
          return next
        })
      }

      setQueryInfoProgress({ current: i + 1, total: ids.length })
    }

    if (failCount === 0) {
      toast.success(`查询完成：成功 ${successCount}/${ids.length}`)
    } else {
      toast.warning(`查询完成：成功 ${successCount} 个，失败 ${failCount} 个`)
    }
    } finally { setQueryingInfo(false) }
    })
  }

  // 批量验活
  const handleBatchVerify = async () => {
    if (batchLockRef.current) return
    if (selectedIds.size === 0) {
      toast.error('请先选择要验活的凭据')
      return
    }

    await runBatch(async () => {
    setVerifying(true)
    try {
    cancelVerifyRef.current = false
    const ids = Array.from(selectedIds)
    setVerifyProgress({ current: 0, total: ids.length })

    let successCount = 0

    // 初始化结果，所有凭据状态为 pending
    const initialResults = new Map<number, VerifyResult>()
    ids.forEach(id => {
      initialResults.set(id, { id, status: 'pending' })
    })
    setVerifyResults(initialResults)
    setVerifyDialogOpen(true)

    // 开始验活
    for (let i = 0; i < ids.length; i++) {
      // 检查是否取消
      if (cancelVerifyRef.current) {
        toast.info('已取消验活')
        break
      }

      const id = ids[i]

      // 更新当前凭据状态为 verifying
      setVerifyResults(prev => {
        const newResults = new Map(prev)
        newResults.set(id, { id, status: 'verifying' })
        return newResults
      })

      try {
        const balance = await getCredentialBalance(id)
        successCount++

        // 更新为成功状态
        setVerifyResults(prev => {
          const newResults = new Map(prev)
          newResults.set(id, {
            id,
            status: 'success',
            usage: `${balance.currentUsage}/${balance.usageLimit}`
          })
          return newResults
        })
      } catch (error) {
        // 更新为失败状态
        setVerifyResults(prev => {
          const newResults = new Map(prev)
          newResults.set(id, {
            id,
            status: 'failed',
            error: extractErrorMessage(error)
          })
          return newResults
        })
      }

      // 更新进度
      setVerifyProgress({ current: i + 1, total: ids.length })

      // 添加延迟防止封号（最后一个不需要延迟）
      if (i < ids.length - 1 && !cancelVerifyRef.current) {
        await new Promise(resolve => setTimeout(resolve, 2000))
      }
    }

    if (!cancelVerifyRef.current) {
      toast.success(`验活完成：成功 ${successCount}/${ids.length}`)
    }
    } finally { setVerifying(false) }
    })
  }

  // 取消验活
  const handleCancelVerify = () => {
    cancelVerifyRef.current = true
  }

  const readBackMode = async () => {
    try {
      // hook 已启动 invalidate GET；复用在途读取，不取消或重复请求。
      const result = await refetchMode({ cancelRefetch: false })
      if (result.isError) throw result.error
      const mode = result.data?.mode
      if (mode !== 'priority' && mode !== 'balanced') throw new Error('服务器返回未知模式')
      setModeReadFailed(false)
      toast.success(`已确认当前为${mode === 'priority' ? '优先级模式' : '均衡负载模式'}`)
    } catch (error) {
      setModeReadFailed(true)
      toast.error(`模式读回失败: ${extractErrorMessage(error)}`)
    }
  }

  // 锁覆盖写入及真实读回；写失败不作废原已知模式。
  const handleToggleLoadBalancing = async () => {
    if (!loadBalancingMode || isLoadingMode || modeLockRef.current) return
    modeLockRef.current = true
    setIsSettingMode(true)
    try {
      await setLoadBalancingMode(loadBalancingMode === 'priority' ? 'balanced' : 'priority')
      await readBackMode()
    } catch (error) {
      toast.error(`切换失败: ${extractErrorMessage(error)}`)
    } finally {
      modeLockRef.current = false
      setIsSettingMode(false)
    }
  }

  const handleRetryModeRead = async () => {
    if (modeLockRef.current) return
    modeLockRef.current = true
    setIsSettingMode(true)
    try { await readBackMode() }
    finally { modeLockRef.current = false; setIsSettingMode(false) }
  }

  if (isLoading) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-background">
        <div className="text-center">
          <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-primary mx-auto mb-4"></div>
          <p className="text-muted-foreground">加载中...</p>
        </div>
      </div>
    )
  }

  if (error && !data) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-background p-4">
        <Card className="w-full max-w-md">
          <CardContent className="pt-6 text-center">
            <div className="text-red-500 mb-4">加载失败</div>
            <p className="text-muted-foreground mb-4">{(error as Error).message}</p>
            <div className="space-x-2">
              <Button onClick={() => refetch()}>重试</Button>
              <Button variant="outline" onClick={handleLogout}>重新登录</Button>
            </div>
          </CardContent>
        </Card>
      </div>
    )
  }

  return (
    <div className="min-h-screen bg-background">
      {/* 顶部导航 */}
      <header className="sticky top-0 z-50 w-full border-b bg-background/95 backdrop-blur supports-[backdrop-filter]:bg-background/60">
        <div className="container mx-auto flex min-h-14 flex-wrap items-center gap-x-4 gap-y-2 px-4 py-2 md:px-8">
          <div className="flex items-center gap-2">
            <Server className="h-5 w-5" />
            <span className="font-semibold">Kiro Admin</span>
          </div>
          <div className="ml-auto flex max-w-full flex-wrap items-center justify-end gap-2 [&_button]:min-h-11 sm:[&_button]:min-h-8">
            <PromptInjectionDialog open={promptInjectionOpen} onOpenChange={setPromptInjectionOpen}
              trigger={<Button variant="outline" size="sm">提示词注入</Button>} />
            <Button
              variant="outline"
              size="sm"
              onClick={handleToggleLoadBalancing}
              disabled={isLoadingMode || isSettingMode || !loadBalancingMode}
              title="切换负载均衡模式"
            >
              {isLoadingMode ? '加载中...' : loadBalancingMode === 'priority' ? '优先级模式' : loadBalancingMode === 'balanced' ? '均衡负载' : '模式未知'}
            </Button>
            <Button variant="ghost" size="icon" aria-label="切换主题" onClick={toggleDarkMode}>
              {darkMode ? <Sun className="h-5 w-5" /> : <Moon className="h-5 w-5" />}
            </Button>
            <Button variant="ghost" size="icon" aria-label="刷新凭据列表" onClick={handleRefresh}>
              <RefreshCw className="h-5 w-5" />
            </Button>
            <Button variant="ghost" size="icon" aria-label="退出登录" onClick={handleLogout}>
              <LogOut className="h-5 w-5" />
            </Button>
          </div>
        </div>
      </header>

      {/* 主内容 */}
      <main className="container mx-auto px-4 md:px-8 py-6">
        <div className="mb-4 flex flex-wrap gap-x-5 gap-y-1 text-sm text-muted-foreground" aria-label="凭据概览">
          <span>凭据总数 <strong className="text-foreground">{data?.total || 0}</strong></span>
          <span>可用凭据 <strong className="text-foreground">{data?.available || 0}</strong></span>
          {loadBalancingMode === 'priority' && <span>当前选定 <strong className="text-foreground">{data?.currentId ? `#${data.currentId}` : '无'}</strong></span>}
        </div>
        {modeReadFailed && <div role="alert" className="mb-3 text-sm text-destructive">
          模式读回失败，当前模式未确认；请重试读取后再切换。
          <Button variant="outline" size="sm" onClick={handleRetryModeRead} disabled={isSettingMode}>重试读取模式</Button>
        </div>}
        {error && <p role="alert" className="mb-3 text-sm text-destructive">后台刷新失败，保留上次列表；可重试刷新。</p>}

        {/* 凭据列表 */}
        <div className="space-y-4">
          <div className="flex min-w-0 flex-col gap-4 xl:flex-row xl:items-start xl:justify-between">
            <div className="flex shrink-0 flex-wrap items-center gap-3">
              <h2 className="text-xl font-semibold leading-normal">凭据管理</h2>
            </div>
            <div className="flex min-w-0 flex-wrap gap-2 xl:justify-end [&_button]:min-h-11 sm:[&_button]:min-h-8">
              <Button onClick={(event) => { dialogTriggerRef.current = event.currentTarget; setProxyPoolOpen(true) }} size="sm" variant="outline">
                <Network className="mr-2 h-4 w-4" />代理列表
              </Button>
              <Button onClick={(event) => { dialogTriggerRef.current = event.currentTarget; setAddDialogOpen(true) }} size="sm">
                <Plus className="mr-2 h-4 w-4" />添加凭据
              </Button>
            </div>
          </div>
          <CredentialListToolbar search={search} status={status} selectedCount={selectedIds.size}
            pageChecked={pageSelection(selectedIds, currentIds)} pageEmpty={currentIds.length === 0}
            pending={batchPending} searchRef={searchRef}
            onSearchChange={value => changeFilter(value, status)} onStatusChange={value => changeFilter(search, value)}
            onTogglePage={() => { if (!batchLockRef.current) setSelectedIds(previous => togglePageSelection(previous, currentIds)) }}
            onClearSelection={() => { if (!batchLockRef.current) deselectAll() }} />
          {selectedIds.size > 0 && (
                <div aria-label="选中凭据操作" className="flex flex-wrap gap-2 rounded-lg border bg-muted/40 p-3 [&_button]:min-h-11 sm:[&_button]:min-h-8">
                  <Button onClick={handleBatchVerify} disabled={batchPending} size="sm" variant="outline">
                    <CheckCircle2 className="h-4 w-4 mr-2" />
                    批量验活
                  </Button>
                  <Button
                    onClick={handleBatchForceRefresh}
                    size="sm"
                    variant="outline"
                    disabled={batchPending}
                  >
                    <RefreshCw className={`h-4 w-4 mr-2 ${batchRefreshing ? 'animate-spin' : ''}`} />
                    {batchRefreshing ? `刷新中... ${batchRefreshProgress.current}/${batchRefreshProgress.total}` : '批量刷新 Token'}
                  </Button>
                  <Button onClick={handleBatchResetFailure} disabled={batchPending} title="重置失败计数并重新启用；不代表上游解锁" size="sm" variant="outline">
                    <RotateCcw className="h-4 w-4 mr-2" />
                    恢复异常
                  </Button>
                  <Button
                    onClick={handleBatchDelete}
                    size="sm"
                    variant="destructive"
                    disabled={batchPending || selectedDisabledCount === 0}
                    title={selectedDisabledCount === 0 ? '只能删除已禁用凭据' : undefined}
                  >
                    <Trash2 className="h-4 w-4 mr-2" />
                    批量删除
                  </Button>
                </div>
              )}
              {verifying && !verifyDialogOpen && (
                <Button onClick={() => setVerifyDialogOpen(true)} size="sm" variant="secondary">
                  <CheckCircle2 className="h-4 w-4 mr-2 animate-spin" />
                  验活中... {verifyProgress.current}/{verifyProgress.total}
                </Button>
              )}
          {data?.credentials.length === 0 ? (
            <Card>
              <CardContent className="py-8 text-center text-muted-foreground">
                暂无凭据
              </CardContent>
            </Card>
          ) : (
            <>
              <div className="space-y-2" aria-label="凭据列表">
                {currentCredentials.map((credential) => (
                  <CredentialCard
                    key={credential.id}
                    credential={credential}
                    loadBalancingMode={loadBalancingMode}
                    onViewBalance={handleViewBalance}
                    onEditProxy={(item, trigger) => {
                      dialogTriggerRef.current = trigger
                      setEditingProxyCredential(item.id)
                    }}
                    selectionDisabled={batchPending}
                    selected={selectedIds.has(credential.id)}
                    onToggleSelect={() => toggleSelect(credential.id)}
                    balance={balanceMap.get(credential.id) || null}
                    loadingBalance={loadingBalanceIds.has(credential.id)}
                  />
                ))}
              </div>

              {/* 分页控件 */}
              {filteredCredentials.length === 0 && <p className="py-6 text-center text-muted-foreground">没有匹配的凭据</p>}
              {
                <div className="mt-4 flex flex-wrap items-center justify-center gap-3 [&_button]:min-h-11 sm:[&_button]:min-h-8">
                  <Button
                    variant="outline"
                    size="sm"
                    onClick={() => setCurrentPage(p => Math.max(1, p - 1))}
                    disabled={currentPage === 1}
                  >
                    上一页
                  </Button>
                  <span className="text-sm text-muted-foreground">
                    第 {page.currentPage} / {totalPages} 页，命中 {filteredCredentials.length} 项
                  </span>
                  <Button
                    variant="outline"
                    size="sm"
                    onClick={() => setCurrentPage(p => Math.min(totalPages, p + 1))}
                    disabled={currentPage === totalPages}
                  >
                    下一页
                  </Button>
                </div>
              }
            </>
          )}
          <div className="flex flex-wrap gap-2 border-t pt-3 [&_button]:min-h-11 sm:[&_button]:min-h-8">
            <Button onClick={handleQueryCurrentPageInfo} size="sm" variant="outline"
              disabled={batchPending || currentCredentials.length === 0}>
              <RefreshCw className={`mr-2 h-4 w-4 ${queryingInfo ? 'animate-spin' : ''}`} />
              {queryingInfo ? `查询中... ${queryInfoProgress.current}/${queryInfoProgress.total}` : '查询当前页信息'}
            </Button>
            <Button onClick={() => setBatchImportDialogOpen(true)} size="sm" variant="outline">
              <Upload className="mr-2 h-4 w-4" />批量导入
            </Button>
            <Button onClick={() => setKamImportDialogOpen(true)} size="sm" variant="outline">
              <FileUp className="mr-2 h-4 w-4" />Kiro Account Manager 导入
            </Button>
          </div>
          <div className="border-t pt-3 [&_button]:min-h-11 sm:[&_button]:min-h-8">
            <Button onClick={handleClearAll} size="sm" variant="outline"
              className="max-w-full whitespace-normal text-destructive hover:text-destructive"
              disabled={batchPending || disabledCredentialCount === 0}
              title={disabledCredentialCount === 0 ? '没有可清除的已禁用凭据' : undefined}>
              <Trash2 className="mr-2 h-4 w-4 shrink-0" />清除全库已禁用凭据（{disabledCredentialCount}）
            </Button>
          </div>
        </div>
      </main>

      {/* 余额对话框 */}
      <BalanceDialog
        credentialId={selectedCredentialId}
        open={balanceDialogOpen}
        onOpenChange={setBalanceDialogOpen}
      />

      {/* 添加凭据对话框 */}
      <AddCredentialDialog
        globalProxyConfigured={globalProxyConfigured}
        open={addDialogOpen}
        onOpenChange={setAddDialogOpen}
        onCloseAutoFocus={restoreDialogFocus}
      />

      {/* 批量导入对话框 */}
      <BatchImportDialog
        open={batchImportDialogOpen}
        onOpenChange={setBatchImportDialogOpen}
      />

      {/* 代理列表管理 */}
      <ProxyPoolDialog open={proxyPoolOpen} onOpenChange={setProxyPoolOpen} onCloseAutoFocus={restoreDialogFocus} />

      {/* 单凭据代理来源 */}
      <CredentialProxyDialog
        globalProxyConfigured={globalProxyConfigured}
        credential={editingProxyCredentialItem}
        onClose={() => setEditingProxyCredential(null)}
        onCloseAutoFocus={restoreDialogFocus}
      />

      {/* KAM 账号导入对话框 */}
      <KamImportDialog
        open={kamImportDialogOpen}
        onOpenChange={setKamImportDialogOpen}
      />

      {/* 批量验活对话框 */}
      <BatchVerifyDialog
        open={verifyDialogOpen}
        onOpenChange={setVerifyDialogOpen}
        verifying={verifying}
        progress={verifyProgress}
        results={verifyResults}
        onCancel={handleCancelVerify}
      />
    </div>
  )
}
