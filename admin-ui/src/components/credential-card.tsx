import { useState } from 'react'
import { disabledReasonLabel } from '@/lib/credential-status'
import { toast } from 'sonner'
import { RefreshCw, ChevronUp, ChevronDown, Wallet, Trash2, Loader2, Network } from 'lucide-react'
import { Card, CardContent } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import { Switch } from '@/components/ui/switch'
import { Input } from '@/components/ui/input'
import { Checkbox } from '@/components/ui/checkbox'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog'
import type { CredentialStatusItem, BalanceResponse } from '@/types/api'
import {
  useSetDisabled,
  useSetPriority,
  useResetFailure,
  useDeleteCredential,
  useForceRefreshToken,
} from '@/hooks/use-credentials'

interface CredentialCardProps {
  credential: CredentialStatusItem
  onViewBalance: (id: number) => void
  onEditProxy: (credential: CredentialStatusItem, trigger: HTMLButtonElement) => void
  selected: boolean
  onToggleSelect: () => void
  balance: BalanceResponse | null
  loadingBalance: boolean
  selectionDisabled?: boolean
  loadBalancingMode?: string
}

/**
 * 代理来源的可读标签。
 *
 * 只用后端给出的 proxyMode/proxyName/effectiveProxyUrl，不再用 hasProxy 布尔值猜测。
 */
export function proxySourceLabel(credential: CredentialStatusItem): string {
  switch (credential.proxyMode) {
    case 'inherit':
      return credential.effectiveProxyUrl
        ? `使用全局代理配置 · ${credential.effectiveProxyUrl}`
        : '使用全局代理配置'
    case 'direct':
      return '明确直连'
    case 'pool':
      return `使用指定代理 · ${credential.proxyName || credential.proxyId || '未知条目'}`
    case 'inline':
      return credential.effectiveProxyUrl || credential.proxyUrl
        ? `高级内联 · ${credential.effectiveProxyUrl || credential.proxyUrl}`
        : '高级内联'
    default:
      // 未知模式不猜测语义，如实显示后端原值
      return credential.proxyMode || '未知'
  }
}

function formatLastUsed(lastUsedAt: string | null): string {
  if (!lastUsedAt) return '从未使用'
  const date = new Date(lastUsedAt)
  const now = new Date()
  const diff = now.getTime() - date.getTime()
  if (diff < 0) return '刚刚'
  const seconds = Math.floor(diff / 1000)
  if (seconds < 60) return `${seconds} 秒前`
  const minutes = Math.floor(seconds / 60)
  if (minutes < 60) return `${minutes} 分钟前`
  const hours = Math.floor(minutes / 60)
  if (hours < 24) return `${hours} 小时前`
  const days = Math.floor(hours / 24)
  return `${days} 天前`
}

export function CredentialCard({
  credential,
  onViewBalance,
  onEditProxy,
  selected,
  onToggleSelect,
  balance,
  loadingBalance,
  selectionDisabled = false,
  loadBalancingMode,
}: CredentialCardProps) {
  const isPriorityMode = loadBalancingMode === 'priority'
  const isSelected = isPriorityMode && credential.isCurrent
  const [expanded, setExpanded] = useState(false)
  const detailId = `credential-detail-${credential.id}`
  const [editingPriority, setEditingPriority] = useState(false)
  const [priorityValue, setPriorityValue] = useState(String(credential.priority))
  const [showDeleteDialog, setShowDeleteDialog] = useState(false)

  const setDisabled = useSetDisabled()
  const setPriority = useSetPriority()
  const resetFailure = useResetFailure()
  const deleteCredential = useDeleteCredential()
  const forceRefresh = useForceRefreshToken()

  const handleToggleDisabled = () => {
    setDisabled.mutate(
      { id: credential.id, disabled: !credential.disabled },
      {
        onSuccess: (res) => {
          toast.success(res.message)
        },
        onError: (err) => {
          toast.error('操作失败: ' + (err as Error).message)
        },
      }
    )
  }

  const handlePriorityChange = () => {
    const newPriority = parseInt(priorityValue, 10)
    if (isNaN(newPriority) || newPriority < 0) {
      toast.error('优先级必须是非负整数')
      return
    }
    setPriority.mutate(
      { id: credential.id, priority: newPriority },
      {
        onSuccess: (res) => {
          toast.success(res.message)
          setEditingPriority(false)
        },
        onError: (err) => {
          toast.error('操作失败: ' + (err as Error).message)
        },
      }
    )
  }

  const handleReset = () => {
    resetFailure.mutate(credential.id, {
      onSuccess: (res) => {
        toast.success(res.message)
      },
      onError: (err) => {
        toast.error('操作失败: ' + (err as Error).message)
      },
    })
  }

  const handleForceRefresh = () => {
    forceRefresh.mutate(credential.id, {
      onSuccess: (res) => {
        toast.success(res.message)
      },
      onError: (err) => {
        toast.error('刷新失败: ' + (err as Error).message)
      },
    })
  }

  const handleDelete = () => {
    if (!credential.disabled) {
      toast.error('请先禁用凭据再删除')
      setShowDeleteDialog(false)
      return
    }

    deleteCredential.mutate(credential.id, {
      onSuccess: (res) => {
        toast.success(res.message)
        setShowDeleteDialog(false)
      },
      onError: (err) => {
        toast.error('删除失败: ' + (err as Error).message)
      },
    })
  }

  return (
    <>
      <Card data-testid={`credential-row-${credential.id}`} className={`min-w-0 ${isSelected ? 'ring-2 ring-primary' : ''}`}>
        <div className="grid min-w-0 grid-cols-[auto_minmax(0,1fr)] items-center gap-x-3 gap-y-1 px-3 py-1 text-sm sm:flex sm:flex-wrap">
          <label className="flex min-h-11 min-w-11 shrink-0 items-center justify-center sm:min-h-8 sm:min-w-8">
            <Checkbox aria-label={`选择凭据 #${credential.id}`} checked={selected}
              disabled={selectionDisabled} onCheckedChange={onToggleSelect} />
          </label>
          <div className="min-w-0 flex-1 basis-40">
            <div className="flex min-w-0 items-center gap-2">
              <h3 className="min-w-0 truncate font-medium leading-normal" title={credential.email}>
                {credential.email || `凭据 #${credential.id}`}
              </h3>
              <span className="shrink-0 text-muted-foreground">#{credential.id}</span>
              {isSelected && <Badge variant="success" className="shrink-0 whitespace-nowrap">当前选定</Badge>}
            </div>
            <div className="flex min-w-0 flex-wrap items-center gap-x-2 text-muted-foreground">
              {credential.disabled && <span data-testid="credential-disabled-summary" className="max-w-full text-foreground [overflow-wrap:anywhere]">
                禁用原因：{disabledReasonLabel(credential.disabledReason)}
              </span>}
              <span className="shrink-0">缓存余额：{loadingBalance ? '加载中…' : balance ? balance.remaining.toFixed(2) : '未知'}</span>
              <span data-testid="credential-proxy-summary" className="truncate" title={credential.proxyName}>
                {credential.proxyMode === 'inherit' ? '使用全局代理配置' :
                 credential.proxyMode === 'direct' ? '明确直连' :
                 credential.proxyMode === 'pool' ? `使用指定代理 · ${credential.proxyName || credential.proxyId || '未知条目'}` :
                 credential.proxyMode === 'inline' ? '高级内联' : credential.proxyMode || '未知'}
              </span>
            </div>
          </div>
          <div className="col-span-2 flex min-w-0 items-center gap-2 sm:shrink-0 sm:gap-3">
            <div className="flex min-w-0 flex-1 flex-wrap items-center gap-x-2 sm:flex-none">
              <span className="[overflow-wrap:anywhere]">{credential.authMethod === 'api_key' ? 'API Key' : credential.authMethod === 'idc' ? 'IdC' : credential.authMethod === 'social' ? 'Social' : credential.authMethod || '未知认证'}</span>
              {isPriorityMode && <span className="whitespace-nowrap">优先级 {credential.priority}</span>}
            </div>
            <label className="flex min-h-11 shrink-0 items-center gap-2 sm:min-h-8">
              <Switch aria-label={`启用凭据 #${credential.id}`} checked={!credential.disabled}
                onCheckedChange={handleToggleDisabled} disabled={setDisabled.isPending} />
            </label>
            <Button size="sm" variant="outline" className="min-h-11 shrink-0 sm:min-h-8"
              aria-label={`凭据 #${credential.id} 详情`} aria-expanded={expanded} aria-controls={detailId}
              onClick={() => { setExpanded(!expanded); setEditingPriority(false) }}>
              {expanded ? '收起' : '详情'}
            </Button>
          </div>
        </div>
        {expanded && <CardContent id={detailId} className="space-y-4 border-t pt-3 text-sm [&_button]:min-h-11 sm:[&_button]:min-h-8">
          <p className="[overflow-wrap:anywhere]">{credential.email || `凭据 #${credential.id}`} · #{credential.id} · {credential.endpoint}</p>
          {credential.disabled && (
            <div data-testid="credential-disabled-reason" className="min-w-0 space-y-1 rounded-md border p-3 text-sm leading-relaxed break-words">
              <p className="font-medium">禁用原因：{disabledReasonLabel(credential.disabledReason)}</p>
              {credential.disabledReason === 'TemporarilySuspended' && (
                <>
                  <p className="font-mono text-xs break-all">TEMPORARILY_SUSPENDED</p>
                  <p className="text-muted-foreground">触发原因和恢复时间未知，可联系官方支持。</p>
                  <p className="text-muted-foreground">人工启用/重置仅解除本地禁用，不代表上游解锁。</p>
                </>
              )}
            </div>
          )}
          {/* 信息网格 */}
          <div className="grid grid-cols-2 gap-4 text-sm">
            <div>
              <span className="text-muted-foreground">优先级：</span>
              {editingPriority ? (
                <div className="inline-flex items-center gap-1 ml-1">
                  <Input
                    type="number"
                    aria-label="优先级"
                    value={priorityValue}
                    onChange={(e) => setPriorityValue(e.target.value)}
                    className="min-h-11 w-20 text-sm sm:min-h-8"
                    min="0"
                  />
                  <Button
                    size="sm"
                    variant="ghost"
                    className="h-7 w-7 p-0"
                    aria-label="保存优先级"
                    onClick={handlePriorityChange}
                    disabled={setPriority.isPending}
                  >
                    ✓
                  </Button>
                  <Button
                    size="sm"
                    variant="ghost"
                    className="h-7 w-7 p-0"
                    aria-label="取消优先级编辑"
                    onClick={() => {
                      setEditingPriority(false)
                      setPriorityValue(String(credential.priority))
                    }}
                  >
                    ✕
                  </Button>
                </div>
              ) : (
                <Button size="sm" variant="ghost" aria-label="编辑优先级"
                  onClick={() => { setPriorityValue(String(credential.priority)); setEditingPriority(true) }}>
                  {credential.priority}（编辑）
                </Button>
              )}
              {loadBalancingMode === 'balanced' && <p className="text-muted-foreground">负载相同时优先，数字越小越优先</p>}
            </div>
            <div>
              <span className="text-muted-foreground">失败次数：</span>
              <span className={credential.failureCount > 0 ? 'text-red-500 font-medium' : ''}>
                {credential.failureCount}
              </span>
            </div>
            <div>
              <span className="text-muted-foreground">刷新失败：</span>
              <span className={credential.refreshFailureCount > 0 ? 'text-red-500 font-medium' : ''}>
                {credential.refreshFailureCount}
              </span>
            </div>
            <div>
              <span className="text-muted-foreground">订阅等级：</span>
              <span className="font-medium">
                {loadingBalance ? (
                  <Loader2 className="inline w-3 h-3 animate-spin" />
                ) : balance?.subscriptionTitle || '未知'}
              </span>
            </div>
            <div>
              <span className="text-muted-foreground">成功次数：</span>
              <span className="font-medium">{credential.successCount}</span>
            </div>
            <div className="col-span-2">
              <span className="text-muted-foreground">最后调用：</span>
              <span className="font-medium">{formatLastUsed(credential.lastUsedAt)}</span>
            </div>
            {credential.maskedApiKey && (
              <div className="col-span-2">
                <span className="text-muted-foreground">API Key：</span>
                <span className="font-mono font-medium">{credential.maskedApiKey}</span>
              </div>
            )}
            <div className="col-span-2">
              <span className="text-muted-foreground">剩余用量：</span>
              {loadingBalance ? (
                <span className="text-sm ml-1">
                  <Loader2 className="inline w-3 h-3 animate-spin" /> 加载中...
                </span>
              ) : balance ? (
                <span className="font-medium ml-1">
                  {balance.remaining.toFixed(2)} / {balance.usageLimit.toFixed(2)}
                  <span className="text-xs text-muted-foreground ml-1">
                    ({(100 - balance.usagePercentage).toFixed(1)}% 剩余)
                  </span>
                </span>
              ) : (
                <span className="text-sm text-muted-foreground ml-1">未知</span>
              )}
            </div>
            <div className="col-span-2 min-w-0 space-y-1 rounded-md border bg-muted/50 p-3 [overflow-wrap:anywhere]" data-testid="credential-proxy-source">
              <span className="text-muted-foreground">代理：</span>
              <span className="font-medium">{proxySourceLabel(credential)}</span>
              {credential.proxyMode === 'pool' && credential.effectiveProxyUrl && (
                <span className="block font-mono text-xs text-muted-foreground [overflow-wrap:anywhere]">
                  {credential.effectiveProxyUrl}
                </span>
              )}
            </div>
            {credential.hasProfileArn && (
              <div className="col-span-2">
                <Badge variant="secondary">有 Profile ARN</Badge>
              </div>
            )}
          </div>

          <p className="text-muted-foreground">重置失败会重新启用凭据；人工启用/重置不代表上游解锁。</p>
          {/* 操作按钮 */}
          <div className="flex flex-wrap gap-2 pt-2 border-t">
            <Button
              size="sm"
              variant="outline"
              onClick={handleReset}
              title="重置失败计数并重新启用；不代表上游解锁"
              disabled={resetFailure.isPending || (credential.failureCount === 0 && credential.refreshFailureCount === 0)}
            >
              <RefreshCw className="h-4 w-4 mr-1" />
              重置失败
            </Button>
            <Button
              size="sm"
              variant="outline"
              onClick={handleForceRefresh}
              disabled={forceRefresh.isPending || credential.disabled || credential.authMethod === 'api_key'}
              title={credential.authMethod === 'api_key' ? 'API Key 凭据无需刷新 Token' : credential.disabled ? '已禁用的凭据无法刷新 Token' : '强制刷新 Token'}
            >
              <RefreshCw className={`h-4 w-4 mr-1 ${forceRefresh.isPending ? 'animate-spin' : ''}`} />
              刷新 Token
            </Button>
            <Button
              size="sm"
              variant="outline"
              onClick={() => {
                const newPriority = Math.max(0, credential.priority - 1)
                setPriority.mutate(
                  { id: credential.id, priority: newPriority },
                  {
                    onSuccess: (res) => toast.success(res.message),
                    onError: (err) => toast.error('操作失败: ' + (err as Error).message),
                  }
                )
              }}
              disabled={setPriority.isPending || credential.priority === 0}
            >
              <ChevronUp className="h-4 w-4 mr-1" />
              提高优先级
            </Button>
            <Button
              size="sm"
              variant="outline"
              onClick={() => {
                const newPriority = credential.priority + 1
                setPriority.mutate(
                  { id: credential.id, priority: newPriority },
                  {
                    onSuccess: (res) => toast.success(res.message),
                    onError: (err) => toast.error('操作失败: ' + (err as Error).message),
                  }
                )
              }}
              disabled={setPriority.isPending}
            >
              <ChevronDown className="h-4 w-4 mr-1" />
              降低优先级
            </Button>
            <Button
              size="sm"
              variant="default"
              onClick={() => onViewBalance(credential.id)}
            >
              <Wallet className="h-4 w-4 mr-1" />
              查看余额
            </Button>
            <Button
              size="sm"
              variant="outline"
              onClick={(event) => onEditProxy(credential, event.currentTarget)}
            >
              <Network className="h-4 w-4 mr-1" />
              修改代理
            </Button>
            <Button
              size="sm"
              variant="destructive"
              onClick={() => setShowDeleteDialog(true)}
              disabled={!credential.disabled}
              title={!credential.disabled ? '需要先禁用凭据才能删除' : undefined}
            >
              <Trash2 className="h-4 w-4 mr-1" />
              删除
            </Button>
          </div>
        </CardContent>}
      </Card>

      {/* 删除确认对话框 */}
      <Dialog open={showDeleteDialog} onOpenChange={setShowDeleteDialog}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>确认删除凭据</DialogTitle>
            <DialogDescription>
              您确定要删除凭据 #{credential.id} 吗？此操作无法撤销。
            </DialogDescription>
          </DialogHeader>
          <DialogFooter>
            <Button
              variant="outline"
              onClick={() => setShowDeleteDialog(false)}
              disabled={deleteCredential.isPending}
            >
              取消
            </Button>
            <Button
              variant="destructive"
              onClick={handleDelete}
              disabled={deleteCredential.isPending || !credential.disabled}
            >
              确认删除
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </>
  )
}
