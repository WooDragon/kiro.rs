import { useRef, useState } from 'react'
import { toast } from 'sonner'
import { Plus, Pencil, Trash2, Loader2 } from 'lucide-react'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import { useProxies, useDeleteProxy } from '@/hooks/use-proxies'
import { extractErrorMessage } from '@/lib/utils'
import { PROTOCOL_LABELS, protocolOf } from '@/lib/proxies'
import type { ProxyItem } from '@/types/proxy'
import { ProxyCreateDialog } from '@/components/proxy-create-dialog'
import { ProxyEditDialog } from '@/components/proxy-edit-dialog'

interface ProxyPoolDialogProps {
  open: boolean
  onOpenChange: (open: boolean) => void
  onCloseAutoFocus?: (event: Event) => void
}

/**
 * 代理列表管理面板：列表 + 新增 + 编辑 + 删除。
 *
 * 明确不展示“健康/可用”之类指标，也没有测试按钮——后端不提供探活，
 * 前端不伪造。
 */
export function ProxyPoolDialog({ open, onOpenChange, onCloseAutoFocus }: ProxyPoolDialogProps) {
  const { data, isLoading, error } = useProxies()
  const deleteProxy = useDeleteProxy()

  const [createOpen, setCreateOpen] = useState(false)
  const createTriggerRef = useRef<HTMLButtonElement | null>(null)
  const childTriggerRef = useRef<HTMLButtonElement | null>(null)
  // 子弹窗是独立的受控 root，关闭时交还父列表中的开启按钮。
  const restoreChildFocus = (event: Event) => {
    if (!childTriggerRef.current?.isConnected) return
    event.preventDefault()
    childTriggerRef.current.focus()
  }
  const [editing, setEditing] = useState<ProxyItem | null>(null)
  const [deleting, setDeleting] = useState<ProxyItem | null>(null)
  /** 删除 409 的冲突原因：必须留在界面上，不能只弹一个会消失的 toast */
  const [deleteConflict, setDeleteConflict] = useState<string | null>(null)

  const proxies = data?.proxies || []
  const poolReady = !isLoading && !error && data !== undefined
  const isEmptyPool = poolReady && proxies.length === 0

  const closeDeleteDialog = () => {
    setDeleting(null)
    setDeleteConflict(null)
  }

  const confirmDelete = () => {
    if (!deleting || deleteProxy.isPending) return
    deleteProxy.mutate(deleting.id, {
      onSuccess: () => {
        toast.success('代理已删除')
        childTriggerRef.current = createTriggerRef.current
        closeDeleteDialog()
      },
      onError: (err) => {
        setDeleteConflict(extractErrorMessage(err))
      },
    })
  }

  return (
    <>
      <Dialog open={open} onOpenChange={onOpenChange}>
        <DialogContent onCloseAutoFocus={onCloseAutoFocus} className="w-[calc(100%-2rem)] max-h-[calc(100dvh-2rem)] flex flex-col rounded-lg p-4 sm:max-w-2xl sm:p-6">
          <DialogHeader className="shrink-0 pr-6">
            <DialogTitle className="leading-normal">代理列表</DialogTitle>
            <DialogDescription>
              列表中的代理可被多个凭据共享；删除前需先解除全部绑定。
            </DialogDescription>
          </DialogHeader>

          <p className="shrink-0 rounded-md border bg-muted/50 p-3 text-sm leading-relaxed text-muted-foreground">
            添加后不会自动应用，需要在凭据中选择该代理。
          </p>
          <div className={isEmptyPool
            ? 'shrink-0 space-y-4 rounded-lg border border-dashed px-4 py-8 text-center'
            : 'flex shrink-0 justify-end'}>
            {isEmptyPool && <p className="text-sm text-muted-foreground">代理列表为空</p>}
            <Button key="create-proxy" size="sm" ref={createTriggerRef} onClick={() => setCreateOpen(true)} disabled={!poolReady}>
              <Plus className="h-4 w-4 mr-2" />
              新增代理
            </Button>
          </div>

          <div className="min-h-0 flex-1 overflow-y-auto px-1 py-1">
            {isLoading ? (
              <div className="py-8 text-center text-muted-foreground">
                <Loader2 className="inline h-4 w-4 animate-spin mr-2" />
                加载中...
              </div>
            ) : error ? (
              <div className="py-8 text-center text-red-500">
                加载失败：{extractErrorMessage(error)}
              </div>
            ) : proxies.length === 0 ? null : (
              <ul className="space-y-3">
                {proxies.map((proxy) => (
                  <li key={proxy.id} className="flex min-w-0 flex-col gap-3 rounded-lg border bg-card p-4 sm:flex-row sm:items-start sm:justify-between">
                    <div className="min-w-0 flex-1 space-y-2 [overflow-wrap:anywhere]">
                      <div className="flex items-center gap-2 flex-wrap">
                        <span className="min-w-0 font-medium">{proxy.name}</span>
                        <Badge variant="outline">
                          {PROTOCOL_LABELS[protocolOf(proxy.url)] ||
                            protocolOf(proxy.url) ||
                            '未知协议'}
                        </Badge>
                      </div>
                      <div className="text-sm font-mono text-muted-foreground [overflow-wrap:anywhere]">
                        {proxy.url}
                      </div>
                      <div className="flex flex-wrap items-center gap-2 text-xs text-muted-foreground">
                        <span>用户名：{proxy.username || '（无）'}</span>
                        {proxy.hasPassword && <Badge variant="secondary">含密码</Badge>}
                        <Badge variant="outline">被 {proxy.referenceCount} 个凭据引用</Badge>
                      </div>
                    </div>
                    <div className="flex shrink-0 justify-end gap-1 border-t pt-2 sm:border-l sm:border-t-0 sm:pl-3 sm:pt-0">
                      <Button
                        size="sm"
                        variant="ghost"
                        aria-label={`编辑 ${proxy.name}`}
                        onClick={(event) => {
                          childTriggerRef.current = event.currentTarget
                          setEditing(proxy)
                        }}
                      >
                        <Pencil className="h-4 w-4" />
                      </Button>
                      <Button
                        size="sm"
                        variant="ghost"
                        className="text-destructive hover:text-destructive"
                        aria-label={`删除 ${proxy.name}`}
                        onClick={(event) => {
                          childTriggerRef.current = event.currentTarget
                          setDeleteConflict(null)
                          setDeleting(proxy)
                        }}
                      >
                        <Trash2 className="h-4 w-4" />
                      </Button>
                    </div>
                  </li>
                ))}
              </ul>
            )}
          </div>
        </DialogContent>
      </Dialog>

      <ProxyCreateDialog
        open={createOpen}
        onOpenChange={setCreateOpen}
        isFirstProxy={isEmptyPool}
        onCloseAutoFocus={(event) => {
          if (!createTriggerRef.current?.isConnected) return
          event.preventDefault()
          createTriggerRef.current.focus()
        }}
      />

      <ProxyEditDialog proxy={editing} onClose={() => setEditing(null)} onCloseAutoFocus={restoreChildFocus} />

      <Dialog open={deleting !== null} onOpenChange={(next) => !next && closeDeleteDialog()}>
        <DialogContent onCloseAutoFocus={restoreChildFocus} className="w-[calc(100%-2rem)] max-h-[calc(100dvh-2rem)] flex flex-col rounded-lg p-4 sm:p-6">
          <DialogHeader className="shrink-0 pr-6">
            <DialogTitle className="leading-normal">删除代理</DialogTitle>
          </DialogHeader>
          <div className="min-h-0 min-w-0 flex-1 space-y-4 overflow-y-auto [overflow-wrap:anywhere]">
            <DialogDescription>
              确定删除代理「{deleting?.name}」吗？此操作无法撤销。
            </DialogDescription>
            {deleteConflict && (
              <p
                role="alert"
                className="rounded-md border border-destructive/50 bg-destructive/10 p-3 text-sm text-destructive"
              >
                {deleteConflict}
              </p>
            )}
          </div>
          <DialogFooter className="shrink-0">
            <Button variant="outline" onClick={closeDeleteDialog} disabled={deleteProxy.isPending}>
              取消
            </Button>
            <Button variant="destructive" onClick={confirmDelete} disabled={deleteProxy.isPending}>
              {deleteProxy.isPending ? '删除中...' : '确认删除'}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </>
  )
}
