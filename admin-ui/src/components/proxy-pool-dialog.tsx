import { useState } from 'react'
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
}

/**
 * 代理池管理面板：列表 + 新增 + 编辑 + 删除。
 *
 * 明确不展示“健康/可用”之类指标，也没有测试按钮——后端不提供探活，
 * 前端不伪造。
 */
export function ProxyPoolDialog({ open, onOpenChange }: ProxyPoolDialogProps) {
  const { data, isLoading, error } = useProxies()
  const deleteProxy = useDeleteProxy()

  const [createOpen, setCreateOpen] = useState(false)
  const [editing, setEditing] = useState<ProxyItem | null>(null)
  const [deleting, setDeleting] = useState<ProxyItem | null>(null)
  /** 删除 409 的冲突原因：必须留在界面上，不能只弹一个会消失的 toast */
  const [deleteConflict, setDeleteConflict] = useState<string | null>(null)

  const proxies = data?.proxies || []

  const closeDeleteDialog = () => {
    setDeleting(null)
    setDeleteConflict(null)
  }

  const confirmDelete = () => {
    if (!deleting || deleteProxy.isPending) return
    deleteProxy.mutate(deleting.id, {
      onSuccess: () => {
        toast.success('代理已删除')
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
        <DialogContent className="sm:max-w-2xl max-h-[85vh] flex flex-col">
          <DialogHeader>
            <DialogTitle>代理池</DialogTitle>
            <DialogDescription>
              池中的代理可被多个凭据共享；删除前需先解除全部绑定。
            </DialogDescription>
          </DialogHeader>

          <div className="flex justify-end">
            <Button size="sm" onClick={() => setCreateOpen(true)}>
              <Plus className="h-4 w-4 mr-2" />
              新增代理
            </Button>
          </div>

          <div className="overflow-y-auto flex-1 pr-1 min-h-[8rem]">
            {isLoading ? (
              <div className="py-8 text-center text-muted-foreground">
                <Loader2 className="inline h-4 w-4 animate-spin mr-2" />
                加载中...
              </div>
            ) : error ? (
              <div className="py-8 text-center text-red-500">
                加载失败：{extractErrorMessage(error)}
              </div>
            ) : proxies.length === 0 ? (
              <div className="py-8 text-center text-muted-foreground">暂无代理</div>
            ) : (
              <ul className="divide-y">
                {proxies.map((proxy) => (
                  <li key={proxy.id} className="py-3 flex items-start justify-between gap-3">
                    <div className="min-w-0 space-y-1">
                      <div className="flex items-center gap-2 flex-wrap">
                        <span className="font-medium truncate">{proxy.name}</span>
                        <Badge variant="outline">
                          {PROTOCOL_LABELS[protocolOf(proxy.url)] ||
                            protocolOf(proxy.url) ||
                            '未知协议'}
                        </Badge>
                        {proxy.hasPassword && <Badge variant="secondary">含密码</Badge>}
                        <Badge variant={proxy.referenceCount > 0 ? 'default' : 'outline'}>
                          被 {proxy.referenceCount} 个凭据引用
                        </Badge>
                      </div>
                      <div className="text-sm font-mono text-muted-foreground truncate">
                        {proxy.url}
                      </div>
                      <div className="text-xs text-muted-foreground">
                        用户名：{proxy.username || '（无）'}
                      </div>
                    </div>
                    <div className="flex gap-1 shrink-0">
                      <Button
                        size="sm"
                        variant="ghost"
                        aria-label={`编辑 ${proxy.name}`}
                        onClick={() => setEditing(proxy)}
                      >
                        <Pencil className="h-4 w-4" />
                      </Button>
                      <Button
                        size="sm"
                        variant="ghost"
                        className="text-destructive hover:text-destructive"
                        aria-label={`删除 ${proxy.name}`}
                        onClick={() => {
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
        isFirstProxy={proxies.length === 0}
      />

      <ProxyEditDialog proxy={editing} onClose={() => setEditing(null)} />

      <Dialog open={deleting !== null} onOpenChange={(next) => !next && closeDeleteDialog()}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>删除代理</DialogTitle>
            <DialogDescription>
              确定删除代理「{deleting?.name}」吗？此操作无法撤销。
            </DialogDescription>
          </DialogHeader>
          {deleteConflict && (
            <p
              role="alert"
              className="rounded-md border border-destructive/50 bg-destructive/10 p-3 text-sm text-destructive"
            >
              {deleteConflict}
            </p>
          )}
          <DialogFooter>
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
