import { useState } from 'react'
import { toast } from 'sonner'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { useUpdateProxy } from '@/hooks/use-proxies'
import { extractErrorMessage } from '@/lib/utils'
import { PROTOCOL_LABELS, buildProxyUrl, splitProxyUrl, DEFAULT_PROTOCOL } from '@/lib/proxies'
import { PROXY_PROTOCOLS, type ProxyItem, type UpdateProxyRequest } from '@/types/proxy'

/**
 * 密码编辑三态。
 *
 * `keep` 表示请求体里根本不出现这两个键（后端 double-option 的“缺省=保留”），
 * 这是密码输入框留空不得隐式清除的实现依据。
 */
type PasswordState = 'keep' | 'replace' | 'clear'

interface ProxyEditDialogProps {
  /** 待编辑的条目；null 表示关闭 */
  proxy: ProxyItem | null
  onClose: () => void
  onCloseAutoFocus?: (event: Event) => void
}

export function ProxyEditDialog({ proxy, onClose, onCloseAutoFocus }: ProxyEditDialogProps) {
  const updateProxy = useUpdateProxy()
  // 用 key 让每次打开都是全新表单，避免上一条目的输入残留
  return (
    <Dialog open={proxy !== null} onOpenChange={(next) => !next && onClose()}>
      <DialogContent onCloseAutoFocus={onCloseAutoFocus} className="w-[calc(100%-2rem)] max-h-[calc(100dvh-2rem)] flex flex-col gap-4 rounded-lg p-4 sm:p-6 sm:max-w-lg">
        <DialogHeader className="shrink-0 pr-6">
          <DialogTitle className="leading-normal">编辑代理</DialogTitle>
          <DialogDescription>
            只改名称不会重建连接；改地址或认证会重建该代理的隧道。
          </DialogDescription>
        </DialogHeader>
        {proxy && (
          <EditProxyForm
            key={proxy.id}
            proxy={proxy}
            pending={updateProxy.isPending}
            onSubmit={(id, patch) =>
              updateProxy.mutate(
                { id, patch },
                {
                  onSuccess: () => {
                    toast.success('代理已更新')
                    onClose()
                  },
                  onError: (err) => {
                    toast.error(`更新失败: ${extractErrorMessage(err)}`)
                  },
                }
              )
            }
            onCancel={onClose}
          />
        )}
      </DialogContent>
    </Dialog>
  )
}

interface EditProxyFormProps {
  proxy: ProxyItem
  pending: boolean
  onSubmit: (id: string, patch: UpdateProxyRequest) => void
  onCancel: () => void
}

function EditProxyForm({ proxy, pending, onSubmit, onCancel }: EditProxyFormProps) {
  const initial = splitProxyUrl(proxy.url)
  const [name, setName] = useState(proxy.name)
  const [protocol, setProtocol] = useState(initial.protocol || DEFAULT_PROTOCOL)
  const [hostPort, setHostPort] = useState(initial.hostPort)
  const [username, setUsername] = useState(proxy.username || '')
  const [password, setPassword] = useState('')
  const [passwordState, setPasswordState] = useState<PasswordState>('keep')

  const handlePasswordStateChange = (next: PasswordState) => {
    setPasswordState(next)
    if (next !== 'replace') {
      setPassword('')
    }
  }

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault()
    if (pending) return

    if (!name.trim()) {
      toast.error('请输入代理名称')
      return
    }
    if (!hostPort.trim()) {
      toast.error('请输入代理主机与端口')
      return
    }

    const nextUrl = buildProxyUrl(protocol, hostPort)
    const patch: UpdateProxyRequest = { name: name.trim() }
    // 回显的 url 是后端规范化后的形式（http/https 无路径时带尾 `/`），与存储原串可能只差格式；
    // 未改动时不回传，否则"只改名"会因格式差异改变路由身份而重建隧道
    if (nextUrl !== proxy.url) {
      patch.url = nextUrl
    }

    if (passwordState === 'clear') {
      // 显式 null = 清除认证：用户名与密码必须成对清除
      patch.username = null
      patch.password = null
    } else if (passwordState === 'replace') {
      if (username === '') {
        toast.error('替换密码时用户名不能为空')
        return
      }
      // 密码原样发送：空串是明确的空密码，含空格也保留
      patch.username = username
      patch.password = password
    } else if (username !== (proxy.username || '')) {
      // keep：password 键不出现 = 后端保留原密码；用户名有改动时单独发送
      patch.username = username
    }
    // keep：用户名未改时不写 username/password 键 = 后端保留原值

    onSubmit(proxy.id, patch)
  }

  return (
    <form onSubmit={handleSubmit} className="flex min-h-0 flex-1 flex-col gap-4">
      <div className="min-h-0 flex-1 space-y-4 overflow-y-auto px-1 py-1">
        <div className="space-y-2">
          <label htmlFor="edit-proxy-name" className="text-sm font-medium">
            名称
          </label>
          <Input
            id="edit-proxy-name"
            value={name}
            onChange={(e) => setName(e.target.value)}
            disabled={pending}
          />
        </div>

        <div className="grid grid-cols-1 gap-3 sm:grid-cols-[9rem_minmax(0,1fr)]">
          <div className="space-y-2">
            <label htmlFor="edit-proxy-protocol" className="text-sm font-medium">
              协议
            </label>
            <select
              id="edit-proxy-protocol"
              value={protocol}
              onChange={(e) => setProtocol(e.target.value)}
              disabled={pending}
              className="flex h-10 w-full rounded-md border border-input bg-background px-3 py-2 text-sm ring-offset-background focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 disabled:cursor-not-allowed disabled:opacity-50"
            >
              {PROXY_PROTOCOLS.map((option) => (
                <option key={option} value={option}>
                  {PROTOCOL_LABELS[option]}
                </option>
              ))}
            </select>
          </div>
          <div className="space-y-2">
            <label htmlFor="edit-proxy-host" className="text-sm font-medium">
              主机:端口
            </label>
            <Input
              id="edit-proxy-host"
              value={hostPort}
              onChange={(e) => setHostPort(e.target.value)}
              disabled={pending}
            />
          </div>
        </div>

        <div className="grid grid-cols-1 gap-2 sm:grid-cols-2">
          <label htmlFor="edit-proxy-username" className="text-sm font-medium sm:col-span-2">
            认证
          </label>
          <Input
            id="edit-proxy-username"
            placeholder="用户名"
            value={username}
            onChange={(e) => setUsername(e.target.value)}
            disabled={pending || passwordState === 'clear'}
          />
          <select
            aria-label="密码操作"
            value={passwordState}
            onChange={(e) => handlePasswordStateChange(e.target.value as PasswordState)}
            disabled={pending}
            className="flex h-10 w-full rounded-md border border-input bg-background px-3 py-2 text-sm ring-offset-background focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 disabled:cursor-not-allowed disabled:opacity-50"
          >
            <option value="keep">保持不变</option>
            <option value="replace">替换密码</option>
            <option value="clear">清除认证</option>
          </select>
          {passwordState === 'replace' && (
            <Input
              aria-label="新密码"
              type="password"
              placeholder="新密码（按原样保存）"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              disabled={pending}
            />
          )}
          <p className="text-xs text-muted-foreground sm:col-span-2">
            {passwordState === 'keep'
              ? '留空不会清除已有密码。'
              : passwordState === 'replace'
                ? '密码按原样保存，不会去除空格；空密码即传空串。'
                : '将同时清除用户名与密码。'}
          </p>
        </div>

      </div>
      <DialogFooter className="shrink-0 gap-2 border-t pt-4 sm:gap-0">
        <Button type="button" variant="outline" onClick={onCancel} disabled={pending}>
          取消
        </Button>
        <Button type="submit" disabled={pending}>
          {pending ? '保存中...' : '保存'}
        </Button>
      </DialogFooter>
    </form>
  )
}
