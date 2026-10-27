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
import { useCreateProxy } from '@/hooks/use-proxies'
import { extractErrorMessage } from '@/lib/utils'
import {
  PROTOCOL_LABELS,
  buildProxyUrl,
  DEFAULT_PROTOCOL,
} from '@/lib/proxies'
import { PROXY_PROTOCOLS, type CreateProxyRequest } from '@/types/proxy'

/** 封套升级提示：只在池为空、创建第一个代理时展示 */
export const ENVELOPE_NOTICE =
  '使用代理列表后，凭据文件会升级为新格式；新版程序仍可读取旧格式，但旧版本程序与直接解析凭据文件的外部脚本无法读取新格式。删光代理列表与所有绑定后会自动回到数组格式。'

interface ProxyCreateDialogProps {
  open: boolean
  onOpenChange: (open: boolean) => void
  /** 池当前是否为空：决定是否展示升级提示 */
  isFirstProxy: boolean
}

const emptyForm = {
  name: '',
  protocol: DEFAULT_PROTOCOL,
  hostPort: '',
  username: '',
  password: '',
}

export function ProxyCreateDialog({
  open,
  onOpenChange,
  isFirstProxy,
}: ProxyCreateDialogProps) {
  const createProxy = useCreateProxy()
  const [form, setForm] = useState(emptyForm)

  const handleOpenChange = (next: boolean) => {
    if (!next) {
      setForm(emptyForm)
    }
    onOpenChange(next)
  }

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault()
    if (createProxy.isPending) return

    if (!form.name.trim()) {
      toast.error('请输入代理名称')
      return
    }
    if (!form.hostPort.trim()) {
      toast.error('请输入代理主机与端口')
      return
    }
    // 后端要求认证字段成对；提前拦截以给出可读提示
    const hasUsername = form.username !== ''
    const hasPassword = form.password !== ''
    if (hasUsername !== hasPassword) {
      toast.error('代理用户名与密码必须同时填写，或同时留空')
      return
    }

    const request: CreateProxyRequest = {
      name: form.name.trim(),
      // 只拼协议+主机端口；密码原样发送，绝不 trim（空串=明确的空密码）
      url: buildProxyUrl(form.protocol, form.hostPort),
      username: hasUsername ? form.username : undefined,
      password: hasPassword ? form.password : undefined,
    }

    createProxy.mutate(request, {
      onSuccess: () => {
        toast.success('代理已添加')
        handleOpenChange(false)
      },
      onError: (err) => {
        // 失败时保留全部输入，只提示原因
        toast.error(`添加失败: ${extractErrorMessage(err)}`)
      },
    })
  }

  return (
    <Dialog open={open} onOpenChange={handleOpenChange}>
      <DialogContent className="sm:max-w-lg">
        <DialogHeader>
          <DialogTitle>新增代理</DialogTitle>
          <DialogDescription>
            地址只填主机与端口；认证信息走独立字段。
            添加后不会自动应用，需要在凭据中选择该代理。
          </DialogDescription>
        </DialogHeader>
        <form onSubmit={handleSubmit} className="space-y-4">
          {isFirstProxy && (
            <p
              role="note"
              className="rounded-md border border-yellow-500/50 bg-yellow-500/10 p-3 text-xs leading-relaxed"
            >
              {ENVELOPE_NOTICE}
            </p>
          )}
          <div className="space-y-2">
            <label htmlFor="proxy-name" className="text-sm font-medium">
              名称
            </label>
            <Input
              id="proxy-name"
              placeholder="例如：家庭 SOCKS"
              value={form.name}
              onChange={(e) => setForm({ ...form, name: e.target.value })}
              disabled={createProxy.isPending}
            />
          </div>
          <div className="grid grid-cols-[9rem_1fr] gap-2">
            <div className="space-y-2">
              <label htmlFor="proxy-protocol" className="text-sm font-medium">
                协议
              </label>
              <select
                id="proxy-protocol"
                value={form.protocol}
                onChange={(e) => setForm({ ...form, protocol: e.target.value })}
                disabled={createProxy.isPending}
                className="flex h-10 w-full rounded-md border border-input bg-background px-3 py-2 text-sm ring-offset-background focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 disabled:cursor-not-allowed disabled:opacity-50"
              >
                {PROXY_PROTOCOLS.map((protocol) => (
                  <option key={protocol} value={protocol}>
                    {PROTOCOL_LABELS[protocol]}
                  </option>
                ))}
              </select>
            </div>
            <div className="space-y-2">
              <label htmlFor="proxy-host" className="text-sm font-medium">
                主机:端口
              </label>
              <Input
                id="proxy-host"
                placeholder="127.0.0.1:1080"
                value={form.hostPort}
                onChange={(e) => setForm({ ...form, hostPort: e.target.value })}
                disabled={createProxy.isPending}
              />
            </div>
          </div>
          <p className="text-xs text-muted-foreground">
            默认 SOCKS5h：域名由代理端解析（本机不做 DNS）。
          </p>
          <div className="grid grid-cols-2 gap-2">
            <Input
              aria-label="代理用户名"
              placeholder="用户名（可选）"
              value={form.username}
              onChange={(e) => setForm({ ...form, username: e.target.value })}
              disabled={createProxy.isPending}
            />
            <Input
              aria-label="代理密码"
              type="password"
              placeholder="密码（可选）"
              value={form.password}
              onChange={(e) => setForm({ ...form, password: e.target.value })}
              disabled={createProxy.isPending}
            />
          </div>
          <p className="text-xs text-muted-foreground">
            用户名与密码须同时填写或同时留空；密码按原样保存，不会去除空格。
          </p>
          <DialogFooter>
            <Button
              type="button"
              variant="outline"
              onClick={() => handleOpenChange(false)}
              disabled={createProxy.isPending}
            >
              取消
            </Button>
            <Button type="submit" disabled={createProxy.isPending}>
              {createProxy.isPending ? '添加中...' : '添加'}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  )
}
