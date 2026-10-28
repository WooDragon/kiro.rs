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
import { useProxies, useBindCredentialProxy } from '@/hooks/use-proxies'
import { extractErrorMessage } from '@/lib/utils'
import { ProxyBindingSelect, type InlineProxyFields } from '@/components/proxy-binding-select'
import type { CredentialStatusItem } from '@/types/api'
import type { ProxyBinding, ProxyMode } from '@/types/proxy'

interface CredentialProxyDialogProps {
  globalProxyConfigured?: boolean
  /** 待编辑的凭据；null 表示关闭 */
  credential: CredentialStatusItem | null
  onClose: () => void
  onCloseAutoFocus?: (event: Event) => void
}

/** 把凭据当前的代理来源还原成选择器初值 */
function initialMode(credential: CredentialStatusItem): ProxyMode {
  const mode = credential.proxyMode
  if (mode === 'inherit' || mode === 'direct' || mode === 'pool' || mode === 'inline') {
    return mode
  }
  // 未知来源按继承处理，避免默认到 direct 改变现有行为
  return 'inherit'
}

export function CredentialProxyDialog({ credential, onClose, globalProxyConfigured, onCloseAutoFocus }: CredentialProxyDialogProps) {
  return (
    <Dialog open={credential !== null} onOpenChange={(next) => !next && onClose()}>
      <DialogContent onCloseAutoFocus={onCloseAutoFocus} className="w-[calc(100%-2rem)] max-h-[calc(100dvh-2rem)] flex flex-col gap-4 rounded-lg p-4 sm:p-6 sm:max-w-lg">
        <DialogHeader className="shrink-0 pr-6">
          <DialogTitle className="leading-normal">修改代理</DialogTitle>
          <DialogDescription>
            凭据 #{credential?.id}：选择该凭据实际使用的代理来源。
          </DialogDescription>
        </DialogHeader>
        {credential && (
          <CredentialProxyForm
            globalProxyConfigured={globalProxyConfigured}
            key={credential.id}
            credential={credential}
            onDone={onClose}
          />
        )}
      </DialogContent>
    </Dialog>
  )
}

interface CredentialProxyFormProps {
  globalProxyConfigured?: boolean
  credential: CredentialStatusItem
  onDone: () => void
}

function CredentialProxyForm({ credential, onDone, globalProxyConfigured }: CredentialProxyFormProps) {
  const { data, isLoading } = useProxies()
  const bindProxy = useBindCredentialProxy()

  const startMode = initialMode(credential)
  const [mode, setMode] = useState<ProxyMode>(startMode)
  const [poolId, setPoolId] = useState(credential.proxyId || '')
  const [inline, setInline] = useState<InlineProxyFields>({
    // 内联地址可回显（已脱敏）；用户名与密码后端不回传，必须重新填写才能保留认证
    url: startMode === 'inline' ? credential.proxyUrl || credential.effectiveProxyUrl || '' : '',
    username: '',
    password: '',
  })

  const proxies = data?.proxies || []
  const wasInline = startMode === 'inline'
  const effectiveAddress = credential.effectiveProxyUrl || (
    credential.proxyMode === 'direct'
      ? '明确直连'
      : credential.proxyMode === 'inherit' && globalProxyConfigured === false
        ? '系统默认网络'
        : '未提供实际地址'
  )

  /** 当前选择是否与打开时一致（用于避免无修改保存导致内联认证被清空） */
  const isUnchanged =
    mode === startMode &&
    (mode !== 'pool' || poolId === (credential.proxyId || '')) &&
    (mode !== 'inline' || (inline.username === '' && inline.password === '' && inline.url === (credential.proxyUrl || credential.effectiveProxyUrl || '')))

  const buildBinding = (): ProxyBinding | null => {
    switch (mode) {
      case 'inherit':
        return { mode: 'inherit' }
      case 'direct':
        return { mode: 'direct' }
      case 'pool':
        if (!poolId) {
          toast.error('请从代理列表选择一条代理')
          return null
        }
        return { mode: 'pool', proxyId: poolId }
      case 'inline': {
        if (inline.url.trim() === '') {
          toast.error('请输入内联代理地址')
          return null
        }
        // 用户名与密码成对；空串密码是明确的空密码，绝不 trim。
        // 既有内联认证无法回显，因此两者都留空时保存为“无认证”——
        // 这一点在表单里已明确告知，不静默发生。
        const hasUsername = inline.username !== ''
        const hasPassword = inline.password !== ''
        if (hasUsername !== hasPassword) {
          toast.error('内联代理用户名与密码必须同时填写，或同时留空')
          return null
        }
        return {
          mode: 'inline',
          url: inline.url,
          username: hasUsername ? inline.username : undefined,
          password: hasPassword ? inline.password : undefined,
        }
      }
    }
  }

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault()
    if (bindProxy.isPending) return

    if (isUnchanged) {
      toast.info('没有需要保存的更改')
      onDone()
      return
    }

    const binding = buildBinding()
    if (!binding) return

    bindProxy.mutate(
      { id: credential.id, binding },
      {
        onSuccess: () => {
          toast.success('代理已更新')
          onDone()
        },
        onError: (err) => {
          // 失败保留表单，只提示后端 message
          toast.error(`更新失败: ${extractErrorMessage(err)}`)
        },
      }
    )
  }

  return (
    <form onSubmit={handleSubmit} className="flex flex-col min-h-0 flex-1">
      <div className="min-h-0 flex-1 space-y-4 overflow-y-auto px-1 py-2">
        <div className="min-w-0 space-y-1 rounded-md border bg-muted/50 p-3 text-xs leading-relaxed text-muted-foreground [overflow-wrap:anywhere]">
          <div>
            当前来源：
            {credential.proxyMode === 'inherit'
              ? '使用全局代理配置'
              : credential.proxyMode === 'direct'
                ? '明确直连'
                : credential.proxyMode === 'pool'
                  ? `使用指定代理 · ${credential.proxyName || credential.proxyId}`
                  : '高级内联'}
          </div>
          <div className="font-mono" data-testid="effective-proxy-url">
            实际地址：{effectiveAddress}
          </div>
        </div>

        <ProxyBindingSelect
          globalProxyConfigured={globalProxyConfigured}
          idPrefix="credential-proxy"
          mode={mode}
          onModeChange={setMode}
          proxies={proxies}
          proxiesLoading={isLoading}
          poolId={poolId}
          onPoolIdChange={setPoolId}
          inline={inline}
          onInlineChange={setInline}
          inlinePasswordPlaceholder={
            wasInline ? '重新输入密码（界面不回显原密码）' : '代理密码（留空表示无密码）'
          }
          disabled={bindProxy.isPending}
        />

        {wasInline && mode === 'inline' && (
          <p className="rounded-md border border-yellow-500/50 bg-yellow-500/10 p-3 text-xs leading-relaxed">
            该凭据当前使用内联代理，其用户名与密码不会回传到浏览器。若该地址需要认证，请重新
            填写用户名与密码；两者都留空则保存为“无认证”。
          </p>
        )}
      </div>

      <DialogFooter className="shrink-0 gap-2 border-t pt-4 sm:gap-0">
        <Button type="button" variant="outline" onClick={onDone} disabled={bindProxy.isPending}>
          取消
        </Button>
        <Button type="submit" disabled={bindProxy.isPending}>
          {bindProxy.isPending ? '保存中...' : '保存'}
        </Button>
      </DialogFooter>
    </form>
  )
}
