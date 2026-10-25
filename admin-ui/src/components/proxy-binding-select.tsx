import { Input } from '@/components/ui/input'
import { Badge } from '@/components/ui/badge'
import type { ProxyItem, ProxyMode } from '@/types/proxy'
import { PROTOCOL_LABELS, protocolOf } from '@/lib/proxies'

/** 模式下拉的选项（顺序固定：继承 → 直连 → 池 → 高级内联） */
const MODE_OPTIONS: { value: ProxyMode; label: string; hint: string }[] = [
  {
    value: 'inherit',
    label: '继承全局',
    hint: '使用全局配置；未配置全局代理时走系统默认',
  },
  { value: 'direct', label: '明确直连', hint: '该凭据不走任何代理' },
  { value: 'pool', label: '代理池', hint: '引用代理池中的共享条目' },
  { value: 'inline', label: '高级：内联地址', hint: '旧写法，仅该凭据使用' },
]

/** 内联三字段（受控值由调用方持有，不做任何 trim） */
export interface InlineProxyFields {
  url: string
  username: string
  password: string
}

export interface ProxyBindingSelectProps {
  mode: ProxyMode
  onModeChange: (mode: ProxyMode) => void
  /** 池列表 */
  proxies: ProxyItem[]
  proxiesLoading?: boolean
  /** 选中的池条目 id（仅 pool 模式） */
  poolId: string
  onPoolIdChange: (id: string) => void
  /** 内联字段（仅 inline 模式） */
  inline: InlineProxyFields
  onInlineChange: (inline: InlineProxyFields) => void
  /** 内联密码输入框的占位文案（编辑已有值时提示“留空=保持不变”） */
  inlinePasswordPlaceholder?: string
  disabled?: boolean
  /** 组件前缀，用于生成唯一的 input id（同一页面可能同时存在多个实例） */
  idPrefix: string
}

/**
 * 凭据代理来源选择器。
 *
 * 新增凭据与编辑已有凭据共用这一个组件：模式语义、池下拉、内联字段都只有
 * 一份实现，避免两处各自演化出不同的选项或校验。
 */
export function ProxyBindingSelect({
  mode,
  onModeChange,
  proxies,
  proxiesLoading = false,
  poolId,
  onPoolIdChange,
  inline,
  onInlineChange,
  inlinePasswordPlaceholder = '代理密码（留空表示无密码）',
  disabled = false,
  idPrefix,
}: ProxyBindingSelectProps) {
  const selectedMode = MODE_OPTIONS.find((option) => option.value === mode)
  const selectedProxy = proxies.find((proxy) => proxy.id === poolId)

  return (
    <div className="space-y-2">
      <label htmlFor={`${idPrefix}-mode`} className="text-sm font-medium">
        代理来源
      </label>
      <select
        id={`${idPrefix}-mode`}
        value={mode}
        onChange={(e) => onModeChange(e.target.value as ProxyMode)}
        disabled={disabled}
        className="flex h-10 w-full rounded-md border border-input bg-background px-3 py-2 text-sm ring-offset-background focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 disabled:cursor-not-allowed disabled:opacity-50"
      >
        {MODE_OPTIONS.map((option) => (
          <option key={option.value} value={option.value}>
            {option.label}
          </option>
        ))}
      </select>
      {selectedMode && (
        <p className="text-xs text-muted-foreground">{selectedMode.hint}</p>
      )}

      {mode === 'pool' && (
        <div className="space-y-1">
          <select
            aria-label="选择池代理"
            value={poolId}
            onChange={(e) => onPoolIdChange(e.target.value)}
            disabled={disabled || proxiesLoading}
            className="flex h-10 w-full rounded-md border border-input bg-background px-3 py-2 text-sm ring-offset-background focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 disabled:cursor-not-allowed disabled:opacity-50"
          >
            <option value="">
              {proxiesLoading ? '加载中...' : '选择一条代理'}
            </option>
            {proxies.map((proxy) => (
              <option key={proxy.id} value={proxy.id}>
                {proxy.name} — {proxy.url}
              </option>
            ))}
          </select>
          {!proxiesLoading && proxies.length === 0 && (
            <p className="text-xs text-muted-foreground">
              代理池为空，请先在“代理池”中新增条目
            </p>
          )}
          {selectedProxy && (
            <div className="flex items-center gap-2 text-xs text-muted-foreground">
              <Badge variant="outline">
                {PROTOCOL_LABELS[protocolOf(selectedProxy.url)] || protocolOf(selectedProxy.url) || '未知协议'}
              </Badge>
              <span className="font-mono">{selectedProxy.url}</span>
              {selectedProxy.hasPassword && <Badge variant="secondary">含认证</Badge>}
            </div>
          )}
        </div>
      )}

      {mode === 'inline' && (
        <div className="space-y-2 rounded-md border border-dashed p-3">
          <p className="text-xs text-muted-foreground">
            内联地址只作用于该凭据，不会进入代理池，也不会被其他凭据复用。
          </p>
          <Input
            id={`${idPrefix}-inline-url`}
            aria-label="内联代理地址"
            placeholder="socks5h://host:1080"
            value={inline.url}
            onChange={(e) => onInlineChange({ ...inline, url: e.target.value })}
            disabled={disabled}
          />
          <div className="grid grid-cols-2 gap-2">
            <Input
              id={`${idPrefix}-inline-username`}
              aria-label="内联代理用户名"
              placeholder="用户名（可选）"
              value={inline.username}
              onChange={(e) => onInlineChange({ ...inline, username: e.target.value })}
              disabled={disabled}
            />
            <Input
              id={`${idPrefix}-inline-password`}
              aria-label="内联代理密码"
              type="password"
              placeholder={inlinePasswordPlaceholder}
              value={inline.password}
              onChange={(e) => onInlineChange({ ...inline, password: e.target.value })}
              disabled={disabled}
            />
          </div>
          <p className="text-xs text-muted-foreground">
            用户名与密码须成对填写；密码不会被打码或回显。
          </p>
        </div>
      )}
    </div>
  )
}
