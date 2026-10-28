import { Input } from '@/components/ui/input'
import { Badge } from '@/components/ui/badge'
import type { ProxyItem, ProxyMode } from '@/types/proxy'
import { PROTOCOL_LABELS, protocolOf } from '@/lib/proxies'

/** 模式卡片的选项（顺序固定：继承 → 直连 → 池 → 高级内联） */
const MODE_OPTIONS: { value: ProxyMode; label: string; hint: string }[] = [
  {
    value: 'inherit',
    label: '使用全局代理配置',
    hint: '使用运行时全局代理配置',
  },
  { value: 'direct', label: '明确直连', hint: '该凭据不走任何代理' },
  { value: 'pool', label: '使用指定代理', hint: '从代理列表选择一条代理，仅作用于本凭据' },
  { value: 'inline', label: '高级：内联地址', hint: '旧写法，仅该凭据使用' },
]

/** 内联三字段（受控值由调用方持有，不做任何 trim） */
export interface InlineProxyFields {
  url: string
  username: string
  password: string
}

export interface ProxyBindingSelectProps {
  globalProxyConfigured?: boolean
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
  globalProxyConfigured,
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
  const globalProxyHint = globalProxyConfigured === true
    ? '已配置全局代理'
    : globalProxyConfigured === false
      ? '未配置，使用系统默认网络'
      : '全局代理状态暂不可用'
  const selectedProxy = proxies.find((proxy) => proxy.id === poolId)

  return (
    <fieldset className="min-w-0 space-y-3" disabled={disabled}>
      <legend className="mb-2 text-sm font-medium">代理来源</legend>
      <div className="grid grid-cols-1 gap-2 sm:grid-cols-2">
        {MODE_OPTIONS.map((option) => (
          <label
            key={option.value}
            className={`flex min-w-0 items-start gap-3 rounded-lg border p-3 transition-colors focus-within:ring-2 focus-within:ring-ring focus-within:ring-offset-2 ${
              disabled ? 'cursor-not-allowed opacity-50' : 'cursor-pointer hover:bg-muted/50'
            } ${mode === option.value ? 'border-primary bg-primary/5' : 'border-input'}`}
          >
            <input
              type="radio"
              id={`${idPrefix}-${option.value}`}
              name={`${idPrefix}-mode`}
              value={option.value}
              checked={mode === option.value}
              onChange={() => onModeChange(option.value)}
              aria-labelledby={`${idPrefix}-${option.value}-title`}
              aria-describedby={`${idPrefix}-${option.value}-hint`}
              className="mt-1 h-4 w-4 shrink-0 accent-primary focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2"
            />
            <span className="min-w-0 space-y-1 [overflow-wrap:anywhere]">
              <span id={`${idPrefix}-${option.value}-title`} className="block text-sm font-medium leading-5">
                {option.label}
              </span>
              <span id={`${idPrefix}-${option.value}-hint`} className="block text-xs leading-relaxed text-muted-foreground">
                {option.value === 'inherit' ? globalProxyHint : option.hint}
              </span>
            </span>
          </label>
        ))}
      </div>

      {mode === 'pool' && (
        <div className="space-y-1">
          <select
            aria-label="选择指定代理"
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
              代理列表为空，请先在“代理列表”中新增条目
            </p>
          )}
          {selectedProxy && (
            <div className="flex min-w-0 flex-wrap items-center gap-2 text-xs text-muted-foreground">
              <Badge variant="outline">
                {PROTOCOL_LABELS[protocolOf(selectedProxy.url)] || protocolOf(selectedProxy.url) || '未知协议'}
              </Badge>
              <span className="min-w-0 font-mono [overflow-wrap:anywhere]">{selectedProxy.url}</span>
              {selectedProxy.hasPassword && <Badge variant="secondary">含认证</Badge>}
            </div>
          )}
        </div>
      )}

      {mode === 'inline' && (
        <div className="space-y-2 rounded-md border border-dashed p-3">
          <p className="text-xs text-muted-foreground">
            内联地址只作用于该凭据，不会进入代理列表，也不会被其他凭据复用。
          </p>
          <Input
            id={`${idPrefix}-inline-url`}
            aria-label="内联代理地址"
            placeholder="socks5h://host:1080"
            value={inline.url}
            onChange={(e) => onInlineChange({ ...inline, url: e.target.value })}
            disabled={disabled}
          />
          <div className="grid grid-cols-1 gap-2 sm:grid-cols-2">
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
    </fieldset>
  )
}
