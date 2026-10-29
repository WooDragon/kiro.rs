import type { Ref } from 'react'
import { Button } from '@/components/ui/button'
import { Checkbox } from '@/components/ui/checkbox'
import { Input } from '@/components/ui/input'
import type { CredentialFilter } from '@/lib/credential-list'

interface CredentialListToolbarProps {
  search: string
  status: CredentialFilter
  selectedCount: number
  pageChecked: boolean | 'indeterminate'
  pageEmpty: boolean
  pending: boolean
  searchRef?: Ref<HTMLInputElement>
  onSearchChange: (value: string) => void
  onStatusChange: (value: CredentialFilter) => void
  onTogglePage: () => void
  onClearSelection: () => void
}

export function CredentialListToolbar(props: CredentialListToolbarProps) {
  return (
    <div className="space-y-2 rounded-lg border p-3 text-sm">
      <div className="flex flex-wrap gap-2">
        <Input ref={props.searchRef} type="search" aria-label="搜索凭据"
          placeholder="搜索邮箱 / ID / 代理名称" value={props.search}
          readOnly={props.pending} onChange={event => props.onSearchChange(event.target.value)}
          className="min-h-11 min-w-0 flex-1 basis-48 sm:min-h-8" />
        <select aria-label="凭据状态" value={props.status} disabled={props.pending}
          onChange={event => props.onStatusChange(event.target.value as CredentialFilter)}
          className="min-h-11 rounded-md border bg-background px-3 sm:min-h-8">
          <option value="all">全部状态</option>
          <option value="enabled">启用</option>
          <option value="disabled">已禁用</option>
        </select>
      </div>
      <div className="flex flex-wrap items-center gap-x-3 gap-y-1">
        <label className="flex min-h-11 cursor-pointer items-center gap-2 sm:min-h-8">
          <Checkbox aria-label="选择当前页" checked={props.pageChecked}
            disabled={props.pending || props.pageEmpty} onCheckedChange={props.onTogglePage} />
          当前页全选
        </label>
        <span role="status">已选 {props.selectedCount} 项</span>
        <Button size="sm" variant="ghost" className="min-h-11 sm:min-h-8"
          disabled={props.pending || props.selectedCount === 0} onClick={props.onClearSelection}>清空选择</Button>
      </div>
      <p className="text-muted-foreground">选择可包含其他页或不可见项；更改搜索或状态会清空选择并回到第一页。</p>
    </div>
  )
}
