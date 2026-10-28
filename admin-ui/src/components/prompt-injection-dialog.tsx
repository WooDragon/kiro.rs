import { useEffect, useRef, useState, type MutableRefObject, type ReactNode } from 'react'
import { toast } from 'sonner'
import {
  Dialog, DialogContent, DialogDescription, DialogFooter,
  DialogHeader, DialogTitle, DialogTrigger,
} from '@/components/ui/dialog'
import { Button } from '@/components/ui/button'
import { usePromptInjection, useSetPromptInjection } from '@/hooks/use-credentials'
import { extractErrorMessage } from '@/lib/utils'

const MAX_BYTES = 16384

interface PromptInjectionDialogProps {
  open: boolean
  onOpenChange: (open: boolean) => void
  trigger: ReactNode
}

export function PromptInjectionDialog({ open, onOpenChange, trigger }: PromptInjectionDialogProps) {
  const saving = useRef(false)
  return (
    <Dialog open={open} onOpenChange={(next) => { if (!saving.current) onOpenChange(next) }}>
      <DialogTrigger asChild>{trigger}</DialogTrigger>
      {open && <PromptInjectionEditor saving={saving} onSaved={() => onOpenChange(false)}
        onCancel={() => { if (!saving.current) onOpenChange(false) }} />}
    </Dialog>
  )
}

function PromptInjectionEditor({ saving, onSaved, onCancel }: {
  saving: MutableRefObject<boolean>
  onSaved: () => void
  onCancel: () => void
}) {
  const query = usePromptInjection()
  const mutation = useSetPromptInjection()
  const [draft, setDraft] = useState<string | null>(null)
  const [saveError, setSaveError] = useState<string | null>(null)
  const bytes = new TextEncoder().encode(draft ?? '').length
  const overLimit = bytes > MAX_BYTES

  // 每次打开都等待新读取；后续 refetch 只更新缓存，不接管编辑中的草稿。
  useEffect(() => {
    if (query.isFetchedAfterMount && query.isSuccess && draft === null) {
      setDraft(query.data.promptInjection)
    }
  }, [query.isFetchedAfterMount, query.isSuccess, query.data, draft])

  const submit = (event: React.FormEvent) => {
    event.preventDefault()
    if (saving.current || draft === null || overLimit) return
    saving.current = true
    setSaveError(null)
    mutation.mutate(draft, {
      onSuccess: (data) => {
        saving.current = false
        setDraft(data.promptInjection)
        toast.success('提示词注入已保存')
        onSaved()
      },
      onError: (error) => {
        saving.current = false
        setSaveError(extractErrorMessage(error))
      },
    })
  }

  return (
    <DialogContent className="sm:max-w-xl max-h-[90vh] overflow-y-auto"
      onEscapeKeyDown={(event) => { if (saving.current) event.preventDefault() }}
      onInteractOutside={(event) => { if (saving.current) event.preventDefault() }}>
      <DialogHeader>
        <DialogTitle>提示词注入</DialogTitle>
        <DialogDescription>
          对当前实例全部常规模型请求生效，纯 WebSearch 不注入。保存后影响已有对话的后续请求，
          可能改变消息段缓存命中。空白关闭；不保证上游服从。不要填写凭据。
        </DialogDescription>
      </DialogHeader>
      <form onSubmit={submit} className="space-y-4">
        {draft === null ? (
          query.isError ? (
            <div className="space-y-2">
              <p role="alert" className="text-sm text-destructive">读取失败：{extractErrorMessage(query.error)}</p>
              <Button type="button" variant="outline" disabled={query.isFetching}
                onClick={() => query.refetch()}>重试</Button>
            </div>
          ) : <p role="status" className="text-sm text-muted-foreground">正在读取提示词配置...</p>
        ) : (
          <div className="space-y-2">
            <label htmlFor="prompt-injection" className="text-sm font-medium">注入提示词</label>
            <textarea id="prompt-injection" value={draft} rows={10}
              onChange={(event) => setDraft(event.target.value)} disabled={mutation.isPending}
              aria-describedby="prompt-injection-bytes" aria-invalid={overLimit}
              className="flex w-full rounded-md border border-input bg-background px-3 py-2 text-sm ring-offset-background focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 disabled:cursor-not-allowed disabled:opacity-50" />
            <p id="prompt-injection-bytes" aria-live="polite"
              className={overLimit ? 'text-sm text-destructive' : 'text-sm text-muted-foreground'}>
              {bytes} / {MAX_BYTES} 字节（UTF-8）
            </p>
            {overLimit && <p role="alert" className="text-sm text-destructive">提示词不能超过 16 KiB（16,384 字节）。</p>}
          </div>
        )}
        {saveError !== null && <p role="alert" className="text-sm text-destructive">保存失败：{saveError}</p>}
        <DialogFooter>
          <Button type="button" variant="outline" disabled={draft === null || mutation.isPending}
            onClick={() => setDraft('')}>清空草稿</Button>
          <Button type="button" variant="outline" disabled={mutation.isPending} onClick={onCancel}>取消</Button>
          <Button type="submit" disabled={draft === null || overLimit || mutation.isPending}>
            {mutation.isPending ? '保存中...' : '保存'}
          </Button>
        </DialogFooter>
      </form>
    </DialogContent>
  )
}
