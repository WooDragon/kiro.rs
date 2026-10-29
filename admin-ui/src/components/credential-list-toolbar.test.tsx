import { describe, expect, it, vi } from 'vitest'
import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { CredentialListToolbar } from './credential-list-toolbar'

function props() {
  return { search: '', status: 'all' as const, selectedCount: 2, pageChecked: 'indeterminate' as const,
    pageEmpty: false, pending: false, onSearchChange: vi.fn(), onStatusChange: vi.fn(),
    onTogglePage: vi.fn(), onClearSelection: vi.fn() }
}

it('受控筛选、半选和清空只调用对应回调，不自行改状态', async () => {
  const callbacks = props()
  render(<CredentialListToolbar {...callbacks} />)
  const user = userEvent.setup()
  expect(screen.getByRole('checkbox', { name: '选择当前页' })).toHaveAttribute('data-state', 'indeterminate')
  await user.type(screen.getByRole('searchbox'), 'a')
  expect(callbacks.onSearchChange).toHaveBeenCalledWith('a')
  expect(screen.getByRole('searchbox')).toHaveValue('')
  await user.selectOptions(screen.getByRole('combobox'), 'disabled')
  expect(callbacks.onStatusChange).toHaveBeenCalledWith('disabled')
  await user.click(screen.getByRole('checkbox'))
  await user.click(screen.getByRole('button', { name: '清空选择' }))
  expect(callbacks.onTogglePage).toHaveBeenCalledTimes(1)
  expect(callbacks.onClearSelection).toHaveBeenCalledTimes(1)
  expect(screen.getByText(/选择可包含其他页或不可见项/)).toBeInTheDocument()
})

describe('禁用状态', () => {
  it('批处理期间搜索只读但可获焦，其他筛选和选择仍禁用，结束解除只读', async () => {
    const callbacks = props()
    const view = render(<CredentialListToolbar {...callbacks} pending />)
    const search = screen.getByRole('searchbox')
    expect(search).toHaveAttribute('readonly')
    expect(search).toBeEnabled()
    search.focus()
    expect(search).toHaveFocus()
    await userEvent.setup().type(search, 'blocked')
    expect(callbacks.onSearchChange).not.toHaveBeenCalled()
    expect(search).toHaveValue('')
    for (const role of ['combobox', 'checkbox', 'button']) expect(screen.getByRole(role)).toBeDisabled()
    view.rerender(<CredentialListToolbar {...callbacks} />)
    expect(search).not.toHaveAttribute('readonly')
    expect(screen.getByRole('combobox')).toBeEnabled()
  })
  it('空页不可全选，无选择不可清空', () => {
    render(<CredentialListToolbar {...props()} pageEmpty selectedCount={0} />)
    expect(screen.getByRole('checkbox')).toBeDisabled()
    expect(screen.getByRole('button')).toBeDisabled()
    expect(screen.getByRole('searchbox')).not.toBeDisabled()
  })
})
