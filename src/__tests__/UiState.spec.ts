import { describe, expect, it } from 'vitest'
import { mount } from '@vue/test-utils'

import EmptyState from '../components/EmptyState.vue'
import { getConnectionBlocker } from '../lib/uiState'

const available = {
  active: false,
  busy: false,
  authenticated: true,
  permissionsLocked: false,
  destinationsLoading: false,
  hasDestination: true,
}

describe('desktop availability presentation', () => {
  it('announces an empty state with its optional guidance', () => {
    const wrapper = mount(EmptyState, {
      props: {
        title: 'No destinations available',
        detail: 'Try again after refreshing the server list.',
        compact: true,
      },
    })

    expect(wrapper.attributes('role')).toBe('status')
    expect(wrapper.get('.empty-state-title').text()).toBe('No destinations available')
    expect(wrapper.get('.empty-state-detail').text()).toContain('refreshing')
    expect(wrapper.classes()).toContain('empty-state--compact')
  })

  it.each([
    [{ ...available, authenticated: false }, 'sign_in'],
    [{ ...available, permissionsLocked: true }, 'permissions'],
    [{ ...available, destinationsLoading: true }, 'loading'],
    [{ ...available, hasDestination: false }, 'no_destination'],
    [available, null],
  ] as const)('identifies the reason a new connection is unavailable', (state, expected) => {
    expect(getConnectionBlocker(state)).toBe(expected)
  })

  it('does not block an active connection when permissions change', () => {
    expect(getConnectionBlocker({
      ...available,
      active: true,
      permissionsLocked: true,
      hasDestination: false,
    })).toBeNull()
  })

  it('leaves transient busy-state messaging to the connection phase', () => {
    expect(getConnectionBlocker({
      ...available,
      busy: true,
      authenticated: false,
    })).toBeNull()
  })
})
