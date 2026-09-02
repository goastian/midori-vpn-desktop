export type ConnectionBlocker = 'sign_in' | 'permissions' | 'loading' | 'no_destination' | null

interface ConnectionAvailability {
  active: boolean
  busy: boolean
  authenticated: boolean
  permissionsLocked: boolean
  destinationsLoading: boolean
  hasDestination: boolean
}

export function getConnectionBlocker(state: ConnectionAvailability): ConnectionBlocker {
  if (state.active || state.busy) return null
  if (!state.authenticated) return 'sign_in'
  if (state.permissionsLocked) return 'permissions'
  if (state.destinationsLoading) return 'loading'
  if (!state.hasDestination) return 'no_destination'
  return null
}
