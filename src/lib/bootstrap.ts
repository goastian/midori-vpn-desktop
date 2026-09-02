export type BootstrapPhase = 'loading' | 'retrying' | 'ready' | 'failed'
export type BootstrapAttempt = 'initial' | 'retry'

interface BootstrapDependencies {
  initialize: (attempt: BootstrapAttempt) => Promise<void>
  subscribe: () => () => void
  onPhaseChange: (phase: BootstrapPhase) => void
}

export function createBootstrapCoordinator(dependencies: BootstrapDependencies) {
  let inFlight: Promise<boolean> | null = null
  let unsubscribe: (() => void) | null = null
  let stopped = false

  function run(attempt: BootstrapAttempt): Promise<boolean> {
    if (stopped) return Promise.resolve(false)
    if (inFlight) return inFlight

    dependencies.onPhaseChange(attempt === 'initial' ? 'loading' : 'retrying')
    inFlight = (async () => {
      try {
        await dependencies.initialize(attempt)
        if (stopped) return false
        if (!unsubscribe) unsubscribe = dependencies.subscribe()
        dependencies.onPhaseChange('ready')
        return true
      } catch {
        if (!stopped) dependencies.onPhaseChange('failed')
        return false
      } finally {
        inFlight = null
      }
    })()
    return inFlight
  }

  function stop() {
    stopped = true
    unsubscribe?.()
    unsubscribe = null
  }

  return { run, stop }
}
