import { createRouter, createWebHistory } from 'vue-router'
import Dashboard from '../views/Dashboard.vue'
import Mesh from '../views/Mesh.vue'
import Settings from '../views/Settings.vue'
import Login from '../views/Login.vue'
import { useAuthStore } from '../stores/auth'

const routes = [
  { path: '/login', component: Login, meta: { public: true } },
  { path: '/', component: Dashboard },
  { path: '/mesh', component: Mesh },
  { path: '/settings', component: Settings },
]

const router = createRouter({
  history: createWebHistory(),
  routes,
})

// Wait until the auth store has applied at least one /status snapshot before
// deciding whether to redirect. Otherwise an unauthenticated default would
// briefly bounce the UI to /login on every cold start.
function whenInitialized(auth: ReturnType<typeof useAuthStore>): Promise<void> {
  if (auth.initialized) return Promise.resolve()
  return new Promise((resolve) => {
    const stop = auth.$subscribe(() => {
      if (auth.initialized) {
        stop()
        resolve()
      }
    })
    // Fail-safe: don't block navigation forever if the agent never reports.
    setTimeout(() => {
      stop()
      resolve()
    }, 5000)
  })
}

router.beforeEach(async (to) => {
  if (to.meta.public) return true
  const auth = useAuthStore()
  await whenInitialized(auth)
  if (!auth.authenticated) {
    return { path: '/login', query: { next: to.fullPath } }
  }
  return true
})

export default router
