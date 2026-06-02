import { createRouter, createWebHistory } from 'vue-router'
import { useAuthStore } from '../stores/auth'

// Route components are lazy-loaded so the initial bundle only contains the
// auth store, the router, and shared infrastructure. Each view becomes its
// own chunk fetched on first navigation.
const Dashboard = () => import('../views/Dashboard.vue')
const Mesh = () => import('../views/Mesh.vue')
const Settings = () => import('../views/Settings.vue')
const Login = () => import('../views/Login.vue')

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
