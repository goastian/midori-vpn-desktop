import { createRouter, createWebHistory } from 'vue-router'
import Dashboard from '../views/Dashboard.vue'
import Mesh from '../views/Mesh.vue'
import Settings from '../views/Settings.vue'

const routes = [
  { path: '/', component: Dashboard },
  { path: '/mesh', component: Mesh },
  { path: '/settings', component: Settings },
]

export default createRouter({
  history: createWebHistory(),
  routes,
})
