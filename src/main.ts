import { createApp } from 'vue'
import { createPinia } from 'pinia'
import router from './router'
import App from './App.vue'
import './assets/style.css'
import { i18n, initLocale } from './i18n'

// Lock zoom in the desktop UI (ctrl/cmd + wheel, +/-/0, trackpad pinch).
const preventZoomWheel = (e: WheelEvent) => {
	if (e.ctrlKey || e.metaKey) e.preventDefault()
}

const preventZoomKeys = (e: KeyboardEvent) => {
	const key = e.key
	if ((e.ctrlKey || e.metaKey) && (key === '+' || key === '-' || key === '=' || key === '0')) {
		e.preventDefault()
	}
}

const preventGestureZoom = (e: Event) => e.preventDefault()

window.addEventListener('wheel', preventZoomWheel, { passive: false })
window.addEventListener('keydown', preventZoomKeys)
document.addEventListener('gesturestart', preventGestureZoom)
document.addEventListener('gesturechange', preventGestureZoom)

async function bootstrap() {
  await initLocale()

  const app = createApp(App)
  app.use(createPinia())
  app.use(router)
  app.use(i18n)
  app.mount('#app')
}

void bootstrap()
