<template>
  <div>
    <!-- Language -->
    <div class="card">
      <div class="section-title">{{ t('settings.language') }}</div>
      <div class="row">
        <div class="label" style="margin-bottom:0">{{ t('settings.languageHint') }}</div>
        <select class="lang-select" :value="currentLocale" @change="onLocaleChange">
          <option value="es">Español</option>
          <option value="en">English</option>
          <option value="pt">Português</option>
        </select>
      </div>
    </div>

    <div class="card">
      <div class="section-title">{{ t('settings.sectionMesh') }}</div>
      <div class="row">
        <div>
          <div style="font-size:14px;">{{ t('settings.meshAutoStart') }}</div>
          <div class="label" style="margin-top:4px;">{{ t('settings.meshAutoStartHint') }}</div>
        </div>
        <button class="toggle" :class="{ on: meshAutoStart }" :disabled="featuresLocked" @click="toggleMeshAutoStart"></button>
      </div>
    </div>

    <div class="card">
      <div class="section-title">{{ t('settings.sectionAutoStart') }}</div>
      <div class="row">
        <div>
          <div style="font-size:14px;">{{ t('settings.autoStart') }}</div>
          <div class="label" style="margin-top:4px;">{{ t('settings.autoStartHint') }}</div>
        </div>
        <button class="toggle" :class="{ on: autostart }" @click="toggleAutostart"></button>
      </div>
    </div>

    <div class="card">
      <div class="section-title">{{ t('settings.sectionAgent') }}</div>
      <div class="row" style="margin-bottom:12px;">
        <div class="label">{{ t('settings.localPort') }}</div>
        <div class="value">7071</div>
      </div>
      <div class="row">
        <div class="label">{{ t('settings.proxyPort') }}</div>
        <div class="value">8888</div>
      </div>
    </div>

    <div class="card">
      <div class="section-title">{{ t('settings.sectionAbout') }}</div>
      <div class="row">
        <div class="label">{{ t('settings.version') }}</div>
        <div class="value">1.0.0</div>
      </div>
    </div>

    <div class="card">
      <QuitButton />
    </div>

    <!-- Permissions management -->
    <div class="card" v-if="capsGranted">
      <div class="section-title">{{ t('settings.sectionPerms') }}</div>
      <div class="row" style="flex-direction:column; align-items:flex-start; gap:8px;">
        <div>
          <div style="font-size:14px; color:var(--ink)">{{ t('settings.revertPerms') }}</div>
          <div class="label" style="margin-top:4px;">{{ t('settings.revertPermsHint') }}</div>
        </div>
        <div style="display:flex; align-items:center; gap:12px; flex-wrap:wrap;">
          <button
            class="btn btn-secondary"
            :disabled="capsGranting"
            @click="handleRevertCaps"
          >
            {{ capsGranting ? t('settings.reverting') : t('settings.revertPermsBtn') }}
          </button>
          <span v-if="revertResult === 'ok'" style="font-size:12px; color:var(--midori-500)">{{ t('settings.revertOk') }}</span>
          <span v-if="revertResult === 'err'" style="font-size:12px; color:#f28b82">{{ capsError || t('settings.revertErr') }}</span>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted } from 'vue'
import { useI18n } from 'vue-i18n'
import { invoke } from '@tauri-apps/api/core'
import { agent } from '../lib/agent'
import { useCaps } from '../composables/useCaps'
import { toErrorMessage } from '../lib/error'
import { setLocale, getLocale, type Locale } from '../i18n'
import QuitButton from '../components/QuitButton.vue'

const { t } = useI18n()
const currentLocale = ref<Locale>(getLocale())

function onLocaleChange(e: Event) {
  const lang = (e.target as HTMLSelectElement).value as Locale
  setLocale(lang)
  currentLocale.value = lang
}

const autostart = ref(false)
const meshAutoStart = ref(true)
const autostartError = ref<string | null>(null)
const meshSettingsError = ref<string | null>(null)
const { featuresLocked, capsGranted, capsGranting, capsError, revertCaps } = useCaps()
const revertResult = ref<'idle' | 'ok' | 'err'>('idle')

async function handleRevertCaps() {
  revertResult.value = 'idle'
  const ok = await revertCaps()
  revertResult.value = ok ? 'ok' : 'err'
}

interface AgentSettings {
  mesh?: { start_disabled?: boolean }
  autostart?: { enabled?: boolean }
}

onMounted(async () => {
  // Autostart status comes from the OS (XDG autostart file presence).
  try {
    autostart.value = await invoke<boolean>('autostart_is_enabled')
  } catch (e) {
    autostartError.value = toErrorMessage(e)
  }
  // Mesh boot preference comes from the agent settings store.
  try {
    const s = await agent.settings.get() as AgentSettings
    meshAutoStart.value = !(s?.mesh?.start_disabled ?? false)
  } catch (e) {
    meshSettingsError.value = toErrorMessage(e)
  }
})

async function toggleAutostart() {
  const next = !autostart.value
  autostartError.value = null
  try {
    await invoke('autostart_set', { enabled: next })
    autostart.value = next
  } catch (e) {
    autostartError.value = toErrorMessage(e)
  }
}

async function toggleMeshAutoStart() {
  const next = !meshAutoStart.value
  meshSettingsError.value = null
  try {
    await agent.settings.put({
      mesh: { start_disabled: !next },
      autostart: { enabled: autostart.value },
    })
    meshAutoStart.value = next
  } catch (e) {
    meshSettingsError.value = toErrorMessage(e)
  }
}
</script>

<style scoped>
.lang-select {
  background: var(--surface-2, #1a2b24);
  color: var(--ink, #ecfdf5);
  border: 1px solid var(--border, #2d4a3e);
  border-radius: 6px;
  padding: 5px 10px;
  font-size: 13px;
  cursor: pointer;
  outline: none;
  min-width: 120px;
}
.lang-select:focus {
  border-color: var(--midori-500, #22c55e);
}
</style>
