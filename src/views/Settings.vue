<template>
  <div>
    <!-- Language -->
    <div class="card">
      <LanguageSelect />
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
      <div class="row" style="margin-top:12px;">
        <div class="label">{{ t('settings.tokenStore') }}</div>
        <div class="value">{{ tokenStoreDisplay }}</div>
      </div>
      <div v-if="tokenStoreDegraded" class="error" style="margin-top:8px;">{{ t('settings.tokenStoreFallback') }}</div>
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
import { computed, ref, onMounted } from 'vue'
import { useI18n } from 'vue-i18n'
import { invoke } from '@tauri-apps/api/core'
import { agent } from '../lib/agent'
import { useCaps } from '../composables/useCaps'
import { toErrorMessage } from '../lib/error'
import LanguageSelect from '../components/LanguageSelect.vue'
import QuitButton from '../components/QuitButton.vue'

const { t } = useI18n()

const autostart = ref(false)
const meshAutoStart = ref(true)
const autostartError = ref<string | null>(null)
const meshSettingsError = ref<string | null>(null)
const tokenStoreLabel = ref('—')
const tokenStoreDegraded = ref(false)
const { featuresLocked, capsGranted, capsGranting, capsError, revertCaps } = useCaps()
const revertResult = ref<'idle' | 'ok' | 'err'>('idle')
const tokenStoreDisplay = computed(() =>
  tokenStoreLabel.value === 'unknown' ? t('settings.unknown') : tokenStoreLabel.value
)

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
  try {
    const snapshot = await agent.status()
    tokenStoreLabel.value = snapshot.security?.token_store ?? 'unknown'
    tokenStoreDegraded.value = snapshot.security?.token_store_degraded ?? true
  } catch {
    tokenStoreLabel.value = 'unknown'
    tokenStoreDegraded.value = true
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
