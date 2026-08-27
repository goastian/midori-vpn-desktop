<template>
  <div>
    <div class="card">
      <div class="section-title">{{ t('settings.sectionMesh') }}</div>
      <div class="row">
        <div>
          <div style="font-size:14px;">{{ t('settings.meshAutoStart') }}</div>
          <div class="label" style="margin-top:4px;">{{ t('settings.meshAutoStartHint') }}</div>
        </div>
        <button class="toggle" :class="{ on: meshAutoStart }" :disabled="featuresLocked" @click="toggleMeshAutoStart"></button>
      </div>
      <div v-if="meshSettingsError" class="error" style="margin-top:8px;">{{ meshSettingsError }}</div>
    </div>

    <div class="card">
      <div class="section-title">Protocolo de Conexión (Smart Protocol)</div>
      <div class="row" style="flex-direction:column; align-items:flex-start; gap:8px;">
        <div>
          <div style="font-size:14px;">Estrategia de Selección</div>
          <div class="label" style="margin-top:4px;">
            Smart Auto valida cada handshake real y recorre WireGuard, WSS y MASQUE según la prioridad y salud anunciadas por el servidor.
          </div>
        </div>
        <select v-model="selectedProtocolPolicy" class="select-field" @change="saveProtocolPolicy">
          <option value="smart_auto">Smart Auto (Recomendado)</option>
          <option value="wireguard">Forzar WireGuard (UDP 51820)</option>
          <option value="wss">Forzar WireGuard sobre WSS (TLS 443, si está disponible)</option>
          <option value="masque">Forzar WireGuard sobre MASQUE (HTTP/3 UDP 443, si está disponible)</option>
          <option value="openvpn">Forzar OpenVPN 2.7/DCO (UDP 1194, si está certificado)</option>
          <option value="ikev2">Forzar IKEv2/EAP-TLS (UDP 500/4500, si está certificado)</option>
        </select>
      </div>
    </div>

    <div class="card">
      <div class="section-title">Inicio de la aplicación</div>
      <div class="row">
        <div>
          <div style="font-size:14px;">Iniciar minimizado en la bandeja</div>
          <div class="label" style="margin-top:4px;">Al iniciar sesión, oculta la ventana solo si el escritorio ofrece bandeja del sistema.</div>
        </div>
        <button class="toggle" :class="{ on: startMinimized }" @click="toggleStartMinimized"></button>
      </div>
      <div v-if="uiSettingsError" class="error" style="margin-top:8px;">{{ uiSettingsError }}</div>
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
      <div v-if="autostartError" class="error" style="margin-top:8px;">{{ autostartError }}</div>
    </div>

    <div class="card">
      <div class="section-title">{{ t('settings.sectionAgent') }}</div>
      <div class="row" style="margin-bottom:12px;">
        <div class="label">{{ t('settings.localPort') }}</div>
        <div class="value">{{ rpcPort ?? '—' }}</div>
      </div>
      <div class="row">
        <div class="label">{{ t('settings.proxyPort') }}</div>
        <div class="value">{{ proxyPort ?? '—' }}</div>
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
        <div class="value">{{ appVersion }}</div>
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
import { agent, invokePlatform } from '../lib/agent'
import { useCaps } from '../composables/useCaps'
import { toErrorMessage } from '../lib/error'
import QuitButton from '../components/QuitButton.vue'

const { t } = useI18n()
const appVersion = __APP_VERSION__

const autostart = ref(false)
const meshAutoStart = ref(true)
const startMinimized = ref(false)
const selectedProtocolPolicy = ref('smart_auto')
const autostartError = ref<string | null>(null)
const meshSettingsError = ref<string | null>(null)
const uiSettingsError = ref<string | null>(null)
const tokenStoreLabel = ref('—')
const tokenStoreDegraded = ref(false)
const rpcPort = ref<number | null>(null)
const proxyPort = ref<number | null>(null)
const { featuresLocked, capsGranted, capsGranting, capsError, revertCaps } = useCaps()
const revertResult = ref<'idle' | 'ok' | 'err'>('idle')
const tokenStoreDisplay = computed(() =>
  tokenStoreLabel.value === 'unknown' ? t('settings.unknown') : tokenStoreLabel.value
)

function saveProtocolPolicy() {
  localStorage.setItem('midori_protocol_policy', selectedProtocolPolicy.value)
}

async function handleRevertCaps() {
  revertResult.value = 'idle'
  const ok = await revertCaps()
  revertResult.value = ok ? 'ok' : 'err'
}

interface AgentSettings {
  mesh?: { start_disabled?: boolean }
  autostart?: { enabled?: boolean }
  ui?: { start_minimized?: boolean }
}

onMounted(async () => {
  // Restore saved protocol policy
  const storedPolicy = localStorage.getItem('midori_protocol_policy')
  if (storedPolicy) {
    selectedProtocolPolicy.value = storedPolicy
  }

  // Autostart status comes from the OS (XDG autostart file presence).
  try {
    autostart.value = await invokePlatform<boolean>('autostart_is_enabled')
  } catch (e) {
    autostartError.value = toErrorMessage(e)
  }
  // Mesh boot preference comes from the agent settings store.
  try {
    const s = await agent.settings.get() as AgentSettings
    meshAutoStart.value = !(s?.mesh?.start_disabled ?? false)
    startMinimized.value = s?.ui?.start_minimized ?? false
  } catch (e) {
    meshSettingsError.value = toErrorMessage(e)
  }
  try {
    const snapshot = await agent.status()
    rpcPort.value = snapshot.local_rpc?.port ?? null
    proxyPort.value = snapshot.local_proxy?.port ?? null
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
    await invokePlatform('autostart_set', { enabled: next })
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
      ui: { start_minimized: startMinimized.value },
    })
    meshAutoStart.value = next
  } catch (e) {
    meshSettingsError.value = toErrorMessage(e)
  }
}

async function toggleStartMinimized() {
  const next = !startMinimized.value
  uiSettingsError.value = null
  try {
    await agent.settings.put({
      mesh: { start_disabled: !meshAutoStart.value },
      autostart: { enabled: autostart.value },
      ui: { start_minimized: next },
    })
    startMinimized.value = next
  } catch (e) {
    uiSettingsError.value = toErrorMessage(e)
  }
}
</script>

<style scoped>
.select-field {
  width: 100%;
  padding: 8px 12px;
  border-radius: 8px;
  border: 1px solid var(--border);
  background: var(--surface);
  color: var(--ink);
  font-size: 13px;
  font-weight: 500;
  outline: none;
  cursor: pointer;
  transition: border-color 0.15s;
}
.select-field:focus {
  border-color: var(--midori-500);
}
</style>
