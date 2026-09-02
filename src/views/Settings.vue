<template>
  <div>
    <div class="card">
      <div class="section-title">{{ t('settings.sectionMesh') }}</div>
      <div class="row">
        <div>
          <div style="font-size:14px;">{{ t('settings.meshAutoStart') }}</div>
          <div class="label" style="margin-top:4px;">{{ t('settings.meshAutoStartHint') }}</div>
        </div>
        <ToggleSwitch :checked="meshAutoStart" :label="t('settings.meshAutoStart')" :disabled="featuresLocked" @change="toggleMeshAutoStart" />
      </div>
      <div v-if="featuresLocked" class="setting-blocked-hint">{{ t('settings.permissionsRequired') }}</div>
      <div v-if="meshSettingsError" class="error" style="margin-top:8px;" role="alert">{{ meshSettingsError }}</div>
    </div>

    <div class="card">
      <div class="section-title">{{ t('settings.protocolTitle') }}</div>
      <div class="row" style="flex-direction:column; align-items:flex-start; gap:8px;">
        <div>
          <div style="font-size:14px;">{{ t('settings.protocolStrategy') }}</div>
        </div>
        <select v-model="selectedProtocolPolicy" class="select-field" @change="saveProtocolPolicy">
          <option
            v-for="option in protocolOptions"
            :key="option.value"
            :value="option.value"
            :disabled="!option.available"
          >{{ option.label }}{{ option.available ? '' : ` — ${t('settings.protocolUnavailableShort')}` }}</option>
        </select>
        <div class="label">{{ selectedProtocolDescription }}</div>
        <div v-if="protocolAvailabilityHint" class="availability-hint">{{ protocolAvailabilityHint }}</div>
      </div>
    </div>

    <div class="card">
      <div class="section-title">{{ t('settings.certificates.title') }}</div>
      <div class="label certificate-hint">{{ t('settings.certificates.hint') }}</div>
      <div v-if="certificatesLoading" class="label">{{ t('settings.certificates.loading') }}</div>
      <EmptyState v-else-if="activeCertificates.length === 0" compact :title="t('settings.certificates.empty')" />
      <div v-else class="certificate-list">
        <div v-for="certificate in activeCertificates" :key="certificate.id" class="certificate-row">
          <div class="certificate-copy">
            <div class="certificate-name">
              {{ certificate.device_name }}
              <span v-if="certificate.is_this_device" class="current-badge">{{ t('settings.certificates.thisDevice') }}</span>
            </div>
            <div class="label">{{ t('settings.certificates.expires', { date: formatCertificateDate(certificate.not_after) }) }}</div>
          </div>
          <button
            class="btn btn-secondary certificate-revoke"
            :disabled="revokingCertificateId === certificate.id || (certificate.is_this_device && vpn.connected)"
            @click="revokeCertificate(certificate)"
          >
            {{ revokingCertificateId === certificate.id ? t('settings.certificates.revoking') : t('settings.certificates.revoke') }}
          </button>
        </div>
      </div>
      <div v-if="certificateError" class="error certificate-message" role="alert">{{ certificateError }}</div>
      <div v-if="certificateNotice" class="success-message certificate-message" role="status" aria-live="polite">{{ certificateNotice }}</div>
    </div>

    <div class="card">
      <div class="section-title">{{ t('settings.sectionAutoStart') }}</div>
      <div class="row">
        <div>
          <div style="font-size:14px;">{{ t('settings.autoStart') }}</div>
          <div class="label" style="margin-top:4px;">{{ t('settings.autoStartHint') }}</div>
        </div>
        <ToggleSwitch :checked="autostart" :label="t('settings.autoStart')" @change="toggleAutostart" />
      </div>
      <div class="row nested-setting">
        <div>
          <div style="font-size:14px;">{{ t('settings.startMinimized') }}</div>
          <div class="label" style="margin-top:4px;">{{ t('settings.startMinimizedHint') }}</div>
        </div>
        <ToggleSwitch :checked="startMinimized" :label="t('settings.startMinimized')" :disabled="!autostart" @change="toggleStartMinimized" />
      </div>
      <div v-if="!autostart" class="setting-blocked-hint">{{ t('settings.startMinimizedUnavailable') }}</div>
      <div v-if="autostartError" class="error" style="margin-top:8px;" role="alert">{{ autostartError }}</div>
      <div v-if="uiSettingsError" class="error" style="margin-top:8px;" role="alert">{{ uiSettingsError }}</div>
    </div>

    <div class="card"><LanguageSelect /></div>

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
import LanguageSelect from '../components/LanguageSelect.vue'
import { useVpnStore } from '../stores/vpn'
import type { DeviceCertificate } from '../lib/agent'
import { protocolIsAvailable, type ProtocolPolicy } from '../lib/protocol'
import ToggleSwitch from '../components/ToggleSwitch.vue'
import EmptyState from '../components/EmptyState.vue'

const { t, locale } = useI18n()
const appVersion = __APP_VERSION__

const autostart = ref(false)
const meshAutoStart = ref(true)
const startMinimized = ref(false)
const selectedProtocolPolicy = ref('smart_auto')
const autostartError = ref<string | null>(null)
const meshSettingsError = ref<string | null>(null)
const uiSettingsError = ref<string | null>(null)
const vpn = useVpnStore()
const { featuresLocked, capsGranted, capsGranting, capsError, revertCaps } = useCaps()
const revertResult = ref<'idle' | 'ok' | 'err'>('idle')
const certificates = ref<DeviceCertificate[]>([])
const certificatesLoading = ref(false)
const revokingCertificateId = ref<string | null>(null)
const certificateError = ref<string | null>(null)
const certificateNotice = ref<string | null>(null)

const activeCertificates = computed(() => certificates.value.filter((certificate) => !certificate.revoked_at))

const protocolOptions = computed(() => {
  return (['smart_auto', 'wireguard', 'wss', 'masque', 'openvpn', 'ikev2'] as ProtocolPolicy[]).map((value) => ({
    value,
    label: t(`settings.protocols.${value}.name`),
    // A refresh may temporarily hide a transport in Control, but it must not
    // invalidate or relabel a tunnel that is already carrying user traffic.
    available: protocolIsAvailable(value, vpn.servers, vpn.connected, vpn.activeProtocol),
  }))
})

const selectedProtocolDescription = computed(() => t(`settings.protocols.${selectedProtocolPolicy.value}.description`))
const protocolAvailabilityHint = computed(() => {
  return protocolOptions.value.some((option) => !option.available)
    ? t('settings.protocolUnavailableHint')
    : ''
})

function saveProtocolPolicy() {
  localStorage.setItem('midori_protocol_policy', selectedProtocolPolicy.value)
}

function formatCertificateDate(value: string) {
  const date = new Date(value)
  if (Number.isNaN(date.getTime())) return t('settings.unknown')
  return new Intl.DateTimeFormat(locale.value, { dateStyle: 'medium' }).format(date)
}

async function loadCertificates() {
  certificatesLoading.value = true
  certificateError.value = null
  try {
    certificates.value = await agent.certificates.list()
  } catch (e) {
    certificateError.value = toErrorMessage(e)
  } finally {
    certificatesLoading.value = false
  }
}

async function revokeCertificate(certificate: DeviceCertificate) {
  if (!window.confirm(t('settings.certificates.confirm', { device: certificate.device_name }))) return
  revokingCertificateId.value = certificate.id
  certificateError.value = null
  certificateNotice.value = null
  try {
    const result = await agent.certificates.revoke(certificate.id)
    certificates.value = certificates.value.filter((item) => item.id !== certificate.id)
    certificateNotice.value = result.local_credential_removed
      ? t('settings.certificates.revokedThisDevice')
      : t('settings.certificates.revoked')
  } catch (e) {
    certificateError.value = toErrorMessage(e)
  } finally {
    revokingCertificateId.value = null
  }
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

  await vpn.fetchServers(true)
  await loadCertificates()
  const selected = protocolOptions.value.find((option) => option.value === selectedProtocolPolicy.value)
  if (!selected?.available && !vpn.connected) {
    selectedProtocolPolicy.value = 'smart_auto'
    saveProtocolPolicy()
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
.select-field option:disabled { color: var(--muted-2); }
.availability-hint {
  color: #b45309;
  background: #fffbeb;
  border: 1px solid #fde68a;
  border-radius: 8px;
  padding: 8px 10px;
  font-size: 12px;
}
.nested-setting {
  margin-top: 14px;
  padding-top: 14px;
  border-top: 1px solid var(--border);
}
.certificate-hint { margin-bottom: 12px; }
.certificate-list { display: flex; flex-direction: column; gap: 10px; }
.certificate-row {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 12px;
  padding: 10px 0;
  border-top: 1px solid var(--border);
}
.certificate-copy { min-width: 0; }
.certificate-name { color: var(--ink); font-size: 13px; overflow-wrap: anywhere; }
.current-badge {
  display: inline-block;
  margin-left: 6px;
  padding: 2px 6px;
  border-radius: 999px;
  background: color-mix(in srgb, var(--midori-500) 14%, transparent);
  color: var(--midori-500);
  font-size: 10px;
  font-weight: 700;
}
.certificate-revoke { flex: 0 0 auto; }
.certificate-message { margin-top: 10px; }
.success-message { color: var(--midori-500); font-size: 12px; }
.setting-blocked-hint { margin-top: 8px; color: var(--muted); font-size: 11.5px; line-height: 1.4; }
</style>
