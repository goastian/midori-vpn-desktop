<template>
  <Teleport to="body">
    <div v-if="open" class="perm-overlay" @click.self="$emit('cancel')">
      <div class="perm-modal" role="dialog" aria-modal="true" aria-labelledby="perm-title">

        <div class="perm-header">
          <div class="perm-icon">🔐</div>
          <div>
            <div id="perm-title" class="perm-title">{{ t('perms.modalTitle') }}</div>
            <div class="perm-subtitle">
              {{ t('perms.modalSubtitle').split('\n')[0] }}<br>
              <strong>{{ t('perms.modalSubtitle').split('\n')[1] }}</strong>
            </div>
          </div>
        </div>

        <div class="perm-list">
          <!-- Capabilities -->
          <div class="perm-item">
            <div class="perm-item-icon perm-cap">⚙️</div>
            <div class="perm-item-body">
              <div class="perm-item-title">{{ t('perms.caps.title') }}</div>
              <div class="perm-item-desc">{{ t('perms.caps.desc') }}</div>
              <div class="perm-item-revert">{{ t('perms.caps.revert') }}</div>
            </div>
          </div>

          <!-- Firewall -->
          <div class="perm-item">
            <div class="perm-item-icon perm-fw">🛡️</div>
            <div class="perm-item-body">
              <div class="perm-item-title">{{ t('perms.firewall.title') }}</div>
              <div class="perm-item-desc">{{ t('perms.firewall.desc') }}</div>
              <div class="perm-item-revert">{{ t('perms.firewall.revert') }}</div>
            </div>
          </div>

          <!-- nftables kill switch -->
          <div class="perm-item">
            <div class="perm-item-icon perm-nft">🔒</div>
            <div class="perm-item-body">
              <div class="perm-item-title">{{ t('perms.killswitch.title') }}</div>
              <div class="perm-item-desc">{{ t('perms.killswitch.desc') }}</div>
              <div class="perm-item-revert">{{ t('perms.killswitch.revert') }}</div>
            </div>
          </div>

          <!-- DNS -->
          <div class="perm-item">
            <div class="perm-item-icon perm-dns">📡</div>
            <div class="perm-item-body">
              <div class="perm-item-title">{{ t('perms.dns.title') }}</div>
              <div class="perm-item-desc">{{ t('perms.dns.desc') }}</div>
              <div class="perm-item-revert">{{ t('perms.dns.revert') }}</div>
            </div>
          </div>

          <!-- AppArmor / SELinux — informational -->
          <div class="perm-item perm-item-info">
            <div class="perm-item-icon perm-sec">ℹ️</div>
            <div class="perm-item-body">
              <div class="perm-item-title">{{ t('perms.aa.title') }}</div>
              <div class="perm-item-desc">{{ t('perms.aa.desc') }}</div>
              <div class="perm-item-revert">{{ t('perms.aa.revert') }}</div>
            </div>
          </div>
        </div>

        <div class="perm-footer">
          <span v-if="error" class="perm-error">{{ error }}</span>
          <div class="perm-actions">
            <button class="btn btn-ghost" :disabled="loading" @click="$emit('cancel')">{{ t('perms.cancel') }}</button>
            <button class="btn btn-primary" :disabled="loading" @click="accept">
              <span v-if="loading" class="spinner" />
              {{ loading ? t('perms.applying') : t('perms.accept') }}
            </button>
          </div>
        </div>

      </div>
    </div>
  </Teleport>
</template>

<script setup lang="ts">
import { ref } from 'vue'
import { useI18n } from 'vue-i18n'

const { t } = useI18n()
defineProps<{ open: boolean }>()
const emit = defineEmits<{
  cancel: []
  granted: []
}>()

const loading = ref(false)
const error = ref('')

async function accept() {
  loading.value = true
  error.value = ''
  emit('granted')
}

// Reset state when modal opens
defineExpose({ reset() { loading.value = false; error.value = '' } })
</script>

<style scoped>
.perm-overlay {
  position: fixed;
  inset: 0;
  background: rgba(0, 0, 0, 0.45);
  display: flex;
  align-items: center;
  justify-content: center;
  z-index: 1000;
  padding: 16px;
}

.perm-modal {
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: 14px;
  width: 100%;
  max-width: 540px;
  max-height: 90vh;
  display: flex;
  flex-direction: column;
  overflow: hidden;
  box-shadow: 0 16px 48px rgba(15,23,42,.18);
}

.perm-header {
  display: flex;
  align-items: flex-start;
  gap: 14px;
  padding: 22px 22px 18px;
  border-bottom: 1px solid var(--border);
  flex-shrink: 0;
}

.perm-icon {
  font-size: 28px;
  line-height: 1;
  margin-top: 2px;
}

.perm-title {
  font-size: 16px;
  font-weight: 700;
  color: var(--ink);
  margin-bottom: 4px;
}

.perm-subtitle {
  font-size: 13px;
  color: var(--muted);
  line-height: 1.5;
}

.perm-list {
  overflow-y: auto;
  padding: 14px 22px;
  display: flex;
  flex-direction: column;
  gap: 10px;
  flex: 1;
}

.perm-item {
  display: flex;
  gap: 12px;
  background: var(--surface-2);
  border-radius: 10px;
  padding: 14px;
  border: 1px solid var(--border);
}

.perm-item-info {
  border-color: rgba(34, 197, 94, .45);
  background: rgba(16, 185, 129, .14);
}

.perm-item-info .perm-item-title {
  color: var(--ink);
}

.perm-item-info .perm-item-desc {
  color: var(--ink-2);
}

.perm-item-info .perm-item-revert {
  color: #16a34a;
  font-weight: 600;
}

.perm-item-info code {
  background: rgba(2, 6, 23, .20);
  color: var(--ink);
}

.perm-item-icon {
  font-size: 18px;
  line-height: 1;
  flex-shrink: 0;
  margin-top: 1px;
}

.perm-item-body {
  display: flex;
  flex-direction: column;
  gap: 3px;
  flex: 1;
  min-width: 0;
}

.perm-item-title {
  font-size: 13px;
  font-weight: 600;
  color: var(--ink-2);
}

.perm-item-desc {
  font-size: 12px;
  color: var(--muted);
  line-height: 1.5;
}

.perm-item-revert {
  font-size: 11px;
  color: var(--midori-600);
  margin-top: 2px;
}

.perm-footer {
  padding: 16px 22px;
  border-top: 1px solid var(--border);
  display: flex;
  flex-direction: column;
  gap: 10px;
  flex-shrink: 0;
}

.perm-actions {
  display: flex;
  gap: 10px;
  justify-content: flex-end;
}

.perm-error {
  font-size: 13px;
  color: var(--danger);
  text-align: right;
}

.spinner {
  display: inline-block;
  width: 13px;
  height: 13px;
  border: 2px solid rgba(22,163,74,0.3);
  border-top-color: white;
  border-radius: 50%;
  animation: spin 0.6s linear infinite;
  margin-right: 6px;
  vertical-align: middle;
}
@keyframes spin { to { transform: rotate(360deg); } }

code {
  font-family: 'SF Mono', 'Fira Code', monospace;
  font-size: 11px;
  background: rgba(0,0,0,0.07);
  padding: 1px 5px;
  border-radius: 3px;
  color: var(--ink-3);
}
</style>
