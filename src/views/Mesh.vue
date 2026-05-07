<template>
  <div>
    <!-- Locked banner -->
    <div v-if="featuresLocked" class="card locked-card">
      <div class="locked-text">
        {{ t('mesh.locked') }}
      </div>
    </div>

    <!-- Mesh toggle -->
    <div class="card">
      <div class="row">
        <div>
          <div style="font-size:15px;font-weight:600;">Mesh Network</div>
          <div class="label" style="margin-top:4px;">
            {{ mesh.enabled ? `IP: ${mesh.meshIp}` : t('mesh.joinHint') }}
          </div>
        </div>
        <button
          class="toggle"
          :class="{ on: mesh.enabled }"
          :disabled="isTransitioning || featuresLocked"
          @click="toggleMesh"
        ></button>
      </div>
      <div v-if="mesh.meshState === 'enabling'" class="mesh-state-hint">{{ t('mesh.enabling') }}</div>
      <div v-else-if="mesh.meshState === 'disabling'" class="mesh-state-hint">{{ t('mesh.disabling') }}</div>
      <div v-if="mesh.error" class="error">{{ mesh.error }}</div>
    </div>

    <!-- Peers list -->
    <div class="card" v-if="mesh.enabled">
      <div class="section-title" style="display:flex;justify-content:space-between;align-items:center;">
        <span>{{ t('mesh.peers') }}</span>
        <button class="btn-refresh" @click="mesh.fetchExitNodes()" :title="t('mesh.refresh')">↻</button>
      </div>
      <div v-if="mesh.exitNodes.length === 0" style="color:#888;font-size:13px;">
        {{ t('mesh.noPeers') }}
      </div>
      <div
        v-for="n in mesh.exitNodes"
        :key="n.mesh_ip"
        style="display:flex;justify-content:space-between;align-items:center;padding:6px 0;border-bottom:1px solid var(--border, #2a2a2a);"
      >
        <span style="font-size:13px;font-weight:500;">{{ n.mesh_ip }}</span>
        <span class="label" style="font-size:11px;">port {{ n.proxy_port }}</span>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { computed, onMounted, watch } from 'vue'
import { useI18n } from 'vue-i18n'
import { useMeshStore } from '../stores/mesh'
import { useCaps } from '../composables/useCaps'

const mesh = useMeshStore()
const { t } = useI18n()
const { featuresLocked } = useCaps()

const isTransitioning = computed(
  () => mesh.meshState === 'enabling' || mesh.meshState === 'disabling'
)

onMounted(async () => {
  if (mesh.enabled) await mesh.fetchExitNodes()
})

watch(() => mesh.enabled, async (v) => {
  if (v) await mesh.fetchExitNodes()
})

async function toggleMesh() {
  if (isTransitioning.value) return
  if (mesh.enabled) await mesh.disable()
  else await mesh.enable()
}
</script>

<style scoped>
.locked-card {
  border-color: rgba(74, 222, 128, .24);
  background: rgba(34, 197, 94, .08);
}
.locked-text {
  font-size: 13px;
  color: var(--midori-200);
  text-align: center;
  padding: 4px 0;
}
.mesh-state-hint {
  font-size: 12px;
  color: var(--muted-2);
  margin-top: 4px;
}
.btn-refresh {
  background: none;
  border: none;
  color: var(--muted-2);
  font-size: 16px;
  cursor: pointer;
  padding: 2px 4px;
  line-height: 1;
}
.btn-refresh:hover { color: var(--ink); }
</style>
