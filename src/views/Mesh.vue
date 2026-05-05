<template>
  <div>
    <!-- Mesh toggle -->
    <div class="card">
      <div class="row">
        <div>
          <div style="font-size:15px;font-weight:600;">Mesh Network</div>
          <div class="label" style="margin-top:4px;">
            {{ mesh.enabled ? `IP: ${mesh.meshIp}` : 'Join to enable peer routing' }}
          </div>
        </div>
        <button
          class="toggle"
          :class="{ on: mesh.enabled }"
          :disabled="mesh.loading"
          @click="toggleMesh"
        ></button>
      </div>
      <div v-if="mesh.error" class="error">{{ mesh.error }}</div>
    </div>

    <!-- Exit node section -->
    <div class="card" v-if="mesh.enabled">
      <div class="section-title">Exit Node</div>
      <div class="label" style="margin-bottom:8px;">
        Route your traffic through another mesh peer's IP
      </div>

      <div v-if="mesh.exitNodes.length === 0" style="color:#888;font-size:13px;">
        No exit nodes available in your mesh.
      </div>

      <div v-else>
        <select v-model="selectedExitNode" style="margin-bottom:12px;">
          <option value="">— Direct (no exit node) —</option>
          <option v-for="n in mesh.exitNodes" :key="n.user_id" :value="n.user_id">
            {{ n.mesh_ip }} (port {{ n.proxy_port }})
            <span v-if="!n.online"> — offline</span>
          </option>
        </select>

        <div class="row">
          <button class="btn btn-primary" @click="applyExitNode" :disabled="!selectedExitNode">
            Use Exit Node
          </button>
          <button class="btn btn-secondary" @click="clearExitNode" v-if="mesh.exitNodeActive">
            Clear
          </button>
        </div>
      </div>
    </div>

    <!-- This machine as exit node -->
    <div class="card" v-if="mesh.enabled">
      <div class="section-title">Act as Exit Node</div>
      <div class="label" style="margin-bottom:8px;">
        Let mesh peers route through your IP (proxy port {{ mesh.proxyPort || 8888 }})
      </div>
      <div class="row">
        <span style="font-size:13px;color:#888;">
          {{ mesh.exitNodeActive ? 'You are an active exit node' : 'Not acting as exit node' }}
        </span>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted, watch } from 'vue'
import { useMeshStore } from '../stores/mesh'

const mesh = useMeshStore()
const selectedExitNode = ref('')

onMounted(async () => {
  if (mesh.enabled) await mesh.fetchExitNodes()
})

watch(() => mesh.enabled, async (v) => {
  if (v) await mesh.fetchExitNodes()
})

async function toggleMesh() {
  if (mesh.enabled) await mesh.disable()
  else await mesh.enable()
}

async function applyExitNode() {
  if (selectedExitNode.value) await mesh.setExitNode(selectedExitNode.value)
}

async function clearExitNode() {
  await mesh.clearExitNode()
  selectedExitNode.value = ''
}
</script>
