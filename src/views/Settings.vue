<template>
  <div>
    <div class="card">
      <div class="section-title">Auto-start</div>
      <div class="row">
        <div>
          <div style="font-size:13px;">Launch MidoriVPN at login</div>
          <div class="label" style="margin-top:4px;">Runs in tray when you log in</div>
        </div>
        <button class="toggle" :class="{ on: autostart }" @click="toggleAutostart"></button>
      </div>
    </div>

    <div class="card">
      <div class="section-title">Agent</div>
      <div class="row" style="margin-bottom:12px;">
        <div class="label">Local port</div>
        <div class="value">7071</div>
      </div>
      <div class="row">
        <div class="label">Proxy port</div>
        <div class="value">8888</div>
      </div>
    </div>

    <div class="card">
      <div class="section-title">About</div>
      <div class="row">
        <div class="label">Version</div>
        <div class="value">1.0.0</div>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted } from 'vue'
import { isEnabled, enable, disable } from '@tauri-apps/plugin-autostart'

const autostart = ref(false)

onMounted(async () => {
  autostart.value = await isEnabled()
})

async function toggleAutostart() {
  if (autostart.value) {
    await disable()
    autostart.value = false
  } else {
    await enable()
    autostart.value = true
  }
}
</script>
