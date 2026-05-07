<template>
  <button class="btn btn-quit" :disabled="confirming" @click="handleQuit">
    {{ confirming ? t('quit.loading') : t('quit.label') }}
  </button>
</template>

<script setup lang="ts">
import { ref } from 'vue'
import { useI18n } from 'vue-i18n'
import { invoke } from '@tauri-apps/api/core'

const { t } = useI18n()
const confirming = ref(false)

async function handleQuit() {
  if (confirming.value) return
  const ok = window.confirm(
    `¿Salir de MidoriVPN?\n\n${t('quit.confirmBody')}`
  )
  if (!ok) return
  confirming.value = true
  try {
    await invoke('quit_app')
  } catch {
    // quit_app closes the window before we can read the response; ignore.
  }
}
</script>

<style scoped>
.btn-quit {
  width: 100%;
  padding: 10px 16px;
  border-radius: 6px;
  border: 1px solid #e53e3e;
  background: transparent;
  color: #fc8181;
  font-size: 14px;
  font-weight: 500;
  cursor: pointer;
  transition: background 0.15s, color 0.15s;
}
.btn-quit:hover:not(:disabled) {
  background: rgba(229, 62, 62, 0.12);
  color: #fed7d7;
}
.btn-quit:disabled {
  opacity: 0.5;
  cursor: not-allowed;
}
</style>
