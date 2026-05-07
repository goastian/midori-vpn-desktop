<template>
  <div class="language-select-card" :class="{ 'language-select-card--compact': compact }">
    <div v-if="!compact" class="language-copy">
      <div class="section-title">{{ t('settings.language') }}</div>
      <div class="label language-hint">{{ t('settings.languageHint') }}</div>
    </div>

    <div v-else class="language-copy language-copy--compact">
      <div class="label language-label">{{ t('settings.language') }}</div>
    </div>

    <select
      class="lang-select"
      :value="currentLocale"
      :aria-label="t('settings.language')"
      @change="onLocaleChange"
    >
      <option value="en">English</option>
      <option value="es">Español</option>
      <option value="pt">Português</option>
      <option value="de">Deutsch</option>
      <option value="fr">Français</option>
      <option value="ru">Русский</option>
    </select>
  </div>
</template>

<script setup lang="ts">
import { computed } from 'vue'
import { useI18n } from 'vue-i18n'
import { getLocale, setLocale, type Locale } from '../i18n'

defineProps<{
  compact?: boolean
}>()

const { t } = useI18n()

const currentLocale = computed(() => getLocale())

function onLocaleChange(e: Event) {
  setLocale((e.target as HTMLSelectElement).value as Locale)
}
</script>

<style scoped>
.language-select-card {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 12px;
}

.language-select-card--compact {
  justify-content: flex-end;
}

.language-copy {
  min-width: 0;
}

.language-copy--compact {
  flex-shrink: 0;
}

.language-label,
.language-hint {
  margin-bottom: 0;
}

.lang-select {
  appearance: none;
  -webkit-appearance: none;
  background: var(--surface) url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='12' height='8' viewBox='0 0 12 8'%3E%3Cpath d='M1 1l5 5 5-5' stroke='%236b7280' stroke-width='1.5' fill='none' stroke-linecap='round'/%3E%3C/svg%3E") no-repeat right 10px center;
  color: var(--ink-2);
  border: 1px solid var(--border);
  border-radius: 8px;
  padding: 7px 32px 7px 12px;
  font-size: 13px;
  font-weight: 500;
  cursor: pointer;
  outline: none;
  min-width: 130px;
  transition: border-color .15s;
}

.lang-select:hover {
  border-color: var(--midori-500);
}

.lang-select:focus {
  border-color: var(--midori-500);
  box-shadow: 0 0 0 3px rgba(34,197,94,.14);
}

.lang-select option {
  background: #ffffff;
  color: #111827;
}
</style>
