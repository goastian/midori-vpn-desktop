<template>
  <div class="empty-state" :class="{ 'empty-state--compact': compact }" role="status">
    <div class="empty-state-title">{{ title }}</div>
    <div v-if="detail" class="empty-state-detail">{{ detail }}</div>
  </div>
</template>

<script setup lang="ts">
defineProps<{
  title: string
  detail?: string
  compact?: boolean
}>()
</script>

<style scoped>
.empty-state {
  padding: 16px;
  border: 1px dashed var(--border-2);
  border-radius: 10px;
  background: rgba(15, 23, 42, 0.46);
  text-align: center;
}
.empty-state--compact { padding: 11px 12px; }
.empty-state-title { color: var(--ink-2); font-size: 13px; font-weight: 650; }
.empty-state-detail { margin-top: 4px; color: var(--muted); font-size: 11.5px; line-height: 1.45; }
</style>
