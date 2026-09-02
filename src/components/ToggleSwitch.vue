<template>
  <button
    type="button"
    class="toggle"
    :class="{ on: checked }"
    role="switch"
    :aria-checked="checked"
    :aria-label="label"
    :disabled="disabled"
    @click="emit('change', !checked)"
  />
</template>

<script setup lang="ts">
defineProps<{
  checked: boolean
  label: string
  disabled?: boolean
}>()

const emit = defineEmits<{
  change: [checked: boolean]
}>()
</script>
