<script setup lang="ts">
import { computed } from 'vue'
import type { NginxLogRow, NginxLogRowContext } from '@nginxui/plugin-sdk'
import { logPathStatsMap } from '../state'

const props = defineProps<{
  context?: NginxLogRowContext
  row?: NginxLogRow
}>()

const stat = computed(() => {
  const logPath = props.context?.row?.path ?? props.row?.path ?? ''
  return logPath ? logPathStatsMap.value[logPath] : undefined
})
</script>

<template>
  <span class="f2b-col-badge" :class="{ hot: (stat?.recent_hits ?? 0) > 0 }">
    {{ stat?.recent_hits ?? 0 }}
  </span>
</template>

<style scoped>
.f2b-col-badge {
  display: inline-block;
  min-width: 24px;
  text-align: center;
  padding: 1px 6px;
  border-radius: 999px;
  font-size: 12px;
  font-variant-numeric: tabular-nums;
  background: var(--ant-color-fill-tertiary, #f5f5f5);
  color: var(--ant-color-text-secondary, #6b7280);
}
.f2b-col-badge.hot {
  background: var(--ant-color-error-bg, #fff2f0);
  color: var(--ant-color-error, #ff4d4f);
  font-weight: 600;
}
</style>
