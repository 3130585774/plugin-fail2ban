<script setup lang="ts">
import { onMounted, ref, watch } from 'vue'
import type { NginxLogViewContext } from '@nginxui/plugin-sdk'
import { formatUnixTime, getRegistry } from '../state'
import type { BanEvent } from '../types'

const props = defineProps<{
  context?: NginxLogViewContext
  path?: string
}>()

const events = ref<BanEvent[]>([])
const loading = ref(false)

async function loadLogEvents() {
  const logPath = props.context?.path ?? props.path ?? ''
  if (!logPath) return
  loading.value = true
  try {
    const res = await getRegistry().http.get<{ items: BanEvent[] }>('/events/history', {
      params: { log_path: logPath, limit: 50 },
    })
    events.value = res.data.items ?? []
  } finally {
    loading.value = false
  }
}

watch(() => props.context?.path ?? props.path, () => {
  void loadLogEvents()
})

onMounted(() => {
  void loadLogEvents()
})
</script>

<template>
  <div class="f2b-slot-view">
    <div class="f2b-slot-head">
      <strong>Fail2ban Threat Analysis</strong>
      <code class="f2b-path">{{ props.context?.path ?? props.path }}</code>
    </div>
    <p v-if="!loading && events.length === 0" class="f2b-empty">
      No Fail2ban actions recorded for this access log.
    </p>
    <table v-else class="f2b-table">
      <thead>
        <tr>
          <th>Time</th>
          <th>Action</th>
          <th>IP</th>
          <th>Jail</th>
          <th>Reason</th>
        </tr>
      </thead>
      <tbody>
        <tr v-for="ev in events" :key="ev.id">
          <td>{{ formatUnixTime(ev.created_at) }}</td>
          <td>{{ ev.action }}</td>
          <td class="f2b-mono">{{ ev.ip }}</td>
          <td>{{ ev.jail }}</td>
          <td>{{ ev.reason }}</td>
        </tr>
      </tbody>
    </table>
  </div>
</template>

<style scoped>
.f2b-slot-view {
  padding: 12px;
  color: var(--ant-color-text, #1f2937);
}
.f2b-slot-head {
  display: flex;
  align-items: center;
  gap: 10px;
  margin-bottom: 10px;
}
.f2b-path {
  font-size: 12px;
  color: var(--ant-color-text-secondary, #6b7280);
}
.f2b-table {
  width: 100%;
  border-collapse: collapse;
  font-size: 13px;
}
.f2b-table th,
.f2b-table td {
  text-align: left;
  padding: 8px;
  border-bottom: 1px solid var(--ant-color-border-secondary, #f0f0f0);
}
.f2b-mono {
  font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
}
.f2b-empty {
  color: var(--ant-color-text-tertiary, #9ca3af);
  font-size: 13px;
}
</style>
