<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import { formatDuration, formatUnixTime, getRegistry, liveEvents, wsConnected } from '../state'
import type { BanEvent } from '../types'

const history = ref<BanEvent[]>([])
const loading = ref(false)

const mergedEvents = computed(() => {
  const seen = new Set<number>()
  const list: BanEvent[] = []
  for (const ev of [...liveEvents.value, ...history.value]) {
    if (ev.id && seen.has(ev.id)) continue
    if (ev.id) seen.add(ev.id)
    list.push(ev)
  }
  return list.slice(0, 200)
})

async function loadHistory() {
  loading.value = true
  try {
    const res = await getRegistry().http.get<{ items: BanEvent[] }>('/events/history', {
      params: { limit: 100 },
    })
    history.value = res.data.items ?? []
  } finally {
    loading.value = false
  }
}

onMounted(() => {
  void loadHistory()
})
</script>

<template>
  <div>
    <div class="f2b-live-head">
      <span class="f2b-hint">
        WebSocket: <strong>{{ wsConnected ? 'Connected' : 'Disconnected' }}</strong>
      </span>
      <button class="f2b-btn" :disabled="loading" @click="loadHistory">Reload History</button>
    </div>

    <div class="f2b-table-wrap">
      <table class="f2b-table">
        <thead>
          <tr>
            <th>Time</th>
            <th>Action</th>
            <th>IP</th>
            <th>Jail</th>
            <th>Duration</th>
            <th>Reason</th>
            <th>Actor</th>
          </tr>
        </thead>
        <tbody>
          <tr v-if="mergedEvents.length === 0">
            <td colspan="7" class="f2b-empty">No enforcement events recorded yet.</td>
          </tr>
          <tr v-for="ev in mergedEvents" :key="`${ev.id}-${ev.created_at}-${ev.ip}`">
            <td>{{ formatUnixTime(ev.created_at) }}</td>
            <td>
              <span class="f2b-badge" :class="`act-${ev.action}`">{{ ev.action }}</span>
            </td>
            <td class="f2b-mono">{{ ev.ip }}</td>
            <td>{{ ev.jail }}</td>
            <td>{{ ev.action === 'ban' || ev.action === 'extend' ? formatDuration(ev.duration_sec) : '—' }}</td>
            <td>{{ ev.reason }}</td>
            <td>{{ ev.actor }}</td>
          </tr>
        </tbody>
      </table>
    </div>
  </div>
</template>

<style scoped>
.f2b-live-head {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 12px;
}
.f2b-hint {
  font-size: 13px;
  color: var(--ant-color-text-secondary, #6b7280);
}
.f2b-btn {
  padding: 5px 12px;
  border-radius: var(--ant-border-radius, 6px);
  border: 1px solid var(--ant-color-border, #d9d9d9);
  background: var(--ant-color-bg-container, #ffffff);
  color: var(--ant-color-text, #1f2937);
  cursor: pointer;
  font-size: 13px;
}
.f2b-table-wrap {
  overflow-x: auto;
}
.f2b-table {
  width: 100%;
  border-collapse: collapse;
  font-size: 13px;
}
.f2b-table th,
.f2b-table td {
  text-align: left;
  padding: 9px 8px;
  border-bottom: 1px solid var(--ant-color-border-secondary, #f0f0f0);
}
.f2b-mono {
  font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
}
.f2b-badge {
  display: inline-block;
  padding: 2px 8px;
  border-radius: 4px;
  font-size: 12px;
  background: var(--ant-color-fill-tertiary, #f5f5f5);
}
.f2b-badge.act-ban {
  color: var(--ant-color-error, #ff4d4f);
  background: var(--ant-color-error-bg, #fff2f0);
}
.f2b-badge.act-unban,
.f2b-badge.act-expire {
  color: var(--ant-color-success, #52c41a);
  background: var(--ant-color-success-bg, #f6ffed);
}
.f2b-empty {
  text-align: center;
  color: var(--ant-color-text-tertiary, #9ca3af);
  padding: 20px 0;
}
</style>
