import { ref } from 'vue'
import type { PluginRegistry } from '@nginxui/plugin-sdk'
import type { LogPathStat, StatusResponse } from './types'

let activeRegistry: PluginRegistry | null = null
let statsTimer: ReturnType<typeof setInterval> | null = null

export const logPathStatsMap = ref<Record<string, LogPathStat>>({})
export const latestStatus = ref<StatusResponse | null>(null)

export function setRegistry(reg: PluginRegistry | null) {
  activeRegistry = reg
}

export function getOptionalRegistry(): PluginRegistry | null {
  return activeRegistry
}

export function getRegistry(): PluginRegistry {
  if (!activeRegistry) {
    throw new Error('Fail2ban plugin registry is not initialized')
  }
  return activeRegistry
}

export async function refreshStatus(): Promise<StatusResponse | null> {
  if (!activeRegistry) return null
  try {
    const res = await activeRegistry.http.get<StatusResponse>('/status')
    latestStatus.value = res.data
    const map: Record<string, LogPathStat> = {}
    for (const item of res.data.log_path_stats ?? []) {
      map[item.log_path] = item
    }
    logPathStatsMap.value = map
    return res.data
  } catch {
    return null
  }
}

export function startBackgroundSync() {
  stopBackgroundSync()
  void refreshStatus()
  statsTimer = setInterval(() => {
    void refreshStatus()
  }, 30000)
}

export function stopBackgroundSync() {
  if (statsTimer) {
    clearInterval(statsTimer)
    statsTimer = null
  }
}

export function formatUnixTime(ts: number): string {
  if (!ts) return '—'
  return new Date(ts * 1000).toLocaleString()
}
