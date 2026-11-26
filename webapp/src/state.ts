import { ref } from 'vue'
import type { PluginRegistry } from '@nginxui/plugin-sdk'
import type { BanEvent, LogPathStat, StatusResponse } from './types'

let activeRegistry: PluginRegistry | null = null
let activeWS: WebSocket | null = null
let reconnectTimer: ReturnType<typeof setTimeout> | null = null
let statsTimer: ReturnType<typeof setInterval> | null = null

export const liveEvents = ref<BanEvent[]>([])
export const wsConnected = ref(false)
export const logPathStatsMap = ref<Record<string, LogPathStat>>({})
export const latestStatus = ref<StatusResponse | null>(null)

export function setRegistry(reg: PluginRegistry | null) {
  activeRegistry = reg
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
  }, 15000)
  connectLiveWS()
}

export function connectLiveWS() {
  if (!activeRegistry?.wsUrl) return
  if (activeWS && (activeWS.readyState === WebSocket.OPEN || activeWS.readyState === WebSocket.CONNECTING)) {
    return
  }
  try {
    const url = activeRegistry.wsUrl('/events')
    const ws = new WebSocket(url)
    activeWS = ws

    ws.onopen = () => {
      wsConnected.value = true
    }
    ws.onmessage = (evt) => {
      try {
        const parsed = JSON.parse(String(evt.data)) as { type?: string; data?: BanEvent }
        if (parsed.type === 'ban_event' && parsed.data) {
          liveEvents.value = [parsed.data, ...liveEvents.value].slice(0, 200)
          void refreshStatus()
        }
      } catch {
        // Ignore malformed frames.
      }
    }
    ws.onclose = () => {
      wsConnected.value = false
      activeWS = null
      if (activeRegistry && !reconnectTimer) {
        reconnectTimer = setTimeout(() => {
          reconnectTimer = null
          connectLiveWS()
        }, 5000)
      }
    }
    ws.onerror = () => {
      ws.close()
    }
  } catch {
    wsConnected.value = false
  }
}

export function stopBackgroundSync() {
  if (reconnectTimer) {
    clearTimeout(reconnectTimer)
    reconnectTimer = null
  }
  if (statsTimer) {
    clearInterval(statsTimer)
    statsTimer = null
  }
  if (activeWS) {
    activeWS.onclose = null
    activeWS.close()
    activeWS = null
  }
  wsConnected.value = false
}

export function formatUnixTime(ts: number): string {
  if (!ts) return '—'
  return new Date(ts * 1000).toLocaleString()
}

export function formatDuration(sec: number): string {
  if (!sec || sec <= 0) return 'Permanent'
  if (sec < 60) return `${sec}s`
  if (sec < 3600) return `${Math.round(sec / 60)}m`
  if (sec < 86400) return `${(sec / 3600).toFixed(sec % 3600 === 0 ? 0 : 1)}h`
  return `${(sec / 86400).toFixed(sec % 86400 === 0 ? 0 : 1)}d`
}
