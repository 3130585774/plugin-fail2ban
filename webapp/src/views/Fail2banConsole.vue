<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import { getRegistry, latestStatus, refreshStatus, wsConnected } from '../state'
import ActiveBansTab from './ActiveBansTab.vue'
import JailRulesTab from './JailRulesTab.vue'
import WhitelistGuideTab from './WhitelistGuideTab.vue'
import LiveEventsTab from './LiveEventsTab.vue'

const activeTab = ref<'bans' | 'jails' | 'whitelist' | 'live'>('bans')
const syncing = ref(false)
const toggling = ref(false)
const bannerMsg = ref('')

const status = computed(() => latestStatus.value)
const enabled = computed(() => status.value?.config?.enabled ?? true)

async function toggleEnabled() {
  if (!status.value) return
  toggling.value = true
  try {
    const nextCfg = { ...status.value.config, enabled: !enabled.value }
    await getRegistry().http.put('/config', nextCfg)
    await refreshStatus()
  } finally {
    toggling.value = false
  }
}

async function syncNow() {
  syncing.value = true
  bannerMsg.value = ''
  try {
    await getRegistry().http.post('/sync')
    await refreshStatus()
    bannerMsg.value = 'Nginx snippet synchronized.'
    setTimeout(() => (bannerMsg.value = ''), 3000)
  } catch (err) {
    bannerMsg.value = `Sync failed: ${String(err)}`
  } finally {
    syncing.value = false
  }
}

onMounted(() => {
  void refreshStatus()
})
</script>

<template>
  <div class="f2b-console">
    <header class="f2b-header">
      <div>
        <h2 class="f2b-title">Fail2ban Guard</h2>
        <p class="f2b-subtitle">
          Real-time gRPC access log intrusion detection &amp; debounced Nginx snippet enforcer
        </p>
      </div>
      <div class="f2b-header-actions">
        <span class="f2b-ws-badge" :class="{ online: wsConnected }">
          <span class="f2b-dot" />
          {{ wsConnected ? 'Live Stream' : 'Polling' }}
        </span>
        <button class="f2b-btn" :disabled="syncing" @click="syncNow">
          {{ syncing ? 'Syncing...' : 'Sync Snippet Now' }}
        </button>
        <button
          class="f2b-btn"
          :class="enabled ? 'f2b-btn-primary' : 'f2b-btn-warn'"
          :disabled="toggling"
          @click="toggleEnabled"
        >
          {{ enabled ? 'Protection Enabled' : 'Protection Paused' }}
        </button>
      </div>
    </header>

    <div v-if="bannerMsg" class="f2b-alert">{{ bannerMsg }}</div>
    <div v-if="status?.enforcer?.last_error" class="f2b-alert f2b-alert-error">
      Enforcer Error: {{ status.enforcer.last_error }}
    </div>

    <section class="f2b-metrics">
      <div class="f2b-metric-card">
        <div class="f2b-metric-label">Active Bans</div>
        <div class="f2b-metric-val">{{ status?.active_bans ?? 0 }}</div>
      </div>
      <div class="f2b-metric-card">
        <div class="f2b-metric-label">Bans (24h)</div>
        <div class="f2b-metric-val">{{ status?.bans_24h ?? 0 }}</div>
      </div>
      <div class="f2b-metric-card">
        <div class="f2b-metric-label">Tracked IPs / Cap</div>
        <div class="f2b-metric-val">
          {{ status?.engine?.tracked_entries ?? 0 }}
          <span class="f2b-metric-sub">/ {{ status?.engine?.max_tracked_ips ?? 50000 }}</span>
        </div>
      </div>
      <div class="f2b-metric-card">
        <div class="f2b-metric-label">Logs Processed</div>
        <div class="f2b-metric-val">{{ status?.engine?.logs_processed ?? 0 }}</div>
      </div>
    </section>

    <nav class="f2b-tabs">
      <button :class="{ active: activeTab === 'bans' }" @click="activeTab = 'bans'">
        Active Bans
      </button>
      <button :class="{ active: activeTab === 'jails' }" @click="activeTab = 'jails'">
        Jail Rules
      </button>
      <button :class="{ active: activeTab === 'whitelist' }" @click="activeTab = 'whitelist'">
        Whitelist &amp; Setup
      </button>
      <button :class="{ active: activeTab === 'live' }" @click="activeTab = 'live'">
        Live Events
      </button>
    </nav>

    <main class="f2b-panel">
      <ActiveBansTab v-if="activeTab === 'bans'" />
      <JailRulesTab v-else-if="activeTab === 'jails'" />
      <WhitelistGuideTab v-else-if="activeTab === 'whitelist'" />
      <LiveEventsTab v-else />
    </main>
  </div>
</template>

<style scoped>
.f2b-console {
  padding: 20px;
  color: var(--ant-color-text, #1f2937);
  background: var(--ant-color-bg-layout, transparent);
}
.f2b-header {
  display: flex;
  flex-wrap: wrap;
  justify-content: space-between;
  align-items: center;
  gap: 12px;
  margin-bottom: 18px;
}
.f2b-title {
  margin: 0;
  font-size: 20px;
  font-weight: 600;
  color: var(--ant-color-text-heading, var(--ant-color-text, #111827));
}
.f2b-subtitle {
  margin: 4px 0 0;
  font-size: 13px;
  color: var(--ant-color-text-secondary, #6b7280);
}
.f2b-header-actions {
  display: flex;
  align-items: center;
  gap: 10px;
}
.f2b-ws-badge {
  display: inline-flex;
  align-items: center;
  gap: 6px;
  font-size: 12px;
  padding: 4px 10px;
  border-radius: 999px;
  border: 1px solid var(--ant-color-border, #d9d9d9);
  color: var(--ant-color-text-secondary, #6b7280);
}
.f2b-ws-badge.online {
  color: var(--ant-color-success, #52c41a);
  border-color: var(--ant-color-success-border, #b7eb8f);
}
.f2b-dot {
  width: 7px;
  height: 7px;
  border-radius: 50%;
  background: currentColor;
}
.f2b-metrics {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(170px, 1fr));
  gap: 12px;
  margin-bottom: 18px;
}
.f2b-metric-card {
  background: var(--ant-color-bg-container, #ffffff);
  border: 1px solid var(--ant-color-border-secondary, #f0f0f0);
  border-radius: var(--ant-border-radius-lg, 8px);
  padding: 14px 16px;
}
.f2b-metric-label {
  font-size: 12px;
  color: var(--ant-color-text-secondary, #6b7280);
  margin-bottom: 6px;
}
.f2b-metric-val {
  font-size: 22px;
  font-weight: 600;
  font-variant-numeric: tabular-nums;
}
.f2b-metric-sub {
  font-size: 13px;
  font-weight: 400;
  color: var(--ant-color-text-tertiary, #9ca3af);
}
.f2b-tabs {
  display: flex;
  gap: 4px;
  border-bottom: 1px solid var(--ant-color-border-secondary, #f0f0f0);
  margin-bottom: 16px;
}
.f2b-tabs button {
  padding: 10px 16px;
  background: transparent;
  border: none;
  border-bottom: 2px solid transparent;
  cursor: pointer;
  font-size: 14px;
  color: var(--ant-color-text-secondary, #6b7280);
}
.f2b-tabs button.active {
  color: var(--ant-color-primary, #1677ff);
  border-bottom-color: var(--ant-color-primary, #1677ff);
  font-weight: 600;
}
.f2b-panel {
  background: var(--ant-color-bg-container, #ffffff);
  border: 1px solid var(--ant-color-border-secondary, #f0f0f0);
  border-radius: var(--ant-border-radius-lg, 8px);
  padding: 16px;
}
.f2b-btn {
  padding: 6px 12px;
  border-radius: var(--ant-border-radius, 6px);
  border: 1px solid var(--ant-color-border, #d9d9d9);
  background: var(--ant-color-bg-container, #ffffff);
  color: var(--ant-color-text, #1f2937);
  cursor: pointer;
  font-size: 13px;
}
.f2b-btn:disabled {
  opacity: 0.6;
  cursor: not-allowed;
}
.f2b-btn-primary {
  background: var(--ant-color-primary, #1677ff);
  border-color: var(--ant-color-primary, #1677ff);
  color: #ffffff;
}
.f2b-btn-warn {
  background: var(--ant-color-warning, #faad14);
  border-color: var(--ant-color-warning, #faad14);
  color: #ffffff;
}
.f2b-alert {
  padding: 10px 14px;
  margin-bottom: 14px;
  border-radius: var(--ant-border-radius, 6px);
  background: var(--ant-color-info-bg, #e6f4ff);
  border: 1px solid var(--ant-color-info-border, #91caff);
  font-size: 13px;
}
.f2b-alert-error {
  background: var(--ant-color-error-bg, #fff2f0);
  border-color: var(--ant-color-error-border, #ffccc7);
  color: var(--ant-color-error, #ff4d4f);
}
</style>
