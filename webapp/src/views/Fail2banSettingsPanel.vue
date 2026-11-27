<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import { t } from '../i18n'
import { getRegistry, latestStatus, refreshStatus } from '../state'
import ActiveBansTab from './ActiveBansTab.vue'
import JailRulesTab from './JailRulesTab.vue'
import WhitelistGuideTab from './WhitelistGuideTab.vue'

defineProps<{
  settings?: Record<string, unknown>
  save?: (next?: Record<string, unknown>) => Promise<void>
}>()

const activeTab = ref<'bans' | 'jails' | 'whitelist'>('bans')
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
    bannerMsg.value = t('Nginx snippet synchronized.')
    setTimeout(() => (bannerMsg.value = ''), 3000)
  } catch (err) {
    bannerMsg.value = t('Sync failed: {err}', { err: String(err) })
  } finally {
    syncing.value = false
  }
}

onMounted(() => {
  void refreshStatus()
})
</script>

<template>
  <div class="f2b-settings">
    <div class="f2b-top-bar">
      <div class="f2b-metrics-inline">
        <div class="f2b-stat">
          <span class="f2b-stat-label">{{ t('Active Bans') }}</span>
          <strong class="f2b-stat-val">{{ status?.active_bans ?? 0 }}</strong>
        </div>
        <div class="f2b-stat">
          <span class="f2b-stat-label">{{ t('Bans (24h)') }}</span>
          <strong class="f2b-stat-val">{{ status?.bans_24h ?? 0 }}</strong>
        </div>
        <div class="f2b-stat">
          <span class="f2b-stat-label">{{ t('Logs Processed') }}</span>
          <strong class="f2b-stat-val">{{ status?.engine?.logs_processed ?? 0 }}</strong>
        </div>
      </div>

      <div class="f2b-top-actions">
        <button class="f2b-btn" :disabled="syncing" @click="syncNow">
          {{ syncing ? t('Syncing...') : t('Sync Snippet Now') }}
        </button>
        <button
          class="f2b-btn"
          :class="enabled ? 'f2b-btn-primary' : 'f2b-btn-warn'"
          :disabled="toggling"
          @click="toggleEnabled"
        >
          {{ enabled ? t('Protection Enabled') : t('Protection Paused') }}
        </button>
      </div>
    </div>

    <div v-if="bannerMsg" class="f2b-alert">{{ bannerMsg }}</div>
    <div v-if="status?.enforcer?.last_error" class="f2b-alert f2b-alert-error">
      {{ t('Enforcer Error: {err}', { err: status.enforcer.last_error }) }}
    </div>

    <nav class="f2b-tabs">
      <button :class="{ active: activeTab === 'bans' }" @click="activeTab = 'bans'">
        {{ t('Ban Management') }}
      </button>
      <button :class="{ active: activeTab === 'jails' }" @click="activeTab = 'jails'">
        {{ t('Jail Rules') }}
      </button>
      <button :class="{ active: activeTab === 'whitelist' }" @click="activeTab = 'whitelist'">
        {{ t('Whitelist & Setup') }}
      </button>
    </nav>

    <div class="f2b-panel-body">
      <ActiveBansTab v-if="activeTab === 'bans'" />
      <JailRulesTab v-else-if="activeTab === 'jails'" />
      <WhitelistGuideTab v-else />
    </div>
  </div>
</template>

<style scoped>
.f2b-settings {
  color: var(--ant-color-text, #1f2937);
}
.f2b-top-bar {
  display: flex;
  flex-wrap: wrap;
  justify-content: space-between;
  align-items: center;
  gap: 12px;
  padding: 12px 14px;
  margin-bottom: 14px;
  border-radius: var(--ant-border-radius-lg, 8px);
  background: var(--ant-color-fill-quaternary, rgba(0, 0, 0, 0.02));
  border: 1px solid var(--ant-color-border-secondary, #f0f0f0);
}
.f2b-metrics-inline {
  display: flex;
  flex-wrap: wrap;
  gap: 18px;
}
.f2b-stat {
  display: flex;
  flex-direction: column;
  gap: 2px;
}
.f2b-stat-label {
  font-size: 12px;
  color: var(--ant-color-text-secondary, #6b7280);
}
.f2b-stat-val {
  font-size: 18px;
  font-weight: 600;
  font-variant-numeric: tabular-nums;
  color: var(--ant-color-text-heading, var(--ant-color-text, #111827));
}
.f2b-top-actions {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  gap: 8px;
}
.f2b-tabs {
  display: flex;
  gap: 4px;
  border-bottom: 1px solid var(--ant-color-border-secondary, #f0f0f0);
  margin-bottom: 14px;
}
.f2b-tabs button {
  padding: 8px 14px;
  background: transparent;
  border: none;
  border-bottom: 2px solid transparent;
  cursor: pointer;
  font-size: 14px;
  color: var(--ant-color-text-secondary, #6b7280);
  transition: color 0.15s ease, border-color 0.15s ease;
}
.f2b-tabs button:hover {
  color: var(--ant-color-text, #1f2937);
}
.f2b-tabs button.active {
  color: var(--ant-color-primary, #1677ff);
  border-bottom-color: var(--ant-color-primary, #1677ff);
  font-weight: 600;
}
.f2b-panel-body {
  min-height: 200px;
}
.f2b-btn {
  padding: 5px 12px;
  border-radius: var(--ant-border-radius, 6px);
  border: 1px solid var(--ant-color-border, #d9d9d9);
  background: var(--ant-color-bg-container, #ffffff);
  color: var(--ant-color-text, #1f2937);
  cursor: pointer;
  font-size: 13px;
  transition: opacity 0.15s ease;
}
.f2b-btn:hover:not(:disabled) {
  border-color: var(--ant-color-primary, #1677ff);
  color: var(--ant-color-primary, #1677ff);
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
.f2b-btn-primary:hover:not(:disabled) {
  color: #ffffff;
  opacity: 0.9;
}
.f2b-btn-warn {
  background: var(--ant-color-warning, #faad14);
  border-color: var(--ant-color-warning, #faad14);
  color: #ffffff;
}
.f2b-btn-warn:hover:not(:disabled) {
  color: #ffffff;
  opacity: 0.9;
}
.f2b-alert {
  padding: 8px 12px;
  margin-bottom: 12px;
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
