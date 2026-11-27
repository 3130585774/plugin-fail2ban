<script setup lang="ts">
import { onMounted, ref } from 'vue'
import { jailName, t } from '../i18n'
import { formatUnixTime, getRegistry, refreshStatus } from '../state'
import type { BanRecord } from '../types'

const bans = ref<BanRecord[]>([])
const total = ref(0)
const loading = ref(false)
const search = ref('')
const jailFilter = ref('')

const manualIP = ref('')
const manualReason = ref('')
const manualDuration = ref(3600)
const errorMsg = ref('')

async function loadBans() {
  loading.value = true
  errorMsg.value = ''
  try {
    const res = await getRegistry().http.get<{ items: BanRecord[]; total: number }>('/bans', {
      params: {
        search: search.value || undefined,
        jail: jailFilter.value || undefined,
        limit: 100,
      },
    })
    bans.value = res.data.items ?? []
    total.value = res.data.total ?? 0
  } catch (err) {
    errorMsg.value = String(err)
  } finally {
    loading.value = false
  }
}

async function addManualBan() {
  if (!manualIP.value.trim()) return
  errorMsg.value = ''
  try {
    await getRegistry().http.post('/bans', {
      ip: manualIP.value.trim(),
      reason: manualReason.value.trim() || t('Manual ban'),
      duration_sec: Number(manualDuration.value) || 0,
    })
    manualIP.value = ''
    manualReason.value = ''
    await Promise.all([loadBans(), refreshStatus()])
  } catch (err) {
    errorMsg.value = String(err)
  }
}

async function unban(ip: string) {
  await getRegistry().http.delete(`/bans/${encodeURIComponent(ip)}`)
  await Promise.all([loadBans(), refreshStatus()])
}

async function extendBan(ip: string) {
  await getRegistry().http.patch(`/bans/${encodeURIComponent(ip)}`, { extra_sec: 86400 })
  await loadBans()
}

async function whitelistIP(ip: string) {
  await getRegistry().http.post('/whitelist', { cidr: ip, note: t('Added from Active Bans') })
  await Promise.all([loadBans(), refreshStatus()])
}

onMounted(() => {
  void loadBans()
})
</script>

<template>
  <div class="f2b-bans-wrap">
    <!-- Compact 2-row Manual Ban Card -->
    <div class="f2b-manual-card">
      <div class="f2b-form-row">
        <input
          v-model="manualIP"
          class="f2b-input f2b-grow"
          :placeholder="t('IP to ban (e.g. 203.0.113.10)')"
          @keyup.enter="addManualBan"
        />
        <select v-model.number="manualDuration" class="f2b-input f2b-select-sm">
          <option :value="1800">{{ t('30 minutes') }}</option>
          <option :value="3600">{{ t('1 hour') }}</option>
          <option :value="86400">{{ t('24 hours') }}</option>
          <option :value="604800">{{ t('7 days') }}</option>
          <option :value="0">{{ t('Permanent') }}</option>
        </select>
        <button class="f2b-btn f2b-btn-danger" @click="addManualBan">{{ t('Manual Ban') }}</button>
      </div>
      <input
        v-model="manualReason"
        class="f2b-input f2b-full"
        :placeholder="t('Reason')"
        @keyup.enter="addManualBan"
      />
    </div>

    <!-- Search & Filter Bar -->
    <div class="f2b-filter-row">
      <input
        v-model="search"
        class="f2b-input f2b-grow"
        :placeholder="t('Search IP, reason, or log path...')"
        @keyup.enter="loadBans"
      />
      <select v-model="jailFilter" class="f2b-input f2b-select-md" @change="loadBans">
        <option value="">{{ t('All Jails') }}</option>
        <option value="http-404-scan">{{ jailName('http-404-scan') }}</option>
        <option value="http-sensitive-probe">{{ jailName('http-sensitive-probe') }}</option>
        <option value="http-auth-bruteforce">{{ jailName('http-auth-bruteforce') }}</option>
        <option value="http-bad-bot">{{ jailName('http-bad-bot') }}</option>
        <option value="nginxui-login-guard">{{ jailName('nginxui-login-guard') }}</option>
        <option value="manual">{{ t('Manual') }}</option>
      </select>
      <button class="f2b-btn" @click="loadBans">{{ t('Refresh ({count})', { count: total }) }}</button>
    </div>

    <p v-if="errorMsg" class="f2b-err">{{ errorMsg }}</p>

    <!-- Narrow-Drawer Friendly Card List -->
    <div v-if="!loading && bans.length === 0" class="f2b-empty-box">
      {{ t('No active bans.') }}
    </div>

    <div v-else class="f2b-ban-list">
      <div v-for="b in bans" :key="b.ip" class="f2b-ban-item">
        <div class="f2b-ban-head">
          <div class="f2b-ban-title">
            <span class="f2b-ip">{{ b.ip }}</span>
            <span class="f2b-tag" :title="b.jail">
              {{ b.jail === 'manual' ? t('Manual') : jailName(b.jail) }}
            </span>
          </div>
          <div class="f2b-actions">
            <button class="f2b-link" @click="unban(b.ip)">{{ t('Unban') }}</button>
            <button class="f2b-link" @click="extendBan(b.ip)">{{ t('+24h') }}</button>
            <button class="f2b-link" @click="whitelistIP(b.ip)">{{ t('Whitelist') }}</button>
          </div>
        </div>

        <div v-if="b.reason" class="f2b-ban-reason">{{ b.reason }}</div>

        <div class="f2b-ban-meta">
          <span>{{ t('Hits / Offenses') }}: <strong class="f2b-mono">{{ b.hit_count }} / #{{ b.offense_count }}</strong></span>
          <span class="f2b-meta-sep">·</span>
          <span>{{ t('Expires At') }}: {{ b.expires_at ? formatUnixTime(b.expires_at) : t('Permanent') }}</span>
        </div>
      </div>
    </div>
  </div>
</template>

<style scoped>
.f2b-bans-wrap {
  display: flex;
  flex-direction: column;
  gap: 10px;
}
.f2b-manual-card {
  display: flex;
  flex-direction: column;
  gap: 8px;
  padding: 10px 12px;
  border-radius: var(--ant-border-radius-lg, 8px);
  background: var(--ant-color-fill-quaternary, rgba(255, 255, 255, 0.02));
  border: 1px solid var(--ant-color-border-secondary, #f0f0f0);
}
.f2b-form-row,
.f2b-filter-row {
  display: flex;
  flex-wrap: wrap;
  gap: 8px;
  align-items: center;
}
.f2b-grow {
  flex: 1 1 150px;
  min-width: 0;
}
.f2b-full {
  width: 100%;
  box-sizing: border-box;
}
.f2b-select-sm {
  flex: 0 0 auto;
}
.f2b-select-md {
  flex: 0 1 140px;
  min-width: 100px;
}
.f2b-input {
  padding: 6px 10px;
  border-radius: var(--ant-border-radius, 6px);
  border: 1px solid var(--ant-color-border, #d9d9d9);
  background: var(--ant-color-bg-container, #ffffff);
  color: var(--ant-color-text, #1f2937);
  font-size: 13px;
  box-sizing: border-box;
}
.f2b-btn {
  padding: 6px 12px;
  border-radius: var(--ant-border-radius, 6px);
  border: 1px solid var(--ant-color-border, #d9d9d9);
  background: var(--ant-color-bg-container, #ffffff);
  color: var(--ant-color-text, #1f2937);
  cursor: pointer;
  font-size: 13px;
  white-space: nowrap;
}
.f2b-btn-danger {
  background: var(--ant-color-error, #ff4d4f);
  border-color: var(--ant-color-error, #ff4d4f);
  color: #ffffff;
}
.f2b-ban-list {
  display: flex;
  flex-direction: column;
  gap: 8px;
}
.f2b-ban-item {
  padding: 10px 12px;
  border-radius: var(--ant-border-radius-lg, 8px);
  border: 1px solid var(--ant-color-border-secondary, #f0f0f0);
  background: var(--ant-color-bg-elevated, var(--ant-color-bg-container, #ffffff));
  display: flex;
  flex-direction: column;
  gap: 6px;
}
.f2b-ban-head {
  display: flex;
  flex-wrap: wrap;
  justify-content: space-between;
  align-items: center;
  gap: 6px 10px;
}
.f2b-ban-title {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  gap: 8px;
  min-width: 0;
}
.f2b-ip {
  font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
  font-size: 14px;
  font-weight: 600;
  color: var(--ant-color-text-heading, var(--ant-color-text, #111827));
}
.f2b-tag {
  display: inline-block;
  padding: 1px 8px;
  font-size: 12px;
  line-height: 1.5;
  white-space: nowrap;
  border-radius: 4px;
  background: var(--ant-color-fill-tertiary, #f5f5f5);
  border: 1px solid var(--ant-color-border-secondary, #e5e7eb);
  color: var(--ant-color-text-secondary, #6b7280);
}
.f2b-actions {
  display: flex;
  align-items: center;
  gap: 10px;
  white-space: nowrap;
}
.f2b-link {
  background: none;
  border: none;
  padding: 0;
  color: var(--ant-color-primary, #1677ff);
  cursor: pointer;
  font-size: 12px;
}
.f2b-link:hover {
  text-decoration: underline;
}
.f2b-ban-reason {
  font-size: 12px;
  line-height: 1.45;
  color: var(--ant-color-text-secondary, #6b7280);
  word-break: break-word;
}
.f2b-ban-meta {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  gap: 4px 6px;
  font-size: 12px;
  color: var(--ant-color-text-tertiary, #9ca3af);
}
.f2b-meta-sep {
  opacity: 0.5;
}
.f2b-mono {
  font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
  font-weight: 500;
  color: var(--ant-color-text-secondary, #6b7280);
}
.f2b-empty-box {
  text-align: center;
  color: var(--ant-color-text-tertiary, #9ca3af);
  padding: 28px 12px;
  font-size: 13px;
  border: 1px dashed var(--ant-color-border-secondary, #e5e7eb);
  border-radius: var(--ant-border-radius-lg, 8px);
}
.f2b-err {
  color: var(--ant-color-error, #ff4d4f);
  font-size: 13px;
  margin: 0;
}
</style>
