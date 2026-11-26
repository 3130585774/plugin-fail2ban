<script setup lang="ts">
import { onMounted, ref } from 'vue'
import { formatUnixTime, getRegistry, refreshStatus } from '../state'
import type { BanRecord } from '../types'

const bans = ref<BanRecord[]>([])
const total = ref(0)
const loading = ref(false)
const search = ref('')
const jailFilter = ref('')

const manualIP = ref('')
const manualReason = ref('manual ban')
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
      reason: manualReason.value.trim() || 'manual ban',
      duration_sec: Number(manualDuration.value) || 0,
    })
    manualIP.value = ''
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
  await getRegistry().http.post('/whitelist', { cidr: ip, note: 'Added from Active Bans' })
  await Promise.all([loadBans(), refreshStatus()])
}

onMounted(() => {
  void loadBans()
})
</script>

<template>
  <div>
    <div class="f2b-toolbar">
      <input
        v-model="search"
        class="f2b-input"
        placeholder="Search IP, reason, or log path..."
        @keyup.enter="loadBans"
      />
      <select v-model="jailFilter" class="f2b-input" @change="loadBans">
        <option value="">All Jails</option>
        <option value="http-404-scan">http-404-scan</option>
        <option value="http-sensitive-probe">http-sensitive-probe</option>
        <option value="http-auth-bruteforce">http-auth-bruteforce</option>
        <option value="http-bad-bot">http-bad-bot</option>
        <option value="nginxui-login-guard">nginxui-login-guard</option>
        <option value="manual">manual</option>
      </select>
      <button class="f2b-btn" @click="loadBans">Refresh ({{ total }})</button>
    </div>

    <div class="f2b-manual-bar">
      <input v-model="manualIP" class="f2b-input" placeholder="IP to ban (e.g. 203.0.113.10)" />
      <input v-model="manualReason" class="f2b-input" placeholder="Reason" />
      <select v-model.number="manualDuration" class="f2b-input">
        <option :value="1800">30 minutes</option>
        <option :value="3600">1 hour</option>
        <option :value="86400">24 hours</option>
        <option :value="604800">7 days</option>
        <option :value="0">Permanent</option>
      </select>
      <button class="f2b-btn f2b-btn-danger" @click="addManualBan">Manual Ban</button>
    </div>

    <p v-if="errorMsg" class="f2b-err">{{ errorMsg }}</p>

    <div class="f2b-table-wrap">
      <table class="f2b-table">
        <thead>
          <tr>
            <th>IP Address</th>
            <th>Jail</th>
            <th>Reason</th>
            <th>Hits / Offenses</th>
            <th>Banned At</th>
            <th>Expires At</th>
            <th>Actions</th>
          </tr>
        </thead>
        <tbody>
          <tr v-if="!loading && bans.length === 0">
            <td colspan="7" class="f2b-empty">No active bans.</td>
          </tr>
          <tr v-for="b in bans" :key="b.ip">
            <td class="f2b-mono">{{ b.ip }}</td>
            <td><span class="f2b-tag">{{ b.jail }}</span></td>
            <td>{{ b.reason }}</td>
            <td class="f2b-mono">{{ b.hit_count }} / #{{ b.offense_count }}</td>
            <td>{{ formatUnixTime(b.banned_at) }}</td>
            <td>{{ b.expires_at ? formatUnixTime(b.expires_at) : 'Permanent' }}</td>
            <td class="f2b-actions">
              <button class="f2b-link" @click="unban(b.ip)">Unban</button>
              <button class="f2b-link" @click="extendBan(b.ip)">+24h</button>
              <button class="f2b-link" @click="whitelistIP(b.ip)">Whitelist</button>
            </td>
          </tr>
        </tbody>
      </table>
    </div>
  </div>
</template>

<style scoped>
.f2b-toolbar,
.f2b-manual-bar {
  display: flex;
  flex-wrap: wrap;
  gap: 8px;
  margin-bottom: 12px;
}
.f2b-input {
  padding: 6px 10px;
  border-radius: var(--ant-border-radius, 6px);
  border: 1px solid var(--ant-color-border, #d9d9d9);
  background: var(--ant-color-bg-container, #ffffff);
  color: var(--ant-color-text, #1f2937);
  font-size: 13px;
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
.f2b-btn-danger {
  background: var(--ant-color-error, #ff4d4f);
  border-color: var(--ant-color-error, #ff4d4f);
  color: #ffffff;
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
  padding: 10px 8px;
  border-bottom: 1px solid var(--ant-color-border-secondary, #f0f0f0);
}
.f2b-mono {
  font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
}
.f2b-tag {
  display: inline-block;
  padding: 2px 8px;
  font-size: 12px;
  border-radius: 4px;
  background: var(--ant-color-fill-tertiary, #f5f5f5);
  border: 1px solid var(--ant-color-border-secondary, #e5e7eb);
}
.f2b-actions {
  display: flex;
  gap: 10px;
}
.f2b-link {
  background: none;
  border: none;
  padding: 0;
  color: var(--ant-color-primary, #1677ff);
  cursor: pointer;
  font-size: 13px;
}
.f2b-empty {
  text-align: center;
  color: var(--ant-color-text-tertiary, #9ca3af);
  padding: 24px 0;
}
.f2b-err {
  color: var(--ant-color-error, #ff4d4f);
  font-size: 13px;
  margin: 0 0 10px;
}
</style>
