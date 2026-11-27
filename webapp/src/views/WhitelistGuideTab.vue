<script setup lang="ts">
import { onMounted, ref } from 'vue'
import { t } from '../i18n'
import { formatUnixTime, getRegistry } from '../state'
import type { SnippetGuideResponse, WhitelistEntry } from '../types'

const entries = ref<WhitelistEntry[]>([])
const guide = ref<SnippetGuideResponse | null>(null)
const newCIDR = ref('')
const newNote = ref('')
const copied = ref(false)
const errMsg = ref('')

async function loadData() {
  const [wlRes, guideRes] = await Promise.all([
    getRegistry().http.get<{ items: WhitelistEntry[] }>('/whitelist'),
    getRegistry().http.get<SnippetGuideResponse>('/snippet/guide'),
  ])
  entries.value = wlRes.data.items ?? []
  guide.value = guideRes.data
}

async function addWhitelist() {
  if (!newCIDR.value.trim()) return
  errMsg.value = ''
  try {
    await getRegistry().http.post('/whitelist', {
      cidr: newCIDR.value.trim(),
      note: newNote.value.trim(),
    })
    newCIDR.value = ''
    newNote.value = ''
    await loadData()
  } catch (err) {
    errMsg.value = String(err)
  }
}

async function removeWhitelist(cidr: string) {
  await getRegistry().http.delete('/whitelist', { params: { cidr } })
  await loadData()
}

async function copyDirective() {
  if (!guide.value?.include_directive) return
  try {
    await navigator.clipboard.writeText(guide.value.include_directive)
    copied.value = true
    setTimeout(() => (copied.value = false), 2000)
  } catch {
    // Clipboard unavailable
  }
}

onMounted(() => {
  void loadData()
})
</script>

<template>
  <div class="f2b-split">
    <section class="f2b-box f2b-box-highlight">
      <h3>{{ t('Blocklist Integration (Recommended)') }}</h3>
      <p class="f2b-hint">
        {{
          t(
            'Fail2ban Guard provides the security.blocklist capability. You can add "Fail2ban Active Bans" directly in Nginx UI -> Blocklists to manage and apply bans natively.',
          )
        }}
      </p>
    </section>

    <section class="f2b-box f2b-box-card">
      <h3>{{ t('Real-Time Nginx Snippet Include') }}</h3>
      <p class="f2b-hint">
        {{
          t(
            'For sub-second debounced enforcement without waiting for blocklist polling, add this directive to your http {} or server {} block:',
          )
        }}
      </p>
      <div class="f2b-code-col">
        <code class="f2b-code">{{
          guide?.include_directive ||
          'include snippets/plugins/io.github.3130585774.fail2ban/fail2ban-bans.conf;'
        }}</code>
        <button class="f2b-btn" @click="copyDirective">
          {{ copied ? t('Copied!') : t('Copy Include Directive') }}
        </button>
      </div>
      <p class="f2b-hint f2b-hint-last">
        {{ t('Built-in anti-lockout always protects 127.0.0.0/8, ::1, 0.0.0.0/0, and ::/0.') }}
      </p>
    </section>

    <section class="f2b-box f2b-box-card">
      <h3>{{ t('Admin Whitelist (CIDR / IP)') }}</h3>
      <div class="f2b-wl-form">
        <div class="f2b-row">
          <input
            v-model="newCIDR"
            class="f2b-input f2b-grow"
            :placeholder="t('e.g. 10.0.0.0/8 or 192.168.1.50')"
            @keyup.enter="addWhitelist"
          />
          <button class="f2b-btn f2b-btn-primary" @click="addWhitelist">{{ t('Add') }}</button>
        </div>
        <input
          v-model="newNote"
          class="f2b-input f2b-full"
          :placeholder="t('Note (e.g. Office VPN)')"
          @keyup.enter="addWhitelist"
        />
      </div>
      <p v-if="errMsg" class="f2b-err">{{ errMsg }}</p>

      <div v-if="entries.length === 0" class="f2b-empty">
        {{ t('No custom whitelist entries yet.') }}
      </div>

      <div v-else class="f2b-wl-list">
        <div v-for="w in entries" :key="w.cidr" class="f2b-wl-item">
          <div class="f2b-wl-main">
            <span class="f2b-mono f2b-wl-cidr">{{ w.cidr }}</span>
            <span v-if="w.note" class="f2b-wl-note">{{ w.note }}</span>
            <span class="f2b-wl-meta">{{ w.created_by }} · {{ formatUnixTime(w.created_at) }}</span>
          </div>
          <button class="f2b-link-danger" @click="removeWhitelist(w.cidr)">
            {{ t('Remove') }}
          </button>
        </div>
      </div>
    </section>
  </div>
</template>

<style scoped>
.f2b-split {
  display: flex;
  flex-direction: column;
  gap: 12px;
}
.f2b-box-highlight {
  padding: 12px 14px;
  border-radius: var(--ant-border-radius-lg, 8px);
  background: var(--ant-color-info-bg, #e6f4ff);
  border: 1px solid var(--ant-color-info-border, #91caff);
}
.f2b-box-card {
  padding: 12px 14px;
  border-radius: var(--ant-border-radius-lg, 8px);
  border: 1px solid var(--ant-color-border-secondary, #f0f0f0);
  background: var(--ant-color-bg-elevated, var(--ant-color-bg-container, #ffffff));
}
.f2b-box h3 {
  margin: 0 0 8px;
  font-size: 14px;
  font-weight: 600;
}
.f2b-hint {
  margin: 0 0 8px;
  font-size: 12px;
  line-height: 1.55;
  color: var(--ant-color-text-secondary, #6b7280);
}
.f2b-hint-last {
  margin-bottom: 0;
}
.f2b-box-highlight .f2b-hint {
  margin-bottom: 0;
  color: var(--ant-color-text, #1f2937);
}
.f2b-code-col {
  display: flex;
  flex-direction: column;
  align-items: flex-start;
  gap: 8px;
  margin-bottom: 8px;
}
.f2b-code {
  width: 100%;
  box-sizing: border-box;
  padding: 8px 10px;
  border-radius: var(--ant-border-radius, 6px);
  background: var(--ant-color-fill-tertiary, #f5f5f5);
  border: 1px solid var(--ant-color-border-secondary, #e5e7eb);
  font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
  font-size: 12px;
  word-break: break-all;
}
.f2b-wl-form {
  display: flex;
  flex-direction: column;
  gap: 8px;
  margin-bottom: 12px;
}
.f2b-row {
  display: flex;
  gap: 8px;
}
.f2b-grow {
  flex: 1 1 0;
  min-width: 0;
}
.f2b-full {
  width: 100%;
  box-sizing: border-box;
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
  padding: 5px 12px;
  border-radius: var(--ant-border-radius, 6px);
  border: 1px solid var(--ant-color-border, #d9d9d9);
  background: var(--ant-color-bg-container, #ffffff);
  color: var(--ant-color-text, #1f2937);
  cursor: pointer;
  font-size: 13px;
  white-space: nowrap;
}
.f2b-btn-primary {
  background: var(--ant-color-primary, #1677ff);
  border-color: var(--ant-color-primary, #1677ff);
  color: #ffffff;
}
.f2b-wl-list {
  display: flex;
  flex-direction: column;
  gap: 8px;
}
.f2b-wl-item {
  display: flex;
  justify-content: space-between;
  align-items: center;
  gap: 10px;
  padding: 8px 10px;
  border-radius: var(--ant-border-radius, 6px);
  background: var(--ant-color-fill-quaternary, rgba(255, 255, 255, 0.02));
  border: 1px solid var(--ant-color-border-secondary, #f0f0f0);
}
.f2b-wl-main {
  display: flex;
  flex-direction: column;
  gap: 2px;
  min-width: 0;
}
.f2b-wl-cidr {
  font-size: 13px;
  font-weight: 600;
}
.f2b-wl-note {
  font-size: 12px;
  color: var(--ant-color-text-secondary, #6b7280);
}
.f2b-wl-meta {
  font-size: 11px;
  color: var(--ant-color-text-tertiary, #9ca3af);
}
.f2b-mono {
  font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
}
.f2b-link-danger {
  background: none;
  border: none;
  color: var(--ant-color-error, #ff4d4f);
  cursor: pointer;
  font-size: 12px;
  white-space: nowrap;
}
.f2b-empty {
  text-align: center;
  color: var(--ant-color-text-tertiary, #9ca3af);
  padding: 16px 0;
  font-size: 13px;
}
.f2b-err {
  color: var(--ant-color-error, #ff4d4f);
  font-size: 13px;
  margin: 0 0 8px;
}
</style>
