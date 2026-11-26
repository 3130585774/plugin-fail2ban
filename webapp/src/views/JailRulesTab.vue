<script setup lang="ts">
import { onMounted, ref } from 'vue'
import { getRegistry } from '../state'
import type { JailConfig } from '../types'

const jails = ref<JailConfig[]>([])
const savingId = ref('')
const msg = ref('')

async function loadJails() {
  const res = await getRegistry().http.get<{ items: JailConfig[] }>('/jails')
  jails.value = res.data.items ?? []
}

async function saveJail(jail: JailConfig) {
  savingId.value = jail.id
  msg.value = ''
  try {
    await getRegistry().http.put(`/jails/${encodeURIComponent(jail.id)}`, jail)
    msg.value = `Saved ${jail.id}`
    setTimeout(() => (msg.value = ''), 2500)
  } catch (err) {
    msg.value = `Failed to save ${jail.id}: ${String(err)}`
  } finally {
    savingId.value = ''
  }
}

onMounted(() => {
  void loadJails()
})
</script>

<template>
  <div>
    <p v-if="msg" class="f2b-msg">{{ msg }}</p>
    <div class="f2b-jail-grid">
      <div v-for="j in jails" :key="j.id" class="f2b-jail-card">
        <div class="f2b-jail-head">
          <div>
            <strong>{{ j.name }}</strong>
            <span class="f2b-jail-id">{{ j.id }}</span>
          </div>
          <label class="f2b-switch">
            <input v-model="j.enabled" type="checkbox" @change="saveJail(j)" />
            <span>{{ j.enabled ? 'Enabled' : 'Disabled' }}</span>
          </label>
        </div>
        <p class="f2b-jail-desc">{{ j.description }}</p>

        <div class="f2b-jail-fields">
          <label>
            Threshold
            <input v-model.number="j.threshold" type="number" min="1" class="f2b-input" />
          </label>
          <label>
            Window (sec)
            <input v-model.number="j.window_sec" type="number" min="1" class="f2b-input" />
          </label>
          <label>
            Ban Duration (sec)
            <input v-model.number="j.ban_duration_sec" type="number" min="0" class="f2b-input" />
          </label>
        </div>

        <div class="f2b-jail-foot">
          <button class="f2b-btn" :disabled="savingId === j.id" @click="saveJail(j)">
            {{ savingId === j.id ? 'Saving...' : 'Save Rule' }}
          </button>
        </div>
      </div>
    </div>
  </div>
</template>

<style scoped>
.f2b-msg {
  font-size: 13px;
  color: var(--ant-color-primary, #1677ff);
  margin: 0 0 12px;
}
.f2b-jail-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(320px, 1fr));
  gap: 14px;
}
.f2b-jail-card {
  border: 1px solid var(--ant-color-border-secondary, #f0f0f0);
  border-radius: var(--ant-border-radius-lg, 8px);
  padding: 14px;
  background: var(--ant-color-bg-elevated, var(--ant-color-bg-container, #ffffff));
}
.f2b-jail-head {
  display: flex;
  justify-content: space-between;
  align-items: center;
  gap: 8px;
}
.f2b-jail-id {
  display: inline-block;
  margin-left: 8px;
  font-size: 12px;
  font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
  color: var(--ant-color-text-secondary, #6b7280);
}
.f2b-jail-desc {
  margin: 8px 0 12px;
  font-size: 13px;
  color: var(--ant-color-text-secondary, #6b7280);
}
.f2b-jail-fields {
  display: grid;
  grid-template-columns: repeat(3, 1fr);
  gap: 8px;
  margin-bottom: 12px;
}
.f2b-jail-fields label {
  display: flex;
  flex-direction: column;
  gap: 4px;
  font-size: 12px;
  color: var(--ant-color-text-secondary, #6b7280);
}
.f2b-input {
  padding: 5px 8px;
  border-radius: var(--ant-border-radius, 6px);
  border: 1px solid var(--ant-color-border, #d9d9d9);
  background: var(--ant-color-bg-container, #ffffff);
  color: var(--ant-color-text, #1f2937);
  font-size: 13px;
}
.f2b-switch {
  display: inline-flex;
  align-items: center;
  gap: 6px;
  font-size: 12px;
  cursor: pointer;
}
.f2b-jail-foot {
  display: flex;
  justify-content: flex-end;
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
</style>
