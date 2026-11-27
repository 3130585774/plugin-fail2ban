<script setup lang="ts">
import { computed } from 'vue'
import type { SiteLogActionsContext } from '@nginxui/plugin-sdk'
import { t } from '../i18n'
import { logPathStatsMap } from '../state'

const props = defineProps<{
  context?: SiteLogActionsContext
  accessLogPath?: string
  accessLogInherited?: boolean
}>()

const logPath = computed(() => props.context?.accessLogPath ?? props.accessLogPath ?? '')
const inherited = computed(() => props.context?.accessLogInherited ?? props.accessLogInherited ?? false)
const hits = computed(() => (logPath.value ? logPathStatsMap.value[logPath.value]?.recent_hits ?? 0 : 0))
</script>

<template>
  <span class="f2b-site-action">
    <span class="f2b-site-badge" :class="{ hot: hits > 0 }">
      {{ t('Fail2ban') }}: {{ hits }}
    </span>
    <span v-if="inherited" class="f2b-inherited-hint" :title="t('This site shares the default access log')">
      ({{ t('Shared default log') }})
    </span>
  </span>
</template>

<style scoped>
.f2b-site-action {
  display: inline-flex;
  align-items: center;
  gap: 6px;
  font-size: 12px;
}
.f2b-site-badge {
  display: inline-block;
  padding: 1px 7px;
  border-radius: 999px;
  background: var(--ant-color-fill-tertiary, #f5f5f5);
  color: var(--ant-color-text-secondary, #6b7280);
  font-variant-numeric: tabular-nums;
}
.f2b-site-badge.hot {
  background: var(--ant-color-error-bg, #fff2f0);
  color: var(--ant-color-error, #ff4d4f);
  font-weight: 600;
}
.f2b-inherited-hint {
  color: var(--ant-color-warning, #faad14);
}
</style>
