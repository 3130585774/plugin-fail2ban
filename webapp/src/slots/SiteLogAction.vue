<script setup lang="ts">
import { computed } from 'vue'
import type { SiteLogActionsContext } from '@nginxui/plugin-sdk'
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
    <a class="f2b-site-link" href="#/fail2ban">
      Fail2ban ({{ hits }})
    </a>
    <span v-if="inherited" class="f2b-inherited-hint" title="This site shares the default access log">
      (Shared default log)
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
.f2b-site-link {
  color: var(--ant-color-primary, #1677ff);
  text-decoration: none;
}
.f2b-inherited-hint {
  color: var(--ant-color-warning, #faad14);
}
</style>
