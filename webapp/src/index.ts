import { defineNginxUIPlugin, registerPlugin } from '@nginxui/plugin-sdk'
import { enUS, zhCN } from './i18n'
import { setRegistry, startBackgroundSync, stopBackgroundSync } from './state'
import Fail2banSettingsPanel from './views/Fail2banSettingsPanel.vue'
import LogThreatView from './slots/LogThreatView.vue'
import LogThreatColumn from './slots/LogThreatColumn.vue'
import SiteLogAction from './slots/SiteLogAction.vue'

export const PLUGIN_ID = 'io.github.3130585774.fail2ban'

registerPlugin(
  PLUGIN_ID,
  defineNginxUIPlugin({
    setup(registry) {
      // Idempotent setup: clear any prior timers before re-initializing.
      stopBackgroundSync()
      setRegistry(registry)

      registry.registerTranslations('zh_CN', zhCN)
      registry.registerTranslations('en', enUS)

      // Integrate directly into Nginx UI's native Plugin Settings Drawer
      // instead of adding a redundant standalone sidebar menu entry.
      registry.registerSettingsPanel(Fail2banSettingsPanel)

      registry.registerSlot('nginx_log.view:fail2ban', LogThreatView, {
        label: 'Threat Analysis',
        order: 20,
        when: (ctx) => ctx.type === 'access',
      })

      registry.registerSlot('nginx_log.list.column:threat_hits', LogThreatColumn, {
        label: 'Threat Hits (24h)',
        order: 30,
        when: (ctx) => ctx.type === 'access',
      })

      registry.registerSlot('site.log.actions', SiteLogAction, {
        order: 20,
      })

      startBackgroundSync()
    },

    teardown() {
      stopBackgroundSync()
      setRegistry(null)
    },
  }),
)
