import { defineNginxUIPlugin, registerPlugin } from '@nginxui/plugin-sdk'
import { enUS, zhCN } from './i18n'
import { setRegistry, startBackgroundSync, stopBackgroundSync } from './state'
import Fail2banConsole from './views/Fail2banConsole.vue'
import LogThreatView from './slots/LogThreatView.vue'
import LogThreatColumn from './slots/LogThreatColumn.vue'
import SiteLogAction from './slots/SiteLogAction.vue'

export const PLUGIN_ID = 'io.github.3130585774.fail2ban'

registerPlugin(
  PLUGIN_ID,
  defineNginxUIPlugin({
    setup(registry) {
      // Idempotent setup: clear any prior timers/sockets before re-initializing.
      stopBackgroundSync()
      setRegistry(registry)

      registry.registerTranslations('zh_CN', zhCN)
      registry.registerTranslations('en', enUS)

      registry.registerRoute(
        {
          path: 'fail2ban',
          name: 'Fail2banGuard',
          component: Fail2banConsole,
          meta: {
            title: 'Fail2ban Guard',
            icon: 'SafetyCertificateOutlined',
          },
        },
        { order: 45 },
      )

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
