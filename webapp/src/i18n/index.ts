import { getOptionalRegistry } from '../state'

export const zhCN: Record<string, string> = {
  // General & Header
  'Fail2ban Guard': 'Fail2ban 防护',
  'Protection Enabled': '防护已开启',
  'Protection Paused': '防护已暂停',
  'Sync Snippet Now': '立即同步片段',
  'Syncing...': '同步中...',
  'Nginx snippet synchronized.': 'Nginx 封禁片段已同步生效。',
  'Sync failed: {err}': '同步失败：{err}',
  'Enforcer Error: {err}': '执行器错误：{err}',

  // Metrics
  'Active Bans': '当前封禁',
  'Bans (24h)': '近 24h 封禁',
  'Logs Processed': '已分析日志',
  'Tracked IPs': '追踪 IP',

  // Tabs
  'Ban Management': '封禁管理',
  'Jail Rules': '规则管理',
  'Whitelist & Setup': '白名单与指引',

  // Active Bans & Manual Ban
  'Search IP, reason, or log path...': '搜索 IP、原因或日志路径...',
  'All Jails': '全部规则',
  'Manual': '手动封禁',
  'Refresh ({count})': '刷新 ({count})',
  'IP to ban (e.g. 203.0.113.10)': '要封禁的 IP（如 203.0.113.10）',
  'Reason': '封禁原因',
  'Manual ban': '手动封禁',
  '30 minutes': '30 分钟',
  '1 hour': '1 小时',
  '24 hours': '24 小时',
  '7 days': '7 天',
  'Permanent': '永久',
  'Manual Ban': '手动封禁',
  'IP Address': 'IP 地址',
  'Jail': '触发规则',
  'Hits / Offenses': '命中 / 累犯',
  'Banned At': '封禁时间',
  'Expires At': '到期时间',
  'Actions': '操作',
  'No active bans.': '当前没有生效中的封禁记录。',
  'Unban': '解封',
  '+24h': '延长24h',
  'Whitelist': '加白名单',
  'Added from Active Bans': '从活跃封禁列表加入白名单',

  // Jail Rules
  'Enabled': '已启用',
  'Disabled': '已停用',
  'Threshold': '触发阈值 (次)',
  'Window (sec)': '统计窗口 (秒)',
  'Ban Duration (sec)': '封禁时长 (秒)',
  'Save Rule': '保存规则',
  'Saving...': '保存中...',
  'Saved {id}': '已保存规则 {id}',
  'Failed to save {id}: {err}': '保存规则 {id} 失败：{err}',

  // Built-in Jail Names & Descriptions
  'jail.name.http-404-scan': '404 路径扫描检测',
  'jail.desc.http-404-scan': '检测短时间内高频请求不同不存在路径（404）的扫描行为，自动忽略静态资源。',
  'jail.name.http-sensitive-probe': '敏感路径探测检测',
  'jail.desc.http-sensitive-probe': '拦截对 /.env、/.git/、/wp-login.php、/phpmyadmin 等敏感路径的探测请求。',
  'jail.name.http-auth-bruteforce': '登录认证爆破检测',
  'jail.desc.http-auth-bruteforce': '针对登录/认证路径（如 /login、/auth、/api/auth 等）拦截连续 401/403 失败请求。为避免正常业务 403 误封，默认关闭，按需开启。',
  'jail.name.http-bad-bot': '恶意扫描器识别',
  'jail.desc.http-bad-bot': '识别并封禁已知恶意扫描器 User-Agent（如 sqlmap、nikto、zgrab、nuclei 等）。',
  'jail.name.nginxui-login-guard': 'Nginx UI 登录防护',
  'jail.desc.nginxui-login-guard': '监听面板登录失败事件，自动封禁针对 Nginx UI 后台的爆破 IP。',
  'jail.name.recidive-escalation': '累犯自动升级',
  'jail.desc.recidive-escalation': '7 天内多次被封禁的 IP 自动逐级延长封禁时长（1 小时 → 24 小时 → 7 天）。',

  // Whitelist & Setup Guide
  'Blocklist Integration (Recommended)': '封锁列表集成（推荐）',
  'Fail2ban Guard provides the security.blocklist capability. You can add "Fail2ban Active Bans" directly in Nginx UI -> Blocklists to manage and apply bans natively.':
    '本插件已提供 security.blocklist 能力，可直接前往 Nginx UI「封锁列表（Blocklists）」页面添加「Fail2ban Active Bans」来源，与原生封锁列表无缝结合。',
  'Real-Time Nginx Snippet Include': '实时 Nginx 配置片段引入',
  'For sub-second debounced enforcement without waiting for blocklist polling, add this directive to your http {} or server {} block:':
    '如需 3 秒防抖实时拦截（无需等待定时拉取），也可将下方指令加入 Nginx 的 http {} 或指定 server {} 配置块中：',
  'Copied!': '已复制',
  'Copy Include Directive': '复制 Include 指令',
  'Built-in anti-lockout always protects 127.0.0.0/8, ::1, 0.0.0.0/0, and ::/0.':
    '内置防锁死机制始终保护 127.0.0.0/8、::1、0.0.0.0/0 和 ::/0，不会被误封。',
  'Admin Whitelist (CIDR / IP)': '管理员白名单（CIDR / IP）',
  'e.g. 10.0.0.0/8 or 192.168.1.50': '例如 10.0.0.0/8 或 192.168.1.50',
  'Note (e.g. Office VPN)': '备注（如 办公室 VPN）',
  'Add': '添加',
  'CIDR': '网段 / IP',
  'Note': '备注',
  'Added By': '操作人',
  'Created At': '添加时间',
  'No custom whitelist entries yet.': '暂未添加自定义白名单。',
  'Remove': '移除',

  // Slots & Actions
  'Threat Analysis': '威胁分析',
  'Threat Hits (24h)': '近 24h 拦截',
  'Fail2ban Threat Analysis': 'Fail2ban 威胁分析',
  'No Fail2ban actions recorded for this access log.': '该访问日志暂无 Fail2ban 拦截记录。',
  'Time': '时间',
  'Action': '动作',
  'IP': 'IP',
  'action.ban': '封禁',
  'action.unban': '解封',
  'action.extend': '延长',
  'action.expire': '到期解封',
}

export const enUS: Record<string, string> = {
  'Fail2ban Guard': 'Fail2ban Guard',
  'Protection Enabled': 'Protection Enabled',
  'Protection Paused': 'Protection Paused',
  'Sync Snippet Now': 'Sync Snippet Now',
  'Syncing...': 'Syncing...',
  'Nginx snippet synchronized.': 'Nginx snippet synchronized.',
  'Sync failed: {err}': 'Sync failed: {err}',
  'Enforcer Error: {err}': 'Enforcer Error: {err}',
  'Active Bans': 'Active Bans',
  'Bans (24h)': 'Bans (24h)',
  'Logs Processed': 'Logs Processed',
  'Tracked IPs': 'Tracked IPs',
  'Ban Management': 'Ban Management',
  'Jail Rules': 'Jail Rules',
  'Whitelist & Setup': 'Whitelist & Setup',
  'Search IP, reason, or log path...': 'Search IP, reason, or log path...',
  'All Jails': 'All Jails',
  'Manual': 'Manual',
  'Refresh ({count})': 'Refresh ({count})',
  'IP to ban (e.g. 203.0.113.10)': 'IP to ban (e.g. 203.0.113.10)',
  'Reason': 'Reason',
  'Manual ban': 'Manual ban',
  '30 minutes': '30 minutes',
  '1 hour': '1 hour',
  '24 hours': '24 hours',
  '7 days': '7 days',
  'Permanent': 'Permanent',
  'Manual Ban': 'Manual Ban',
  'IP Address': 'IP Address',
  'Jail': 'Jail',
  'Hits / Offenses': 'Hits / Offenses',
  'Banned At': 'Banned At',
  'Expires At': 'Expires At',
  'Actions': 'Actions',
  'No active bans.': 'No active bans.',
  'Unban': 'Unban',
  '+24h': '+24h',
  'Whitelist': 'Whitelist',
  'Added from Active Bans': 'Added from Active Bans',
  'Enabled': 'Enabled',
  'Disabled': 'Disabled',
  'Threshold': 'Threshold',
  'Window (sec)': 'Window (sec)',
  'Ban Duration (sec)': 'Ban Duration (sec)',
  'Save Rule': 'Save Rule',
  'Saving...': 'Saving...',
  'Saved {id}': 'Saved {id}',
  'Failed to save {id}: {err}': 'Failed to save {id}: {err}',
  'jail.name.http-404-scan': 'HTTP 404 Path Scan',
  'jail.desc.http-404-scan': 'Detects rapid 404 requests across distinct paths while ignoring static assets.',
  'jail.name.http-sensitive-probe': 'Sensitive Path Probe',
  'jail.desc.http-sensitive-probe': 'Blocks probes targeting /.env, /.git/, /wp-login.php, /phpmyadmin, and similar paths.',
  'jail.name.http-auth-bruteforce': 'Auth & Login Brute Force',
  'jail.desc.http-auth-bruteforce': 'Blocks repeated 401/403 failures on login/auth paths (/login, /auth, /api/auth, etc.). Disabled by default to avoid false positives.',
  'jail.name.http-bad-bot': 'Malicious Scanner / Bad Bot',
  'jail.desc.http-bad-bot': 'Blocks known vulnerability scanners (sqlmap, nikto, zgrab, nuclei, etc.).',
  'jail.name.nginxui-login-guard': 'Nginx UI Login Guard',
  'jail.desc.nginxui-login-guard': 'Protects Nginx UI admin login by banning IPs after repeated login failures.',
  'jail.name.recidive-escalation': 'Recidive Escalation',
  'jail.desc.recidive-escalation': 'Escalates repeat offenders within 7 days (1h -> 24h -> 7d).',
  'Blocklist Integration (Recommended)': 'Blocklist Integration (Recommended)',
  'Fail2ban Guard provides the security.blocklist capability. You can add "Fail2ban Active Bans" directly in Nginx UI -> Blocklists to manage and apply bans natively.':
    'Fail2ban Guard provides the security.blocklist capability. You can add "Fail2ban Active Bans" directly in Nginx UI -> Blocklists to manage and apply bans natively.',
  'Real-Time Nginx Snippet Include': 'Real-Time Nginx Snippet Include',
  'For sub-second debounced enforcement without waiting for blocklist polling, add this directive to your http {} or server {} block:':
    'For sub-second debounced enforcement without waiting for blocklist polling, add this directive to your http {} or server {} block:',
  'Copied!': 'Copied!',
  'Copy Include Directive': 'Copy Include Directive',
  'Built-in anti-lockout always protects 127.0.0.0/8, ::1, 0.0.0.0/0, and ::/0.':
    'Built-in anti-lockout always protects 127.0.0.0/8, ::1, 0.0.0.0/0, and ::/0.',
  'Admin Whitelist (CIDR / IP)': 'Admin Whitelist (CIDR / IP)',
  'e.g. 10.0.0.0/8 or 192.168.1.50': 'e.g. 10.0.0.0/8 or 192.168.1.50',
  'Note (e.g. Office VPN)': 'Note (e.g. Office VPN)',
  'Add': 'Add',
  'CIDR': 'CIDR',
  'Note': 'Note',
  'Added By': 'Added By',
  'Created At': 'Created At',
  'No custom whitelist entries yet.': 'No custom whitelist entries yet.',
  'Remove': 'Remove',
  'Threat Analysis': 'Threat Analysis',
  'Threat Hits (24h)': 'Threat Hits (24h)',
  'Fail2ban Threat Analysis': 'Fail2ban Threat Analysis',
  'No Fail2ban actions recorded for this access log.': 'No Fail2ban actions recorded for this access log.',
  'Time': 'Time',
  'Action': 'Action',
  'IP': 'IP',
  'action.ban': 'Ban',
  'action.unban': 'Unban',
  'action.extend': 'Extend',
  'action.expire': 'Expired',
}

function isZhLocale(): boolean {
  const reg = getOptionalRegistry()
  const locale = (reg?.host?.locale ?? navigator.language ?? 'en').toLowerCase()
  return locale.startsWith('zh')
}

export function t(key: string, params?: Record<string, string | number>): string {
  const dict = isZhLocale() ? zhCN : enUS
  let text = dict[key] ?? enUS[key] ?? key
  if (params) {
    for (const [k, v] of Object.entries(params)) {
      text = text.replace(`{${k}}`, String(v))
    }
  }
  return text
}

export function jailName(id: string, fallback?: string): string {
  const key = `jail.name.${id}`
  const dict = isZhLocale() ? zhCN : enUS
  return dict[key] ?? fallback ?? id
}

export function jailDesc(id: string, fallback?: string): string {
  const key = `jail.desc.${id}`
  const dict = isZhLocale() ? zhCN : enUS
  return dict[key] ?? fallback ?? ''
}

export function actionLabel(action: string): string {
  const key = `action.${action}`
  const dict = isZhLocale() ? zhCN : enUS
  return dict[key] ?? action
}
