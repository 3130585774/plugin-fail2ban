package detector

import (
	"fmt"
	"path"
	"regexp"
	"strings"

	"github.com/3130585774/plugin-fail2ban/internal/store"
)

const (
	JailHTTP404Scan        = "http-404-scan"
	JailHTTPSensitiveProbe = "http-sensitive-probe"
	JailHTTPAuthBruteforce = "http-auth-bruteforce"
	JailHTTPBadBot         = "http-bad-bot"
	JailNginxUILoginGuard  = "nginxui-login-guard"
	JailRecidiveEscalation = "recidive-escalation"
)

// DefaultJails returns the 6 built-in detection jails from the architecture spec.
func DefaultJails() []store.JailConfig {
	return []store.JailConfig{
		{
			ID:             JailHTTP404Scan,
			Name:           "HTTP 404 Path Scanner",
			Description:    "Detect sequential 404 directory/path enumeration using deduplicated URI paths.",
			Enabled:        true,
			Threshold:      15,
			WindowSec:      60,
			BanDurationSec: 3600, // 1h
			StatusCodes:    []int{404},
			DeduplicateURI: true,
			ExcludeExts: []string{
				".ico", ".map", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".webp",
				".css", ".js", ".woff", ".woff2", ".ttf", ".eot",
			},
		},
		{
			ID:             JailHTTPSensitiveProbe,
			Name:           "Sensitive Path Probe",
			Description:    "Block probes targeting high-risk files and admin endpoints (/.env, /.git/, /wp-login.php, /phpmyadmin).",
			Enabled:        true,
			Threshold:      3,
			WindowSec:      300,
			BanDurationSec: 86400, // 24h
			StatusCodes:    []int{403, 404},
			Patterns: []string{
				`(?i)/\.env(\b|\.)`,
				`(?i)/\.git(/|$)`,
				`(?i)/wp-login\.php`,
				`(?i)/wp-admin(/|$)`,
				`(?i)/xmlrpc\.php`,
				`(?i)/phpmyadmin(/|$)`,
				`(?i)/pma(/|$)`,
				`(?i)/actuator(/|$)`,
				`(?i)/\.aws(/|$)`,
				`(?i)/\.ssh(/|$)`,
				`(?i)/cgi-bin/`,
				`(?i)/etc/passwd`,
			},
		},
		{
			ID:             JailHTTPAuthBruteforce,
			Name:           "Auth & API Brute Force",
			Description:    "Detect repeated 401/403 authentication failures on login or API endpoints.",
			Enabled:        true,
			Threshold:      10,
			WindowSec:      180,
			BanDurationSec: 1800, // 30m
			StatusCodes:    []int{401, 403},
		},
		{
			ID:             JailHTTPBadBot,
			Name:           "Malicious Scanner User-Agent",
			Description:    "Block requests carrying known vulnerability scanner User-Agent signatures.",
			Enabled:        true,
			Threshold:      2,
			WindowSec:      60,
			BanDurationSec: 86400, // 24h
			Patterns: []string{
				`(?i)(sqlmap|nikto|zgrab|masscan|nuclei|dirbuster|gobuster|ffuf|wpscan|acunetix|nessus|openvas|nmap)`,
			},
		},
		{
			ID:             JailNginxUILoginGuard,
			Name:           "Nginx UI Login Guard",
			Description:    "Protect Nginx UI admin panel against credential stuffing via host auth.login_failed events.",
			Enabled:        true,
			Threshold:      5,
			WindowSec:      600,
			BanDurationSec: 3600, // 1h
		},
		{
			ID:               JailRecidiveEscalation,
			Name:             "Recidive Escalation",
			Description:      "Escalate ban durations (1h -> 24h -> 7d) for repeat offenders within a 7-day rolling window.",
			Enabled:          true,
			Threshold:        1,
			WindowSec:        7 * 24 * 3600,
			BanDurationSec:   86400,
			EscalationLevels: []int64{3600, 86400, 7 * 86400},
		},
	}
}

type compiledJail struct {
	cfg          store.JailConfig
	statusSet    map[int]struct{}
	methodSet    map[string]struct{}
	excludeExts  map[string]struct{}
	logPathSet   map[string]struct{}
	regexps      []*regexp.Regexp
	pathPrefixes []string
}

func compileJail(cfg store.JailConfig) (*compiledJail, error) {
	if cfg.ID == "" {
		return nil, fmt.Errorf("jail id is required")
	}
	if cfg.Threshold < 1 {
		return nil, fmt.Errorf("jail %s: threshold must be >= 1", cfg.ID)
	}
	if cfg.WindowSec < 1 {
		return nil, fmt.Errorf("jail %s: window_sec must be >= 1", cfg.ID)
	}
	if cfg.BanDurationSec < 0 {
		return nil, fmt.Errorf("jail %s: ban_duration_sec must be >= 0", cfg.ID)
	}

	cj := &compiledJail{
		cfg:          cfg,
		statusSet:    make(map[int]struct{}, len(cfg.StatusCodes)),
		methodSet:    make(map[string]struct{}, len(cfg.Methods)),
		excludeExts:  make(map[string]struct{}, len(cfg.ExcludeExts)),
		logPathSet:   make(map[string]struct{}, len(cfg.LogPaths)),
		pathPrefixes: make([]string, 0, len(cfg.PathPrefixes)),
	}
	for _, s := range cfg.StatusCodes {
		cj.statusSet[s] = struct{}{}
	}
	for _, m := range cfg.Methods {
		m = strings.ToUpper(strings.TrimSpace(m))
		if m != "" {
			cj.methodSet[m] = struct{}{}
		}
	}
	for _, ext := range cfg.ExcludeExts {
		ext = strings.ToLower(strings.TrimSpace(ext))
		if ext != "" {
			if !strings.HasPrefix(ext, ".") {
				ext = "." + ext
			}
			cj.excludeExts[ext] = struct{}{}
		}
	}
	for _, lp := range cfg.LogPaths {
		lp = strings.TrimSpace(lp)
		if lp != "" {
			cj.logPathSet[lp] = struct{}{}
		}
	}
	for _, p := range cfg.PathPrefixes {
		p = strings.TrimSpace(p)
		if p != "" {
			cj.pathPrefixes = append(cj.pathPrefixes, p)
		}
	}
	for _, pat := range cfg.Patterns {
		pat = strings.TrimSpace(pat)
		if pat == "" {
			continue
		}
		re, err := regexp.Compile(pat)
		if err != nil {
			return nil, fmt.Errorf("jail %s: invalid regex %q: %w", cfg.ID, pat, err)
		}
		cj.regexps = append(cj.regexps, re)
	}
	return cj, nil
}

// StripQuery extracts the normalized URI path without query string.
func StripQuery(uri string) string {
	if idx := strings.IndexByte(uri, '?'); idx >= 0 {
		uri = uri[:idx]
	}
	if uri == "" {
		return "/"
	}
	return uri
}

func (cj *compiledJail) matchesLog(logPath string, status int, method, uriPath, userAgent string) bool {
	if !cj.cfg.Enabled {
		return false
	}
	if len(cj.logPathSet) > 0 {
		if _, ok := cj.logPathSet[logPath]; !ok {
			return false
		}
	}
	if len(cj.statusSet) > 0 {
		if _, ok := cj.statusSet[status]; !ok {
			return false
		}
	}
	if len(cj.methodSet) > 0 {
		if _, ok := cj.methodSet[strings.ToUpper(method)]; !ok {
			return false
		}
	}
	if len(cj.pathPrefixes) > 0 {
		matched := false
		for _, pref := range cj.pathPrefixes {
			if strings.HasPrefix(uriPath, pref) {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}
	if len(cj.excludeExts) > 0 {
		ext := strings.ToLower(path.Ext(uriPath))
		if _, excluded := cj.excludeExts[ext]; excluded {
			return false
		}
	}

	switch cj.cfg.ID {
	case JailHTTPBadBot:
		if userAgent == "" || len(cj.regexps) == 0 {
			return false
		}
		for _, re := range cj.regexps {
			if re.MatchString(userAgent) {
				return true
			}
		}
		return false
	default:
		if len(cj.regexps) > 0 {
			for _, re := range cj.regexps {
				if re.MatchString(uriPath) {
					return true
				}
			}
			return false
		}
		return true
	}
}
