package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	sdk "github.com/nginxui/plugin-sdk-go"
	"github.com/nginxui/plugin-sdk-go/protocol"

	"github.com/3130585774/plugin-fail2ban/internal/detector"
	"github.com/3130585774/plugin-fail2ban/internal/enforcer"
	"github.com/3130585774/plugin-fail2ban/internal/store"
)

type stubHost struct{}

func (stubHost) Ready() bool                                                       { return false }
func (stubHost) Info() sdk.Info                                                    { return sdk.Info{PluginID: "io.github.3130585774.fail2ban"} }
func (stubHost) KVGet(_ context.Context, _ string, _ any) (bool, error)            { return false, nil }
func (stubHost) KVSet(_ context.Context, _ string, _ any) error                    { return nil }
func (stubHost) SitesList(_ context.Context) ([]protocol.HostSite, error)          { return nil, nil }
func (stubHost) NginxSnippetPut(_ context.Context, _, _ string) (bool, string, error) { return false, "", nil }
func (stubHost) NginxSnippetDelete(_ context.Context, _ string) (bool, error)      { return false, nil }
func (stubHost) NginxSnippetList(_ context.Context) ([]protocol.HostNginxSnippet, error) {
	return nil, nil
}
func (stubHost) Notify(_ context.Context, _, _, _ string, _ any) error { return nil }

func TestAPIRESTEndpoints(t *testing.T) {
	st, err := store.Open(":memory:")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer func() { _ = st.Close() }()

	host := stubHost{}
	hub := NewHub()
	defer hub.Close()

	enf := enforcer.NewSnippetEnforcer(st, host, nil, "io.github.3130585774.fail2ban", time.Second, 3*time.Second)
	eng, err := detector.NewEngine(st, enf, hub, host, store.DefaultGlobalConfig())
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	srv := NewServer(st, eng, enf, hub, host)

	// 1. Create manual ban.
	body := bytes.NewBufferString(`{"ip":"203.0.113.55","reason":"test ban","duration_sec":3600}`)
	req := httptest.NewRequest(http.MethodPost, "/bans", body)
	req.Header.Set(sdk.HeaderUser, "alice")
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusCreated {
		t.Fatalf("POST /bans expected 201, got %d: %s", w.Code, w.Body.String())
	}

	// 2. Reject banning loopback IP.
	body2 := bytes.NewBufferString(`{"ip":"127.0.0.1","reason":"bad","duration_sec":3600}`)
	req2 := httptest.NewRequest(http.MethodPost, "/bans", body2)
	w2 := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w2, req2)
	if w2.Code != http.StatusConflict {
		t.Fatalf("POST /bans loopback expected 409, got %d", w2.Code)
	}

	// 3. Adding whitelist CIDR covering 203.0.113.55 must auto-unban it.
	wlBody := bytes.NewBufferString(`{"cidr":"203.0.113.0/24","note":"office"}`)
	wlReq := httptest.NewRequest(http.MethodPost, "/whitelist", wlBody)
	wlW := httptest.NewRecorder()
	srv.Handler().ServeHTTP(wlW, wlReq)
	if wlW.Code != http.StatusCreated {
		t.Fatalf("POST /whitelist expected 201, got %d: %s", wlW.Code, wlW.Body.String())
	}
	var wlResp struct {
		AutoUnbanned int `json:"auto_unbanned"`
	}
	_ = json.Unmarshal(wlW.Body.Bytes(), &wlResp)
	if wlResp.AutoUnbanned != 1 {
		t.Fatalf("expected auto_unbanned=1, got %d", wlResp.AutoUnbanned)
	}

	// 4. GET /status returns valid JSON.
	stReq := httptest.NewRequest(http.MethodGet, "/status", nil)
	stW := httptest.NewRecorder()
	srv.Handler().ServeHTTP(stW, stReq)
	if stW.Code != http.StatusOK {
		t.Fatalf("GET /status expected 200, got %d", stW.Code)
	}

	// 5. GET /jails returns 6 built-in jails.
	jReq := httptest.NewRequest(http.MethodGet, "/jails", nil)
	jW := httptest.NewRecorder()
	srv.Handler().ServeHTTP(jW, jReq)
	var jResp struct {
		Items []store.JailConfig `json:"items"`
	}
	_ = json.Unmarshal(jW.Body.Bytes(), &jResp)
	if len(jResp.Items) != 6 {
		t.Fatalf("expected 6 built-in jails, got %d", len(jResp.Items))
	}
}
