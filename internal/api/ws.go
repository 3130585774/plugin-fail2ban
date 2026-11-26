package api

import (
	"context"
	"encoding/json"
	"net/http"
	"sync"
	"time"

	"github.com/coder/websocket"

	"github.com/3130585774/plugin-fail2ban/internal/store"
)

const wsClientBufSize = 64

type wsMessage struct {
	Type string `json:"type"`
	Data any    `json:"data"`
	TS   int64  `json:"ts"`
}

// Hub broadcasts real-time Fail2ban events to connected WebSocket clients.
type Hub struct {
	mu      sync.Mutex
	clients map[chan []byte]struct{}
	closed  bool
}

// NewHub creates a new WebSocket event hub.
func NewHub() *Hub {
	return &Hub{
		clients: make(map[chan []byte]struct{}),
	}
}

// Broadcast serializes a BanEvent and fans it out to all subscribers without blocking.
func (h *Hub) Broadcast(ev store.BanEvent) {
	payload, err := json.Marshal(wsMessage{
		Type: "ban_event",
		Data: ev,
		TS:   store.NowUnix(),
	})
	if err != nil {
		return
	}

	h.mu.Lock()
	defer h.mu.Unlock()
	if h.closed {
		return
	}
	for ch := range h.clients {
		select {
		case ch <- payload:
		default:
			// Slow client: drop frame rather than backpressuring the detector.
		}
	}
}

// Close disconnects all active WebSocket subscribers cleanly.
func (h *Hub) Close() {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.closed {
		return
	}
	h.closed = true
	for ch := range h.clients {
		close(ch)
		delete(h.clients, ch)
	}
}

// ServeWS upgrades an HTTP connection to WebSocket and streams live events.
func (h *Hub) ServeWS(w http.ResponseWriter, r *http.Request) {
	conn, err := websocket.Accept(w, r, &websocket.AcceptOptions{
		// Host proxies WebSocket upgrades over Unix socket with the dashboard's Origin.
		InsecureSkipVerify: true,
	})
	if err != nil {
		return
	}
	defer func() { _ = conn.Close(websocket.StatusNormalClosure, "bye") }()

	ch := make(chan []byte, wsClientBufSize)
	h.mu.Lock()
	if h.closed {
		h.mu.Unlock()
		return
	}
	h.clients[ch] = struct{}{}
	h.mu.Unlock()

	defer func() {
		h.mu.Lock()
		if _, ok := h.clients[ch]; ok {
			delete(h.clients, ch)
			close(ch)
		}
		h.mu.Unlock()
	}()

	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()

	// Drain inbound frames to detect client closure promptly.
	go func() {
		defer cancel()
		for {
			if _, _, err := conn.Read(ctx); err != nil {
				return
			}
		}
	}()

	ticker := time.NewTicker(25 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case msg, ok := <-ch:
			if !ok {
				return
			}
			wctx, wcancel := context.WithTimeout(ctx, 5*time.Second)
			err := conn.Write(wctx, websocket.MessageText, msg)
			wcancel()
			if err != nil {
				return
			}
		case <-ticker.C:
			pctx, pcancel := context.WithTimeout(ctx, 5*time.Second)
			err := conn.Ping(pctx)
			pcancel()
			if err != nil {
				return
			}
		}
	}
}
