package api

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/coder/websocket/wsjson"

	"vram-governor/internal/store"
	"vram-governor/internal/wsproto"
)

func TestNodeWebSocketRequiresBoundNodePlaneCredential(t *testing.T) {
	cfg := &Config{}
	cfg.Auth.Credentials = []CredentialConfig{{ID: "node-a", Token: "node-secret", Plane: "node", OwnerID: "system", NodeID: "node-a", Scopes: []string{"node:connect"}}}
	backing := store.NewMemoryStore()
	server := NewServer(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)), backing, nil, nil)
	httpServer := httptest.NewServer(server.Handler())
	defer httpServer.Close()
	endpoint := "ws" + strings.TrimPrefix(httpServer.URL, "http") + "/ws/node"

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if connection, response, err := websocket.Dial(ctx, endpoint, nil); err == nil || response == nil || response.StatusCode != http.StatusUnauthorized {
		if connection != nil {
			connection.CloseNow()
		}
		t.Fatalf("unauthenticated node websocket was accepted: response=%v err=%v", response, err)
	}

	headers := http.Header{"Authorization": []string{"Bearer node-secret"}}
	wrong, _, err := websocket.Dial(ctx, endpoint, &websocket.DialOptions{HTTPHeader: headers})
	if err != nil {
		t.Fatal(err)
	}
	wrongPayload, _ := json.Marshal(wsproto.RegisterPayload{NodeID: "node-b", NodeName: "wrong"})
	if err := wsjson.Write(ctx, wrong, wsproto.Envelope{Type: wsproto.MsgRegister, Payload: wrongPayload}); err != nil {
		t.Fatal(err)
	}
	var ignored wsproto.Envelope
	if err := wsjson.Read(ctx, wrong, &ignored); websocket.CloseStatus(err) != websocket.StatusPolicyViolation {
		t.Fatalf("credential escaped its node binding: %v", err)
	}
	wrong.CloseNow()

	connection, _, err := websocket.Dial(ctx, endpoint, &websocket.DialOptions{HTTPHeader: headers})
	if err != nil {
		t.Fatal(err)
	}
	defer connection.CloseNow()
	register, _ := json.Marshal(wsproto.RegisterPayload{NodeID: "node-a", NodeName: "authorized", LocationClass: "local", PowerControlMode: "manual"})
	if err := wsjson.Write(ctx, connection, wsproto.Envelope{Type: wsproto.MsgRegister, Payload: register}); err != nil {
		t.Fatal(err)
	}
	var ack wsproto.Envelope
	if err := wsjson.Read(ctx, connection, &ack); err != nil || ack.Type != wsproto.MsgAck {
		t.Fatalf("authorized node did not register: ack=%+v err=%v", ack, err)
	}
	if _, err := backing.GetNode(ctx, "node-a"); err != nil {
		t.Fatalf("authorized registration was not persisted: %v", err)
	}
}
