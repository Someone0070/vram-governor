package workloads

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"vram-governor/internal/domain"
	"vram-governor/internal/store"
)

func TestSignedWebhookRetriesFromDurableOutbox(t *testing.T) {
	secret := []byte("0123456789abcdef0123456789abcdef")
	var attempts atomic.Int32
	received := make(chan bool, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		call := attempts.Add(1)
		if call == 1 {
			http.Error(w, "retry", http.StatusServiceUnavailable)
			return
		}
		mac := hmac.New(sha256.New, secret)
		_, _ = mac.Write([]byte(r.Header.Get("X-VRAM-Timestamp") + "."))
		_, _ = mac.Write(body)
		valid := hmac.Equal([]byte(r.Header.Get("X-VRAM-Signature")), []byte("sha256="+hex.EncodeToString(mac.Sum(nil))))
		select {
		case received <- valid && r.Header.Get("X-VRAM-Delivery") != "":
		default:
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	parsed, _ := url.Parse(server.URL)
	backing := store.NewMemoryStore()
	mgr := NewManager(quietLogger(), backing, time.Second)
	if err := mgr.SetNotificationOptions(NotificationOptions{Enabled: true, SigningSecret: secret, AllowedHosts: []string{parsed.Host}, AllowedPrivateCIDRs: []string{"127.0.0.0/8"}, AllowHTTP: true, MaxAttempts: 3, BaseRetry: time.Millisecond, RequestTimeout: time.Second, DispatchInterval: time.Millisecond}); err != nil {
		t.Fatal(err)
	}
	mgr.RegisterAdapter(NewMockAdapter())
	mgr.RegisterTarget(Target{ID: "mock", Adapter: "mock", Endpoint: "in-process", Enabled: true})
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	mgr.Start(ctx)
	workload, _, err := mgr.Submit(ctx, domain.WorkloadRequest{OwnerID: "alice", Adapter: "mock", Payload: json.RawMessage(`{"secret_prompt":"must-not-leak"}`), Notifications: domain.NotificationPreferences{Webhooks: []string{server.URL}, OnFinish: true}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := mgr.Wait(ctx, workload.Request.ID); err != nil {
		t.Fatal(err)
	}
	select {
	case valid := <-received:
		if !valid {
			t.Fatal("webhook signature or delivery identity was invalid")
		}
	case <-ctx.Done():
		t.Fatal("webhook was not delivered after retry")
	}
	var rows []*domain.NotificationDelivery
	var listErr error
	durableDeadline := time.Now().Add(time.Second)
	for time.Now().Before(durableDeadline) {
		rows, listErr = backing.ListNotifications(context.Background(), "alice", 10)
		if listErr == nil && len(rows) == 1 && rows[0].DeliveredAt != nil && rows[0].Attempts == 2 {
			break
		}
		time.Sleep(time.Millisecond)
	}
	if listErr != nil || len(rows) != 1 || rows[0].DeliveredAt == nil || rows[0].Attempts != 2 {
		t.Fatalf("durable delivery state: rows=%+v err=%v", rows, listErr)
	}
	if strings.Contains(string(rows[0].Payload), "must-not-leak") {
		t.Fatal("workload payload leaked into webhook notification")
	}
}

func TestWebhookSSRFProtectionRejectsPrivateAddressBeforeDial(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls.Add(1) }))
	defer server.Close()
	parsed, _ := url.Parse(server.URL)
	backing := store.NewMemoryStore()
	mgr := NewManager(quietLogger(), backing, time.Second)
	if err := mgr.SetNotificationOptions(NotificationOptions{Enabled: true, SigningSecret: []byte("0123456789abcdef"), AllowedHosts: []string{parsed.Host}, AllowHTTP: true, MaxAttempts: 1, RequestTimeout: time.Second}); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	delivery := &domain.NotificationDelivery{ID: "n", IdempotencyKey: "n", WorkloadID: "w", OwnerID: "alice", EventType: "workload.failed", Destination: server.URL, Payload: json.RawMessage(`{"event":"workload.failed"}`), NextAttemptAt: now, CreatedAt: now, UpdatedAt: now}
	_, _, _ = backing.CreateNotification(context.Background(), delivery)
	mgr.dispatchNotifications(context.Background())
	rows, _ := backing.ListNotifications(context.Background(), "alice", 10)
	if calls.Load() != 0 || len(rows) != 1 || rows[0].FailedAt == nil || !strings.Contains(rows[0].LastError, "forbidden address") {
		t.Fatalf("private destination was not blocked: calls=%d rows=%+v", calls.Load(), rows)
	}
}

func TestWebhookHostMustBeAllowlistedAtSubmission(t *testing.T) {
	mgr := NewManager(quietLogger(), store.NewMemoryStore(), time.Second)
	_ = mgr.SetNotificationOptions(NotificationOptions{Enabled: true, SigningSecret: []byte("0123456789abcdef"), AllowedHosts: []string{"hooks.example.com"}})
	mgr.RegisterAdapter(NewMockAdapter())
	_, _, err := mgr.Submit(context.Background(), domain.WorkloadRequest{OwnerID: "alice", Adapter: "mock", Payload: json.RawMessage(`{"prompt":"hi"}`), Notifications: domain.NotificationPreferences{Webhooks: []string{"https://evil.example/receive"}, OnFinish: true}})
	if err == nil || !strings.Contains(err.Error(), "not allowlisted") {
		t.Fatalf("unexpected submission result: %v", err)
	}
}
