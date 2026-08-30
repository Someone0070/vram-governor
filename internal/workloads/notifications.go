package workloads

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"vram-governor/internal/domain"
)

type NotificationOptions struct {
	Enabled             bool
	SigningSecret       []byte
	AllowedHosts        []string
	AllowedPrivateCIDRs []string
	AllowHTTP           bool
	MaxAttempts         int
	BaseRetry           time.Duration
	RequestTimeout      time.Duration
	DispatchInterval    time.Duration
}

func DefaultNotificationOptions() NotificationOptions {
	return NotificationOptions{MaxAttempts: 8, BaseRetry: time.Second, RequestTimeout: 10 * time.Second, DispatchInterval: time.Second}
}

func (m *Manager) SetNotificationOptions(options NotificationOptions) error {
	defaults := DefaultNotificationOptions()
	if options.MaxAttempts <= 0 {
		options.MaxAttempts = defaults.MaxAttempts
	}
	if options.BaseRetry <= 0 {
		options.BaseRetry = defaults.BaseRetry
	}
	if options.RequestTimeout <= 0 {
		options.RequestTimeout = defaults.RequestTimeout
	}
	if options.DispatchInterval <= 0 {
		options.DispatchInterval = defaults.DispatchInterval
	}
	if options.Enabled && len(options.SigningSecret) < 16 {
		return fmt.Errorf("notification signing secret must contain at least 16 bytes")
	}
	var allowedNets []*net.IPNet
	for _, raw := range options.AllowedPrivateCIDRs {
		_, block, err := net.ParseCIDR(strings.TrimSpace(raw))
		if err != nil {
			return fmt.Errorf("invalid notification private CIDR %q: %w", raw, err)
		}
		allowedNets = append(allowedNets, block)
	}
	for i, host := range options.AllowedHosts {
		options.AllowedHosts[i] = strings.ToLower(strings.TrimSpace(host))
	}
	m.notificationMu.Lock()
	m.notifications = options
	m.notificationNets = allowedNets
	m.notificationMu.Unlock()
	return nil
}

func (m *Manager) notificationOptions() (NotificationOptions, []*net.IPNet) {
	m.notificationMu.Lock()
	defer m.notificationMu.Unlock()
	options := m.notifications
	options.SigningSecret = append([]byte(nil), options.SigningSecret...)
	nets := append([]*net.IPNet(nil), m.notificationNets...)
	return options, nets
}

func (m *Manager) validateNotificationPreferences(preferences domain.NotificationPreferences) error {
	if len(preferences.Webhooks) == 0 {
		return nil
	}
	options, _ := m.notificationOptions()
	if !options.Enabled {
		return fmt.Errorf("webhook notifications are not enabled")
	}
	for _, destination := range preferences.Webhooks {
		if _, err := validateNotificationDestination(destination, options); err != nil {
			return err
		}
	}
	return nil
}

func validateNotificationDestination(destination string, options NotificationOptions) (*url.URL, error) {
	parsed, err := url.Parse(destination)
	if err != nil || parsed.Hostname() == "" || parsed.User != nil {
		return nil, fmt.Errorf("invalid webhook destination")
	}
	if parsed.Scheme != "https" && !(options.AllowHTTP && parsed.Scheme == "http") {
		return nil, fmt.Errorf("webhook destination must use HTTPS")
	}
	if parsed.Fragment != "" {
		return nil, fmt.Errorf("webhook destination may not contain a fragment")
	}
	host := strings.ToLower(parsed.Hostname())
	hostPort := strings.ToLower(parsed.Host)
	allowed := false
	for _, configured := range options.AllowedHosts {
		if configured == host || configured == hostPort {
			allowed = true
			break
		}
	}
	if !allowed {
		return nil, fmt.Errorf("webhook destination host %q is not allowlisted", host)
	}
	return parsed, nil
}

func resolveNotificationDestination(ctx context.Context, parsed *url.URL, allowedNets []*net.IPNet) ([]net.IP, error) {
	host := parsed.Hostname()
	var ips []net.IP
	if direct := net.ParseIP(host); direct != nil {
		ips = []net.IP{direct}
	} else {
		resolved, err := net.DefaultResolver.LookupIP(ctx, "ip", host)
		if err != nil {
			return nil, fmt.Errorf("resolve webhook destination: %w", err)
		}
		ips = resolved
	}
	if len(ips) == 0 {
		return nil, fmt.Errorf("webhook destination resolved to no addresses")
	}
	for _, ip := range ips {
		if !restrictedNotificationIP(ip) {
			continue
		}
		allowed := false
		for _, block := range allowedNets {
			if block.Contains(ip) {
				allowed = true
				break
			}
		}
		if !allowed {
			return nil, fmt.Errorf("webhook destination resolved to forbidden address %s", ip)
		}
	}
	return ips, nil
}

func restrictedNotificationIP(ip net.IP) bool {
	return ip.IsPrivate() || ip.IsLoopback() || ip.IsUnspecified() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsMulticast()
}

func (m *Manager) enqueueNotification(ctx context.Context, workload *domain.Workload, eventType string) {
	if workload == nil || len(workload.Request.Notifications.Webhooks) == 0 {
		return
	}
	now := time.Now().UTC()
	payload, _ := json.Marshal(map[string]any{
		"event": eventType, "workload_id": workload.Request.ID, "owner_id": workload.Request.OwnerID,
		"adapter": workload.Request.Adapter, "status": workload.Status, "timestamp": now,
	})
	for _, destination := range workload.Request.Notifications.Webhooks {
		keyMaterial := workload.Request.ID + "\x00" + eventType + "\x00" + destination
		sum := sha256.Sum256([]byte(keyMaterial))
		key := hex.EncodeToString(sum[:])
		delivery := &domain.NotificationDelivery{
			ID: "ntf-" + key[:24], IdempotencyKey: key, WorkloadID: workload.Request.ID,
			OwnerID: workload.Request.OwnerID, EventType: eventType, Destination: destination,
			Payload: payload, NextAttemptAt: now, CreatedAt: now, UpdatedAt: now,
		}
		if _, created, err := m.store.CreateNotification(ctx, delivery); err != nil {
			m.log.Warn("enqueue webhook notification", "workload", workload.Request.ID, "event", eventType, "err", err)
		} else if created {
			m.signal()
		}
	}
}

func (m *Manager) notificationLoop(ctx context.Context) {
	options, _ := m.notificationOptions()
	interval := options.DispatchInterval
	if interval <= 0 {
		interval = time.Second
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			m.dispatchNotifications(ctx)
		}
	}
}

func (m *Manager) dispatchNotifications(ctx context.Context) {
	options, allowedNets := m.notificationOptions()
	if !options.Enabled {
		return
	}
	rows, err := m.store.ListPendingNotifications(ctx, time.Now().UTC(), 100)
	if err != nil {
		m.log.Warn("list pending notifications", "err", err)
		return
	}
	for _, delivery := range rows {
		m.deliverNotification(ctx, delivery, options, allowedNets)
	}
}

func (m *Manager) deliverNotification(ctx context.Context, delivery *domain.NotificationDelivery, options NotificationOptions, allowedNets []*net.IPNet) {
	delivery.Attempts++
	delivery.UpdatedAt = time.Now().UTC()
	parsed, err := validateNotificationDestination(delivery.Destination, options)
	var ips []net.IP
	if err == nil {
		resolveCtx, cancel := context.WithTimeout(ctx, options.RequestTimeout)
		ips, err = resolveNotificationDestination(resolveCtx, parsed, allowedNets)
		cancel()
	}
	if err == nil {
		timestamp := strconv.FormatInt(time.Now().UTC().Unix(), 10)
		mac := hmac.New(sha256.New, options.SigningSecret)
		_, _ = mac.Write([]byte(timestamp + "."))
		_, _ = mac.Write(delivery.Payload)
		delivery.Signature = "sha256=" + hex.EncodeToString(mac.Sum(nil))
		err = postPinnedWebhook(ctx, parsed, ips[0], delivery, timestamp, options.RequestTimeout)
	}
	now := time.Now().UTC()
	delivery.UpdatedAt = now
	if err == nil {
		delivery.DeliveredAt = &now
		delivery.LastError = ""
		_, _ = m.store.UpdateNotification(context.Background(), delivery)
		m.auditActor(context.Background(), "notification-dispatcher", delivery.OwnerID, delivery.WorkloadID, "notification.delivered", "info", map[string]any{"notification_id": delivery.ID, "event": delivery.EventType, "attempts": delivery.Attempts})
		return
	}
	delivery.LastError = err.Error()
	if delivery.Attempts >= options.MaxAttempts {
		delivery.FailedAt = &now
		m.auditActor(context.Background(), "notification-dispatcher", delivery.OwnerID, delivery.WorkloadID, "notification.failed", "error", map[string]any{"notification_id": delivery.ID, "event": delivery.EventType, "attempts": delivery.Attempts, "error": delivery.LastError})
	} else {
		delay := options.BaseRetry
		for attempt := 1; attempt < delivery.Attempts && delay < time.Hour; attempt++ {
			delay *= 2
		}
		if delay > time.Hour {
			delay = time.Hour
		}
		delivery.NextAttemptAt = now.Add(delay)
	}
	_, _ = m.store.UpdateNotification(context.Background(), delivery)
}

func postPinnedWebhook(ctx context.Context, destination *url.URL, ip net.IP, delivery *domain.NotificationDelivery, timestamp string, timeout time.Duration) error {
	port := destination.Port()
	if port == "" {
		if destination.Scheme == "https" {
			port = "443"
		} else {
			port = "80"
		}
	}
	dialer := &net.Dialer{Timeout: timeout}
	transport := &http.Transport{
		Proxy: nil,
		DialContext: func(dialCtx context.Context, network, _ string) (net.Conn, error) {
			return dialer.DialContext(dialCtx, network, net.JoinHostPort(ip.String(), port))
		},
		TLSClientConfig: &tls.Config{ServerName: destination.Hostname(), MinVersion: tls.VersionTLS12},
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: timeout, CheckRedirect: func(*http.Request, []*http.Request) error { return fmt.Errorf("webhook redirects are forbidden") }}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, destination.String(), bytes.NewReader(delivery.Payload))
	if err != nil {
		return err
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-VRAM-Event", delivery.EventType)
	request.Header.Set("X-VRAM-Delivery", delivery.ID)
	request.Header.Set("X-VRAM-Timestamp", timestamp)
	request.Header.Set("X-VRAM-Signature", delivery.Signature)
	response, err := client.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		message, _ := io.ReadAll(io.LimitReader(response.Body, 1024))
		return fmt.Errorf("webhook returned %d: %s", response.StatusCode, strings.TrimSpace(string(message)))
	}
	return nil
}

func (m *Manager) ListNotifications(ctx context.Context, ownerID string, limit int) ([]*domain.NotificationDelivery, error) {
	return m.store.ListNotifications(ctx, ownerID, limit)
}
