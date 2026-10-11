package nodetransport

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"
)

type receivingSide uint8

const (
	serverReceives receivingSide = iota
	clientReceives
)

func TestControlMessageLimitIsFiniteFourMiB(t *testing.T) {
	if ControlMessageLimit != 4*1024*1024 || ControlMessageLimit <= 0 {
		t.Fatalf("control message limit=%d, want finite 4 MiB", ControlMessageLimit)
	}
}

func TestDefaultReadLimitRejectsLegitimate64KiBControlJSON(t *testing.T) {
	if err := exchangeJSON(t, serverReceives, false, jsonMessage(64*1024), true); err != nil {
		t.Fatal(err)
	}
}

func TestSharedLimitAcceptsLegitimateLargeControlJSONBothDirections(t *testing.T) {
	payload := jsonMessage(64 * 1024)
	for _, side := range []receivingSide{serverReceives, clientReceives} {
		t.Run(side.name(), func(t *testing.T) {
			if err := exchangeJSON(t, side, true, payload, false); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestSharedLimitAllowsExactBoundaryBothDirections(t *testing.T) {
	payload := jsonMessage(int(ControlMessageLimit))
	for _, side := range []receivingSide{serverReceives, clientReceives} {
		t.Run(side.name(), func(t *testing.T) {
			if err := exchangeJSON(t, side, true, payload, false); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestSharedLimitRejectsBoundaryPlusOneBothDirections(t *testing.T) {
	payload := jsonMessage(int(ControlMessageLimit + 1))
	for _, side := range []receivingSide{serverReceives, clientReceives} {
		t.Run(side.name(), func(t *testing.T) {
			if err := exchangeJSON(t, side, true, payload, true); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestOversizeRejectionLeavesReconnectUsable(t *testing.T) {
	tooLarge := jsonMessage(int(ControlMessageLimit + 1))
	normal := jsonMessage(256)
	for _, side := range []receivingSide{serverReceives, clientReceives} {
		t.Run(side.name(), func(t *testing.T) {
			if err := exchangeJSON(t, side, true, tooLarge, true); err != nil {
				t.Fatal(err)
			}
			if err := exchangeJSON(t, side, true, normal, false); err != nil {
				t.Fatalf("fresh connection failed after the bounded rejection: %v", err)
			}
		})
	}
}

func (side receivingSide) name() string {
	if side == serverReceives {
		return "client-to-server"
	}
	return "server-to-client"
}

func jsonMessage(size int) []byte {
	const prefix, suffix = `{"data":"`, `"}`
	if size < len(prefix)+len(suffix) {
		panic("test JSON message size is too small")
	}
	message := make([]byte, size)
	copy(message, prefix)
	for index := len(prefix); index < size-len(suffix); index++ {
		message[index] = 'x'
	}
	copy(message[size-len(suffix):], suffix)
	return message
}

func exchangeJSON(t *testing.T, side receivingSide, applySharedLimit bool, payload []byte, wantTooBig bool) error {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	serverResult := make(chan error, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := websocket.Accept(w, r, nil)
		if err != nil {
			serverResult <- fmt.Errorf("accept websocket: %w", err)
			return
		}
		defer conn.CloseNow()
		if applySharedLimit && side == serverReceives {
			ApplyControlMessageLimit(conn)
		}
		if side == clientReceives {
			if err := conn.Write(ctx, websocket.MessageText, payload); err != nil && !wantTooBig {
				serverResult <- fmt.Errorf("write server message: %w", err)
				return
			} else if err != nil && websocket.CloseStatus(err) != websocket.StatusMessageTooBig {
				serverResult <- fmt.Errorf("unexpected server write error after client read-limit rejection: %w", err)
				return
			}
			serverResult <- nil
			return
		}
		_, received, err := conn.Read(ctx)
		if wantTooBig {
			if !errors.Is(err, websocket.ErrMessageTooBig) {
				serverResult <- fmt.Errorf("server receiver error=%v, want ErrMessageTooBig", err)
				return
			}
			serverResult <- nil
			return
		}
		if err != nil {
			serverResult <- fmt.Errorf("read client message: %w", err)
			return
		}
		if !bytes.Equal(received, payload) {
			serverResult <- errors.New("server received a different control message")
			return
		}
		serverResult <- nil
	}))
	defer server.Close()

	url := "ws" + strings.TrimPrefix(server.URL, "http")
	client, _, err := websocket.Dial(ctx, url, nil)
	if err != nil {
		return fmt.Errorf("dial websocket: %w", err)
	}
	defer client.CloseNow()
	if applySharedLimit && side == clientReceives {
		ApplyControlMessageLimit(client)
	}

	if side == serverReceives {
		writeErr := client.Write(ctx, websocket.MessageText, payload)
		if writeErr != nil && !wantTooBig {
			return fmt.Errorf("write client message: %w", writeErr)
		}
	} else {
		_, received, readErr := client.Read(ctx)
		if wantTooBig {
			if !errors.Is(readErr, websocket.ErrMessageTooBig) {
				return fmt.Errorf("client receiver error=%v, want ErrMessageTooBig", readErr)
			}
		} else if readErr != nil {
			return fmt.Errorf("read server message: %w", readErr)
		} else if !bytes.Equal(received, payload) {
			return errors.New("client received a different control message")
		}
	}

	select {
	case serverErr := <-serverResult:
		if serverErr != nil {
			return serverErr
		}
		return nil
	case <-ctx.Done():
		return fmt.Errorf("websocket exchange exceeded its bound: %w", ctx.Err())
	}
}
