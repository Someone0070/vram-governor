package jobs

import (
	"encoding/json"
	"testing"
)

func TestPositiveIntAcceptsDecodedJSONNumber(t *testing.T) {
	for _, value := range []any{float64(257), json.Number("258"), int64(259), 260} {
		got, ok := positiveInt(value)
		if !ok || got < 257 || got > 260 {
			t.Fatalf("positiveInt(%T(%v)) = %d,%v", value, value, got, ok)
		}
	}
	for _, value := range []any{float64(1.5), float64(-1), json.Number("bad"), nil} {
		if _, ok := positiveInt(value); ok {
			t.Fatalf("positiveInt unexpectedly accepted %T(%v)", value, value)
		}
	}
}
