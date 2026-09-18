package scheduler

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"
	"time"
)

func TestQuotaExhaustionFromPayload(t *testing.T) {
	reset := time.Now().Add(time.Hour).UTC().Truncate(time.Second)
	payload := map[string]any{
		"windowLimits": map[string]any{
			"fiveHour": map[string]any{
				"exceeded": true,
				"resetAt":  reset.Format(time.RFC3339),
			},
			"weekly": map[string]any{
				"exceeded": false,
			},
		},
	}
	exhausted, resetAt, ok := quotaExhaustionFromPayload(payload)
	if !ok || !exhausted {
		t.Fatalf("expected exhausted quota, got exhausted=%v ok=%v", exhausted, ok)
	}
	if resetAt != reset.UnixMilli() {
		t.Fatalf("resetAt=%d want=%d", resetAt, reset.UnixMilli())
	}
}

func TestQuotaExhaustionFromPayloadAvailable(t *testing.T) {
	payload := map[string]any{
		"windowLimits": map[string]any{
			"fiveHour": map[string]any{"exceeded": false},
			"weekly":   map[string]any{"exceeded": false},
		},
	}
	exhausted, resetAt, ok := quotaExhaustionFromPayload(payload)
	if !ok || exhausted || resetAt != 0 {
		t.Fatalf("unexpected quota state exhausted=%v resetAt=%d ok=%v", exhausted, resetAt, ok)
	}
}

func TestStableAuthIndexMatchesCPA(t *testing.T) {
	seed := "commandcode-provider:auth-v1:group:key"
	sum := sha256.Sum256([]byte("auth_index_seed:" + seed))
	want := hex.EncodeToString(sum[:8])
	if got := stableAuthIndex("auth_index_seed:" + seed); got != want {
		t.Fatalf("stableAuthIndex=%q want=%q", got, want)
	}
}
