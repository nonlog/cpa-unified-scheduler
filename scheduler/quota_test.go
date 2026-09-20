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

func TestQuotaExhaustionFromZeroUsableBalance(t *testing.T) {
	payload := map[string]any{
		"credits": map[string]any{
			"monthlyCredits":   float64(0),
			"purchasedCredits": float64(0),
			"freeCredits":      float64(0),
		},
	}
	exhausted, resetAt, ok := quotaExhaustionFromPayload(payload)
	if !ok || !exhausted || resetAt != 0 {
		t.Fatalf("expected zero balance exhaustion, got exhausted=%v resetAt=%d ok=%v", exhausted, resetAt, ok)
	}
}

func TestQuotaZeroBalanceDoesNotOverrideHealthyWindows(t *testing.T) {
	payload := map[string]any{
		"credits": map[string]any{
			"monthlyCredits":   float64(0),
			"purchasedCredits": float64(0),
			"freeCredits":      float64(0),
		},
		"windowLimits": map[string]any{
			"fiveHour": map[string]any{"used": float64(1), "cap": float64(3), "exceeded": false},
			"weekly":   map[string]any{"used": float64(2), "cap": float64(6), "exceeded": false},
		},
	}
	exhausted, resetAt, ok := quotaExhaustionFromPayload(payload)
	if !ok || exhausted || resetAt != 0 {
		t.Fatalf("healthy windows must take precedence over zero balance: exhausted=%v resetAt=%d ok=%v", exhausted, resetAt, ok)
	}
}

func TestQuotaExhaustionAllowsExtraCredits(t *testing.T) {
	for name, credits := range map[string]map[string]any{
		"purchased": {"monthlyCredits": float64(0), "purchasedCredits": 1.25, "freeCredits": float64(0)},
		"free":      {"monthlyCredits": float64(0), "purchasedCredits": float64(0), "freeCredits": 0.5},
	} {
		t.Run(name, func(t *testing.T) {
			exhausted, resetAt, ok := quotaExhaustionFromPayload(map[string]any{"credits": credits})
			if !ok || exhausted || resetAt != 0 {
				t.Fatalf("unexpected state exhausted=%v resetAt=%d ok=%v", exhausted, resetAt, ok)
			}
		})
	}
}

func TestQuotaExhaustionMissingSignalsIsUnknown(t *testing.T) {
	exhausted, resetAt, ok := quotaExhaustionFromPayload(map[string]any{"credits": map[string]any{"planId": "individual-go"}})
	if ok || exhausted || resetAt != 0 {
		t.Fatalf("unexpected state exhausted=%v resetAt=%d ok=%v", exhausted, resetAt, ok)
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
