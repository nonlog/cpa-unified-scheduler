package scheduler

import (
	"net/http"
	"testing"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
)

func TestPersonaColdDelegatesAndThenSticks(t *testing.T) {
	a := newAffinityController(personaProvider, personaAffinityHeader, false, false)
	req := pluginapi.SchedulerPickRequest{
		Provider: personaProvider,
		Model:    "test-model",
		Options: pluginapi.SchedulerOptions{
			Headers: http.Header{"Session-Id": {"persona-session-a"}},
		},
		Candidates: []pluginapi.SchedulerAuthCandidate{
			testCandidate(personaProvider, "persona-provider:auth-v2:g:1", "1", "g", "round-robin"),
			testCandidate(personaProvider, "persona-provider:auth-v2:g:2", "2", "g", "round-robin"),
		},
	}

	first := a.pick(req)
	if !first.Handled || first.DelegateBuiltin != pluginapi.SchedulerBuiltinRoundRobin || first.AuthID != "" {
		t.Fatalf("cold Persona pick = %#v", first)
	}

	identity := deriveAffinityIdentity(req.Options.Metadata, req.Options.Headers, nil, false, "cpa-unified-persona-affinity")
	a.mu.Lock()
	for _, c := range req.Candidates {
		a.descriptors[c.ID] = affinityPolicyFromAttributes(c.Attributes)
	}
	a.mu.Unlock()

	a.complete(identity, req.Model, req.Candidates[1].ID, pluginapi.RequestCompletion{
		Outcome:     pluginapi.RequestCompletionSucceeded,
		CompletedAt: time.Now(),
	})

	second := a.pick(req)
	if !second.Handled || second.AuthID != req.Candidates[1].ID {
		t.Fatalf("bound Persona pick = %#v", second)
	}
}

func TestCommandCodeColdRoundRobinAndAffinity(t *testing.T) {
	a := newAffinityController(commandCodeProvider, commandAffinityHeader, true, true)
	candidates := []pluginapi.SchedulerAuthCandidate{
		testCandidate(commandCodeProvider, "commandcode-provider:auth-v1:g:1", "1", "g", "round-robin"),
		testCandidate(commandCodeProvider, "commandcode-provider:auth-v1:g:2", "2", "g", "round-robin"),
	}

	req1 := pluginapi.SchedulerPickRequest{
		Provider: commandCodeProvider,
		Model:    "test-model",
		Options: pluginapi.SchedulerOptions{
			Metadata: map[string]any{"session_id": "session-a"},
		},
		Candidates: candidates,
	}
	req2 := req1
	req2.Options.Metadata = map[string]any{"session_id": "session-b"}

	first := a.pick(req1)
	if !first.Handled || first.AuthID != candidates[0].ID {
		t.Fatalf("first cold Command Code pick = %#v", first)
	}
	repeat := a.pick(req1)
	if repeat.AuthID != first.AuthID {
		t.Fatalf("same session changed key: first=%#v repeat=%#v", first, repeat)
	}
	second := a.pick(req2)
	if !second.Handled || second.AuthID != candidates[1].ID {
		t.Fatalf("second cold Command Code pick = %#v", second)
	}
}

func TestCommandCodeExplicitSelector(t *testing.T) {
	a := newAffinityController(commandCodeProvider, commandAffinityHeader, true, true)
	candidates := []pluginapi.SchedulerAuthCandidate{
		testCandidate(commandCodeProvider, "commandcode-provider:auth-v1:g:1", "1", "g", "round-robin"),
		testCandidate(commandCodeProvider, "commandcode-provider:auth-v1:g:2", "2", "g", "round-robin"),
	}
	req := pluginapi.SchedulerPickRequest{
		Provider:   commandCodeProvider,
		Candidates: candidates,
		Options: pluginapi.SchedulerOptions{
			Headers: selectorHeaders("2"),
		},
	}
	got := a.pick(req)
	if !got.Handled || got.AuthID != candidates[1].ID {
		t.Fatalf("explicit selector pick = %#v", got)
	}
}

func TestStrictUnavailableHonorsFailoverFalse(t *testing.T) {
	a := newAffinityController(personaProvider, personaAffinityHeader, false, false)
	candidate := testCandidate(personaProvider, "persona-provider:auth-v2:g:1", "1", "g", "round-robin")
	candidate.Attributes["key_affinity_failover_unavailable"] = "false"

	req := pluginapi.SchedulerPickRequest{
		Provider: personaProvider,
		Model:    "test-model",
		Options: pluginapi.SchedulerOptions{
			Headers: http.Header{"Session-Id": {"strict-session"}},
		},
		Candidates: []pluginapi.SchedulerAuthCandidate{candidate},
	}
	identity := deriveAffinityIdentity(req.Options.Metadata, req.Options.Headers, nil, false, "cpa-unified-persona-affinity")
	policy := affinityPolicyFromAttributes(candidate.Attributes)
	key := affinityBindingKey(policy, identity, req.Model)
	a.mu.Lock()
	a.descriptors[candidate.ID] = policy
	a.bindings[key] = affinityBinding{
		AuthID:    "persona-provider:auth-v2:g:missing",
		ExpiresAt: time.Now().Add(time.Minute),
		Policy:    policy,
	}
	a.mu.Unlock()

	if !a.strictUnavailable(req) {
		t.Fatal("strict unavailable binding was not rejected")
	}
}

func testCandidate(provider, id, keyID, group, strategy string) pluginapi.SchedulerAuthCandidate {
	return pluginapi.SchedulerAuthCandidate{
		Provider: provider,
		ID:       id,
		Attributes: map[string]string{
			"provider_group":                    group,
			"key_id":                            keyID,
			"weight":                            "1",
			"routing_strategy":                  strategy,
			"key_affinity_enabled":              "true",
			"key_affinity_ttl_seconds":          "600",
			"key_affinity_refresh_on_success":   "true",
			"key_affinity_failover_unavailable": "true",
			"key_affinity_include_model":        "false",
		},
	}
}

func selectorHeaders(value string) http.Header {
	h := make(http.Header)
	h.Set(commandSelectorHeader, value)
	return h
}


func TestRegistrationDoesNotExposeGlobalRequestInterceptor(t *testing.T) {
	registration := pluginRegistration()
	if !registration.Capabilities.Scheduler {
		t.Fatal("scheduler capability is disabled")
	}
	if registration.Capabilities.RequestInterceptor {
		t.Fatal("request interceptor must stay disabled to avoid copying every model request body through the plugin ABI")
	}
	if !registration.Capabilities.RequestLifecyclePlugin {
		t.Fatal("request lifecycle capability is required for affinity completion")
	}
}

func TestPersonaLifecycleBindsFromCanonicalMetadataWithoutInterceptor(t *testing.T) {
	adapter := New(nil)
	candidates := []pluginapi.SchedulerAuthCandidate{
		testCandidate(personaProvider, "persona-provider:auth-v2:g:1", "1", "g", "round-robin"),
		testCandidate(personaProvider, "persona-provider:auth-v2:g:2", "2", "g", "round-robin"),
	}
	req := pluginapi.SchedulerPickRequest{
		Provider: personaProvider,
		Model:    "test-model",
		Options: pluginapi.SchedulerOptions{
			Metadata: map[string]any{"canonical_session_id": "header:persona-session-a"},
		},
		Candidates: candidates,
	}

	first, err := adapter.pick(req)
	if err != nil {
		t.Fatalf("cold pick failed: %v", err)
	}
	if !first.Handled || first.DelegateBuiltin != pluginapi.SchedulerBuiltinRoundRobin {
		t.Fatalf("cold pick = %#v", first)
	}

	adapter.complete(pluginapi.RequestCompletion{
		Model:       req.Model,
		Outcome:     pluginapi.RequestCompletionSucceeded,
		CompletedAt: time.Now(),
		Metadata: map[string]any{
			"selected_auth_id":       candidates[1].ID,
			"selected_auth_provider": personaProvider,
			"canonical_session_id":   "header:persona-session-a",
		},
	})

	second, err := adapter.pick(req)
	if err != nil {
		t.Fatalf("bound pick failed: %v", err)
	}
	if !second.Handled || second.AuthID != candidates[1].ID {
		t.Fatalf("lifecycle-only affinity did not bind selected auth: %#v", second)
	}
}

func TestAffinityIdentityRecognizesPiSessionHeaders(t *testing.T) {
	for _, header := range []string{"X-Session-Affinity", "X-Session-Id", "Session_id"} {
		headers := make(http.Header)
		headers.Set(header, "pi-session-a")
		got := deriveAffinityIdentity(nil, headers, nil, false, "test-salt")
		if got == "" {
			t.Fatalf("%s did not produce an affinity identity", header)
		}
	}
}
