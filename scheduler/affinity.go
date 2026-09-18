package scheduler

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
)

const (
	defaultAffinityTTLSeconds = 600
	maxAffinityEntries        = 100000
)

type affinityPolicy struct {
	GroupID               string
	Strategy              string
	Enabled               bool
	TTLSeconds            int
	RefreshOnSuccess      bool
	FailoverOnUnavailable bool
	IncludeModel          bool
}

type affinityBinding struct {
	AuthID      string
	ExpiresAt   time.Time
	Policy      affinityPolicy
	Provisional bool
}

type affinityController struct {
	provider           string
	header             string
	allowDerived       bool
	selectColdDirectly bool

	mu          sync.Mutex
	bindings    map[string]affinityBinding
	descriptors map[string]affinityPolicy
	cursors     map[string]uint64
}

func newAffinityController(provider, header string, allowDerived, selectColdDirectly bool) *affinityController {
	return &affinityController{
		provider:           provider,
		header:             header,
		allowDerived:       allowDerived,
		selectColdDirectly: selectColdDirectly,
		bindings:           make(map[string]affinityBinding),
		descriptors:        make(map[string]affinityPolicy),
		cursors:            make(map[string]uint64),
	}
}

func (a *affinityController) pick(req pluginapi.SchedulerPickRequest) pluginapi.SchedulerPickResponse {
	if a == nil || len(req.Candidates) == 0 || candidateProvider(req.Candidates) != a.provider {
		return pluginapi.SchedulerPickResponse{Handled: false}
	}

	if a.provider == commandCodeProvider {
		selector := strings.TrimSpace(firstHeader(req.Options.Headers, commandSelectorHeader))
		if selector != "" && !strings.EqualFold(selector, "auto") {
			for _, candidate := range req.Candidates {
				if strings.EqualFold(strings.TrimSpace(candidate.Attributes["key_id"]), selector) {
					return pluginapi.SchedulerPickResponse{AuthID: candidate.ID, Handled: true}
				}
			}
			return pluginapi.SchedulerPickResponse{Handled: false}
		}
	}

	now := time.Now()
	identity := strings.TrimSpace(firstHeader(req.Options.Headers, a.header))
	if identity == "" {
		identity = deriveAffinityIdentity(req.Options.Metadata, req.Options.Headers, nil, a.allowDerived, "cpa-unified-"+a.provider+"-affinity")
	}

	a.mu.Lock()
	defer a.mu.Unlock()
	a.cleanupExpiredLocked(now)

	candidateIDs := make(map[string]struct{}, len(req.Candidates))
	groups := make(map[string]affinityPolicy)
	for _, candidate := range req.Candidates {
		candidateIDs[candidate.ID] = struct{}{}
		policy := affinityPolicyFromAttributes(candidate.Attributes)
		if policy.GroupID == "" {
			continue
		}
		a.descriptors[candidate.ID] = policy
		groups[policy.GroupID] = policy
	}
	a.trimLocked()

	if identity != "" {
		for _, policy := range groups {
			if !policy.Enabled {
				continue
			}
			key := affinityBindingKey(policy, identity, req.Model)
			binding, ok := a.bindings[key]
			if !ok {
				continue
			}
			if _, available := candidateIDs[binding.AuthID]; available {
				if a.provider == commandCodeProvider && policy.RefreshOnSuccess {
					binding.ExpiresAt = now.Add(time.Duration(policy.TTLSeconds) * time.Second)
					a.bindings[key] = binding
				}
				return pluginapi.SchedulerPickResponse{AuthID: binding.AuthID, Handled: true}
			}
			if policy.FailoverOnUnavailable {
				delete(a.bindings, key)
			}
		}
	}

	if len(groups) != 1 {
		return pluginapi.SchedulerPickResponse{Handled: false}
	}

	for _, policy := range groups {
		if !policy.Enabled || identity == "" {
			return pluginapi.SchedulerPickResponse{
				Handled:         true,
				DelegateBuiltin: builtinForStrategy(policy.Strategy),
			}
		}

		if !a.selectColdDirectly {
			return pluginapi.SchedulerPickResponse{
				Handled:         true,
				DelegateBuiltin: builtinForStrategy(policy.Strategy),
			}
		}

		selected := a.nextCandidateLocked(policy, req.Candidates, req.Model)
		if selected == "" {
			return pluginapi.SchedulerPickResponse{
				Handled:         true,
				DelegateBuiltin: builtinForStrategy(policy.Strategy),
			}
		}
		key := affinityBindingKey(policy, identity, req.Model)
		a.bindings[key] = affinityBinding{
			AuthID:      selected,
			ExpiresAt:   now.Add(time.Duration(policy.TTLSeconds) * time.Second),
			Policy:      policy,
			Provisional: true,
		}
		a.trimLocked()
		return pluginapi.SchedulerPickResponse{AuthID: selected, Handled: true}
	}

	return pluginapi.SchedulerPickResponse{Handled: false}
}

func (a *affinityController) strictUnavailable(req pluginapi.SchedulerPickRequest) bool {
	if a == nil || candidateProvider(req.Candidates) != a.provider {
		return false
	}
	if a.provider == commandCodeProvider {
		selector := strings.TrimSpace(firstHeader(req.Options.Headers, commandSelectorHeader))
		if selector != "" && !strings.EqualFold(selector, "auto") {
			return false
		}
	}

	identity := strings.TrimSpace(firstHeader(req.Options.Headers, a.header))
	if identity == "" {
		identity = deriveAffinityIdentity(req.Options.Metadata, req.Options.Headers, nil, a.allowDerived, "cpa-unified-"+a.provider+"-affinity")
	}
	if identity == "" {
		return false
	}

	a.mu.Lock()
	defer a.mu.Unlock()

	available := make(map[string]bool, len(req.Candidates))
	for _, candidate := range req.Candidates {
		available[candidate.ID] = true
	}
	for _, candidate := range req.Candidates {
		policy := affinityPolicyFromAttributes(candidate.Attributes)
		if policy.GroupID == "" || !policy.Enabled || policy.FailoverOnUnavailable {
			continue
		}
		binding, ok := a.bindings[affinityBindingKey(policy, identity, req.Model)]
		if ok && binding.ExpiresAt.After(time.Now()) && !available[binding.AuthID] {
			return true
		}
	}
	return false
}

func (a *affinityController) complete(identity, model, authID string, completion pluginapi.RequestCompletion) {
	if a == nil || identity == "" || authID == "" {
		return
	}

	a.mu.Lock()
	defer a.mu.Unlock()

	policy, ok := a.descriptors[authID]
	if !ok || !policy.Enabled {
		return
	}

	key := affinityBindingKey(policy, identity, model)
	existing, exists := a.bindings[key]

	if completion.Outcome != pluginapi.RequestCompletionSucceeded {
		if exists && existing.AuthID == authID && existing.Provisional {
			delete(a.bindings, key)
		}
		return
	}

	now := completion.CompletedAt
	if now.IsZero() {
		now = time.Now()
	}

	if exists && existing.AuthID == authID && !policy.RefreshOnSuccess && existing.ExpiresAt.After(now) {
		existing.Provisional = false
		a.bindings[key] = existing
		return
	}

	a.bindings[key] = affinityBinding{
		AuthID:      authID,
		ExpiresAt:   now.Add(time.Duration(policy.TTLSeconds) * time.Second),
		Policy:      policy,
		Provisional: false,
	}
	a.cleanupExpiredLocked(now)
	a.trimLocked()
}

func (a *affinityController) nextCandidateLocked(policy affinityPolicy, candidates []pluginapi.SchedulerAuthCandidate, model string) string {
	eligible := make([]pluginapi.SchedulerAuthCandidate, 0, len(candidates))
	for _, candidate := range candidates {
		if candidate.ID == "" {
			continue
		}
		cp := affinityPolicyFromAttributes(candidate.Attributes)
		if cp.GroupID == policy.GroupID {
			eligible = append(eligible, candidate)
		}
	}
	if len(eligible) == 0 {
		return ""
	}

	sort.Slice(eligible, func(i, j int) bool {
		left := strings.TrimSpace(eligible[i].Attributes["key_id"])
		right := strings.TrimSpace(eligible[j].Attributes["key_id"])
		li, le := strconv.Atoi(left)
		ri, re := strconv.Atoi(right)
		if le == nil && re == nil && li != ri {
			return li < ri
		}
		if left != right {
			return left < right
		}
		return eligible[i].ID < eligible[j].ID
	})

	cursorKey := policy.GroupID
	if policy.IncludeModel {
		cursorKey += "|" + strings.ToLower(strings.TrimSpace(model))
	}

	totalWeight := uint64(0)
	weights := make([]uint64, len(eligible))
	for i, candidate := range eligible {
		weight := parseIntDefault(candidate.Attributes["weight"], 1)
		weights[i] = uint64(weight)
		totalWeight += uint64(weight)
	}
	if totalWeight == 0 {
		return eligible[0].ID
	}

	position := a.cursors[cursorKey] % totalWeight
	a.cursors[cursorKey]++
	for i, weight := range weights {
		if position < weight {
			return eligible[i].ID
		}
		position -= weight
	}
	return eligible[len(eligible)-1].ID
}

func (a *affinityController) cleanupExpiredLocked(now time.Time) {
	for key, entry := range a.bindings {
		if !entry.ExpiresAt.After(now) {
			delete(a.bindings, key)
		}
	}
}

func (a *affinityController) trimLocked() {
	if len(a.descriptors) > maxAffinityEntries {
		for id := range a.descriptors {
			delete(a.descriptors, id)
			if len(a.descriptors) <= maxAffinityEntries*9/10 {
				break
			}
		}
	}
	if len(a.bindings) <= maxAffinityEntries {
		return
	}
	type expiring struct {
		key string
		at  time.Time
	}
	entries := make([]expiring, 0, len(a.bindings))
	for key, binding := range a.bindings {
		entries = append(entries, expiring{key: key, at: binding.ExpiresAt})
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].at.Before(entries[j].at) })
	remove := len(entries) - maxAffinityEntries*9/10
	for _, entry := range entries[:remove] {
		delete(a.bindings, entry.key)
	}
}

func affinityPolicyFromAttributes(attrs map[string]string) affinityPolicy {
	policy := affinityPolicy{
		GroupID:               strings.TrimSpace(attrs["provider_group"]),
		Strategy:              strings.ToLower(strings.TrimSpace(attrs["routing_strategy"])),
		Enabled:               parseBoolDefault(attrs["key_affinity_enabled"], true),
		TTLSeconds:            parseIntDefault(attrs["key_affinity_ttl_seconds"], defaultAffinityTTLSeconds),
		RefreshOnSuccess:      parseBoolDefault(attrs["key_affinity_refresh_on_success"], true),
		FailoverOnUnavailable: parseBoolDefault(attrs["key_affinity_failover_unavailable"], true),
		IncludeModel:          parseBoolDefault(attrs["key_affinity_include_model"], false),
	}
	if policy.Strategy == "" {
		policy.Strategy = "round-robin"
	}
	return policy
}

func builtinForStrategy(strategy string) string {
	if strings.EqualFold(strings.TrimSpace(strategy), "fill-first") {
		return pluginapi.SchedulerBuiltinFillFirst
	}
	return pluginapi.SchedulerBuiltinRoundRobin
}

func affinityBindingKey(policy affinityPolicy, identity, model string) string {
	parts := []string{policy.GroupID, identity}
	if policy.IncludeModel {
		parts = append(parts, strings.ToLower(strings.TrimSpace(model)))
	}
	return strings.Join(parts, "|")
}

func deriveAffinityIdentity(metadata map[string]any, headers http.Header, body []byte, allowDerived bool, salt string) string {
	keys := []string{
		"execution_session_id",
		"prompt_cache_key",
		"session_id",
		"conversation_id",
		"thread_id",
		"parent_session_id",
		"parent_thread_id",
	}
	for _, key := range keys {
		if value := metadataString(metadata, key); value != "" {
			return hashAffinityIdentity(salt, key, value)
		}
	}

	for _, key := range []string{
		"Session-Id",
		"X-Session-Id",
		"X-Claude-Code-Session-Id",
		"X-Conversation-Id",
		"X-Thread-Id",
		"Thread-Id",
		"X-Codex-Thread-Id",
		"X-Codex-Parent-Thread-Id",
		"X-Parent-Session-Id",
		"X-Parent-Thread-Id",
	} {
		if value := firstHeader(headers, key); value != "" {
			return hashAffinityIdentity(salt, strings.ToLower(key), value)
		}
	}

	if len(body) > 0 {
		var payload map[string]any
		if json.Unmarshal(body, &payload) == nil {
			if kind, value := explicitAffinityBodyIdentity(payload); value != "" {
				return hashAffinityIdentity(salt, kind, value)
			}
		}
	}

	if allowDerived {
		for _, key := range []string{"canonical_session_id", "derived_session_id", "lcp_affinity_session_id"} {
			if value := metadataString(metadata, key); value != "" {
				return hashAffinityIdentity(salt, key, value)
			}
		}
	}
	return ""
}

func explicitAffinityBodyIdentity(payload map[string]any) (string, string) {
	if payload == nil {
		return "", ""
	}
	for _, key := range []string{
		"prompt_cache_key",
		"session_id",
		"conversation_id",
		"thread_id",
		"parent_session_id",
		"parent_thread_id",
	} {
		if value, _ := payload[key].(string); strings.TrimSpace(value) != "" {
			return key, strings.TrimSpace(value)
		}
	}
	if extra, _ := payload["extra_body"].(map[string]any); extra != nil {
		for _, key := range []string{"session_id", "conversation_id", "thread_id"} {
			if value, _ := extra[key].(string); strings.TrimSpace(value) != "" {
				return "extra_body." + key, strings.TrimSpace(value)
			}
		}
	}
	if meta, _ := payload["metadata"].(map[string]any); meta != nil {
		for _, key := range []string{"session_id", "conversation_id", "thread_id", "parent_session_id"} {
			if value, _ := meta[key].(string); strings.TrimSpace(value) != "" {
				return "metadata." + key, strings.TrimSpace(value)
			}
		}
		if raw, _ := meta["user_id"].(string); strings.HasPrefix(strings.TrimSpace(raw), "{") {
			var userMeta map[string]any
			if json.Unmarshal([]byte(raw), &userMeta) == nil {
				for _, key := range []string{"session_id", "parent_session_id"} {
					if value, _ := userMeta[key].(string); strings.TrimSpace(value) != "" {
						return "metadata.user_id." + key, strings.TrimSpace(value)
					}
				}
			}
		}
	}
	return "", ""
}

func hashAffinityIdentity(salt, kind, value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(salt + "|" + strings.TrimSpace(kind) + "|" + value))
	return hex.EncodeToString(sum[:16])
}

func metadataString(metadata map[string]any, keys ...string) string {
	for _, key := range keys {
		if metadata == nil {
			continue
		}
		raw, ok := metadata[key]
		if !ok || raw == nil {
			continue
		}
		switch value := raw.(type) {
		case string:
			if strings.TrimSpace(value) != "" {
				return strings.TrimSpace(value)
			}
		case json.Number:
			return value.String()
		case float64:
			return strconv.FormatFloat(value, 'f', -1, 64)
		case int:
			return strconv.Itoa(value)
		case int64:
			return strconv.FormatInt(value, 10)
		}
	}
	return ""
}

func firstHeader(headers http.Header, key string) string {
	if headers == nil {
		return ""
	}
	return strings.TrimSpace(headers.Get(key))
}

func parseBoolDefault(raw string, fallback bool) bool {
	value, err := strconv.ParseBool(strings.TrimSpace(raw))
	if err != nil {
		return fallback
	}
	return value
}

func parseIntDefault(raw string, fallback int) int {
	value, err := strconv.Atoi(strings.TrimSpace(raw))
	if err != nil || value <= 0 {
		return fallback
	}
	return value
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}
