package scheduler

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginabi"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
)

const (
	defaultCommandCodeBaseURL  = "https://api.commandcode.ai"
	commandCodeProtocolVersion = "1.53.1"
	defaultQuotaCheckSeconds   = 60
	quotaRequestTimeout        = 8 * time.Second
)

var userKeyPattern = regexp.MustCompile(`user_[A-Za-z0-9_-]+`)

type commandKeyConfig struct {
	ID       string `json:"id"`
	APIKey   string `json:"api_key"`
	ProxyURL string `json:"proxy_url,omitempty"`
	Disabled bool   `json:"disabled,omitempty"`
	Weight   int    `json:"weight,omitempty"`
}

type commandQuotaConfig struct {
	Enabled              *bool `json:"enabled,omitempty"`
	AutoDisable          *bool `json:"auto_disable,omitempty"`
	CheckIntervalSeconds int   `json:"check_interval_seconds,omitempty"`
}

type commandProviderConfig struct {
	Name              string             `json:"name"`
	BaseURL           string             `json:"base_url,omitempty"`
	ClientVersionMode string             `json:"client_version_mode,omitempty"`
	ClientVersion     string             `json:"client_version,omitempty"`
	Keys              []commandKeyConfig `json:"keys"`
	Quota             commandQuotaConfig `json:"quota,omitempty"`
}

type commandCredentialDocument struct {
	Type string `json:"type"`
	commandProviderConfig
}

type commandRuntimeDocument struct {
	Type   string                `json:"type"`
	Config commandProviderConfig `json:"config"`
}

type quotaSettings struct {
	Enabled              bool
	AutoDisable          bool
	CheckIntervalSeconds int
}

type quotaState struct {
	Exhausted   bool
	NextResetAt int64
	Checked     time.Time
	Error       string
}

type quotaController struct {
	host HostCaller

	mu     sync.RWMutex
	states map[string]quotaState

	clientsMu sync.Mutex
	clients   map[string]*http.Client
}

func newQuotaController(host HostCaller) *quotaController {
	return &quotaController{
		host:    host,
		states:  make(map[string]quotaState),
		clients: make(map[string]*http.Client),
	}
}

func (q *quotaController) prepare(req pluginapi.SchedulerPickRequest) (pluginapi.SchedulerPickRequest, error) {
	if q == nil || q.host == nil || len(req.Candidates) == 0 || candidateProvider(req.Candidates) != commandCodeProvider {
		return req, nil
	}

	cfg, err := q.loadConfig(req.Candidates[0])
	if err != nil {
		// Preserve availability on control-plane read failures. The original
		// Command Code scheduler also keeps a previously known state rather
		// than disabling a key solely because a quota probe failed.
		return q.filterKnownState(req, quotaSettings{Enabled: true, AutoDisable: true, CheckIntervalSeconds: defaultQuotaCheckSeconds})
	}

	settings := cfg.quotaSettings()
	if !settings.Enabled || !settings.AutoDisable {
		return req, nil
	}

	keysByID := make(map[string]commandKeyConfig, len(cfg.Keys))
	for _, key := range cfg.Keys {
		keysByID[strings.TrimSpace(key.ID)] = key
	}

	var wg sync.WaitGroup
	for _, candidate := range req.Candidates {
		keyID := strings.TrimSpace(candidate.Attributes["key_id"])
		key, ok := keysByID[keyID]
		if !ok || !q.shouldRefresh(keyID, settings) {
			continue
		}
		wg.Add(1)
		go func(id string, selected commandKeyConfig) {
			defer wg.Done()
			ctx, cancel := context.WithTimeout(context.Background(), quotaRequestTimeout)
			defer cancel()
			_ = q.refresh(ctx, cfg, selected)
		}(keyID, key)
	}
	wg.Wait()

	return q.filterKnownState(req, settings)
}

func (q *quotaController) filterKnownState(req pluginapi.SchedulerPickRequest, settings quotaSettings) (pluginapi.SchedulerPickRequest, error) {
	if !settings.Enabled || !settings.AutoDisable {
		return req, nil
	}

	selector := strings.TrimSpace(firstHeader(req.Options.Headers, commandSelectorHeader))
	filtered := make([]pluginapi.SchedulerAuthCandidate, 0, len(req.Candidates))
	earliest := int64(0)
	blockedSelector := false

	for _, candidate := range req.Candidates {
		keyID := strings.TrimSpace(candidate.Attributes["key_id"])
		state, ok := q.snapshot(keyID)
		if ok && state.Exhausted {
			if state.NextResetAt > 0 && (earliest == 0 || state.NextResetAt < earliest) {
				earliest = state.NextResetAt
			}
			if selector != "" && !strings.EqualFold(selector, "auto") && strings.EqualFold(selector, keyID) {
				blockedSelector = true
			}
			continue
		}
		filtered = append(filtered, candidate)
	}

	if blockedSelector {
		return req, quotaExhaustedError(selector, earliest)
	}
	if len(filtered) == 0 && len(req.Candidates) > 0 {
		return req, quotaExhaustedError("", earliest)
	}
	req.Candidates = filtered
	return req, nil
}

func quotaExhaustedError(keyID string, resetAt int64) error {
	message := "all Command Code keys are temporarily quota exhausted"
	if keyID != "" {
		message = "Command Code key " + fmt.Sprintf("%q", keyID) + " is temporarily quota exhausted"
	}
	if resetAt > 0 {
		message += "; reset at " + time.UnixMilli(resetAt).UTC().Format(time.RFC3339)
	}
	return &RPCError{
		Code:       "commandcode_quota_exhausted",
		Message:    message,
		HTTPStatus: http.StatusTooManyRequests,
		Retryable:  true,
	}
}

func (q *quotaController) loadConfig(candidate pluginapi.SchedulerAuthCandidate) (commandProviderConfig, error) {
	seed := strings.TrimSpace(candidate.Attributes["auth_index_seed"])
	if seed == "" {
		return commandProviderConfig{}, fmt.Errorf("candidate %q has no auth_index_seed", candidate.ID)
	}
	authIndex := stableAuthIndex("auth_index_seed:" + seed)

	raw, err := q.host.Call(pluginabi.MethodHostAuthGet, pluginapi.HostAuthGetRequest{AuthIndex: authIndex})
	if err != nil {
		return commandProviderConfig{}, fmt.Errorf("host.auth.get: %w", err)
	}

	var response pluginapi.HostAuthGetResponse
	if err := json.Unmarshal(raw, &response); err != nil {
		return commandProviderConfig{}, fmt.Errorf("decode host.auth.get: %w", err)
	}

	var doc commandCredentialDocument
	if err := json.Unmarshal(response.JSON, &doc); err == nil &&
		strings.EqualFold(strings.TrimSpace(doc.Type), commandCodeProvider) &&
		len(doc.Keys) > 0 {
		return normalizeCommandConfig(doc.commandProviderConfig), nil
	}

	var runtime commandRuntimeDocument
	if err := json.Unmarshal(response.JSON, &runtime); err == nil &&
		strings.EqualFold(strings.TrimSpace(runtime.Type), commandCodeProvider) &&
		len(runtime.Config.Keys) > 0 {
		return normalizeCommandConfig(runtime.Config), nil
	}

	return commandProviderConfig{}, fmt.Errorf("physical Command Code auth has unsupported schema")
}

func normalizeCommandConfig(cfg commandProviderConfig) commandProviderConfig {
	cfg.BaseURL = strings.TrimRight(strings.TrimSpace(cfg.BaseURL), "/")
	if cfg.BaseURL == "" {
		cfg.BaseURL = defaultCommandCodeBaseURL
	}
	cfg.ClientVersionMode = strings.ToLower(strings.TrimSpace(cfg.ClientVersionMode))
	cfg.ClientVersion = strings.TrimSpace(cfg.ClientVersion)
	for i := range cfg.Keys {
		cfg.Keys[i].ID = strings.TrimSpace(cfg.Keys[i].ID)
		cfg.Keys[i].APIKey = strings.TrimSpace(cfg.Keys[i].APIKey)
		cfg.Keys[i].ProxyURL = strings.TrimSpace(cfg.Keys[i].ProxyURL)
		if cfg.Keys[i].ProxyURL == "" {
			cfg.Keys[i].ProxyURL = "direct"
		}
		if cfg.Keys[i].Weight <= 0 {
			cfg.Keys[i].Weight = 1
		}
	}
	return cfg
}

func (cfg commandProviderConfig) quotaSettings() quotaSettings {
	enabled := true
	autoDisable := true
	if cfg.Quota.Enabled != nil {
		enabled = *cfg.Quota.Enabled
	}
	if cfg.Quota.AutoDisable != nil {
		autoDisable = *cfg.Quota.AutoDisable
	}
	interval := cfg.Quota.CheckIntervalSeconds
	if interval <= 0 {
		interval = defaultQuotaCheckSeconds
	}
	if interval < 15 {
		interval = 15
	}
	return quotaSettings{
		Enabled:              enabled,
		AutoDisable:          autoDisable,
		CheckIntervalSeconds: interval,
	}
}

func (cfg commandProviderConfig) effectiveClientVersion() string {
	if strings.EqualFold(cfg.ClientVersionMode, "custom") && strings.TrimSpace(cfg.ClientVersion) != "" {
		return strings.TrimSpace(cfg.ClientVersion)
	}
	return commandCodeProtocolVersion
}

func (q *quotaController) shouldRefresh(keyID string, settings quotaSettings) bool {
	q.mu.RLock()
	state, ok := q.states[keyID]
	q.mu.RUnlock()
	if !ok {
		return true
	}
	now := time.Now()
	if state.Exhausted && state.NextResetAt > 0 && now.UnixMilli() >= state.NextResetAt {
		return true
	}
	return now.Sub(state.Checked) >= time.Duration(settings.CheckIntervalSeconds)*time.Second
}

func (q *quotaController) snapshot(keyID string) (quotaState, bool) {
	q.mu.RLock()
	defer q.mu.RUnlock()
	state, ok := q.states[keyID]
	return state, ok
}

func (q *quotaController) update(keyID string, state quotaState) {
	state.Checked = time.Now()
	q.mu.Lock()
	q.states[keyID] = state
	q.mu.Unlock()
}

func (q *quotaController) refresh(ctx context.Context, cfg commandProviderConfig, key commandKeyConfig) error {
	keyID := strings.TrimSpace(key.ID)
	state, hadPrevious := q.snapshot(keyID)

	client, err := q.clientFor(key.ProxyURL)
	if err != nil {
		state.Error = err.Error()
		q.update(keyID, state)
		return err
	}

	endpoint := strings.TrimRight(cfg.BaseURL, "/") + "/alpha/billing/credits"
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		state.Error = err.Error()
		q.update(keyID, state)
		return err
	}

	apiKey := normalizeCommandAPIKey(key.APIKey)
	request.Header = http.Header{
		"Authorization":          {"Bearer " + apiKey},
		"X-Command-Code-Version": {cfg.effectiveClientVersion()},
		"X-Cli-Environment":      {"production"},
		"User-Agent":             {"cli"},
		"Accept":                 {"application/json"},
	}

	response, err := client.Do(request)
	if err != nil {
		state.Error = err.Error()
		q.update(keyID, state)
		return err
	}
	defer response.Body.Close()

	body, err := io.ReadAll(io.LimitReader(response.Body, 2<<20))
	if err != nil {
		state.Error = err.Error()
		q.update(keyID, state)
		return err
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		err = fmt.Errorf("billing/credits: HTTP %d", response.StatusCode)
		state.Error = err.Error()
		q.update(keyID, state)
		return err
	}

	var payload map[string]any
	if err := json.Unmarshal(body, &payload); err != nil {
		state.Error = err.Error()
		q.update(keyID, state)
		return err
	}

	exhausted, resetAt, ok := quotaExhaustionFromPayload(payload)
	if !ok {
		err := fmt.Errorf("billing/credits returned no quota windows")
		if !hadPrevious {
			state.Exhausted = false
			state.NextResetAt = 0
		}
		state.Error = err.Error()
		q.update(keyID, state)
		return err
	}

	state.Exhausted = exhausted
	state.NextResetAt = resetAt
	state.Error = ""
	q.update(keyID, state)
	return nil
}

func quotaExhaustionFromPayload(payload map[string]any) (bool, int64, bool) {
	found := false
	exhausted := false
	earliest := int64(0)

	if credits, _ := payload["credits"].(map[string]any); credits != nil {
		balanceFound := false
		balanceTotal := 0.0
		for _, name := range []string{"monthlyCredits", "purchasedCredits", "freeCredits"} {
			raw, exists := credits[name]
			if !exists {
				continue
			}
			value, ok := quotaNumber(raw)
			if !ok {
				continue
			}
			balanceFound = true
			balanceTotal += value
		}
		if balanceFound {
			found = true
			if balanceTotal <= 0 {
				exhausted = true
			}
		}
	}

	if windows, _ := payload["windowLimits"].(map[string]any); windows != nil {
		for _, name := range []string{"fiveHour", "weekly"} {
			raw, ok := windows[name]
			if !ok {
				continue
			}
			window, _ := raw.(map[string]any)
			if window == nil {
				continue
			}
			found = true
			exceeded, _ := window["exceeded"].(bool)
			if !exceeded {
				continue
			}
			exhausted = true
			reset := resetMillis(window["resetAt"])
			if reset > 0 && (earliest == 0 || reset < earliest) {
				earliest = reset
			}
		}
	}

	return exhausted, earliest, found
}

func quotaNumber(value any) (float64, bool) {
	switch v := value.(type) {
	case float64:
		return v, true
	case float32:
		return float64(v), true
	case int:
		return float64(v), true
	case int64:
		return float64(v), true
	case json.Number:
		n, err := v.Float64()
		return n, err == nil
	default:
		return 0, false
	}
}

func resetMillis(value any) int64 {
	switch v := value.(type) {
	case string:
		v = strings.TrimSpace(v)
		if v == "" {
			return 0
		}
		if parsed, err := time.Parse(time.RFC3339Nano, v); err == nil {
			return parsed.UnixMilli()
		}
		if n, err := strconvParseInt(v); err == nil {
			if n > 0 && n < 1_000_000_000_000 {
				n *= 1000
			}
			return n
		}
	case float64:
		n := int64(v)
		if n > 0 && n < 1_000_000_000_000 {
			n *= 1000
		}
		return n
	case json.Number:
		if n, err := v.Int64(); err == nil {
			if n > 0 && n < 1_000_000_000_000 {
				n *= 1000
			}
			return n
		}
	}
	return 0
}

func strconvParseInt(value string) (int64, error) {
	var n int64
	_, err := fmt.Sscan(value, &n)
	return n, err
}

func (q *quotaController) clientFor(proxyURL string) (*http.Client, error) {
	proxyURL = strings.TrimSpace(proxyURL)
	cacheKey := proxyURL
	if cacheKey == "" {
		cacheKey = "direct"
	}

	q.clientsMu.Lock()
	defer q.clientsMu.Unlock()
	if client := q.clients[cacheKey]; client != nil {
		return client, nil
	}

	base, ok := http.DefaultTransport.(*http.Transport)
	if !ok {
		return nil, fmt.Errorf("default HTTP transport is not *http.Transport")
	}

	transport := base.Clone()
	transport.Proxy = nil
	transport.DialContext = (&net.Dialer{Timeout: 30 * time.Second, KeepAlive: 30 * time.Second}).DialContext
	transport.TLSHandshakeTimeout = 10 * time.Second
	transport.ResponseHeaderTimeout = 90 * time.Second
	transport.MaxConnsPerHost = 64
	transport.MaxIdleConns = 128
	transport.MaxIdleConnsPerHost = 16
	transport.IdleConnTimeout = 90 * time.Second
	transport.ForceAttemptHTTP2 = true

	if proxyURL != "" && !strings.EqualFold(proxyURL, "direct") {
		parsed, err := url.Parse(proxyURL)
		if err != nil || parsed.Host == "" {
			return nil, fmt.Errorf("invalid proxy URL")
		}
		switch strings.ToLower(parsed.Scheme) {
		case "http", "https", "socks5", "socks5h":
		default:
			return nil, fmt.Errorf("unsupported proxy scheme %q", parsed.Scheme)
		}
		transport.Proxy = http.ProxyURL(parsed)
	}

	client := &http.Client{Transport: transport, Timeout: quotaRequestTimeout}
	q.clients[cacheKey] = client
	return client, nil
}

func normalizeCommandAPIKey(raw string) string {
	raw = strings.TrimSpace(raw)
	if match := userKeyPattern.FindString(raw); match != "" {
		return match
	}
	return raw
}

func stableAuthIndex(seed string) string {
	seed = strings.TrimSpace(seed)
	if seed == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(seed))
	return hex.EncodeToString(sum[:8])
}
