package scheduler

import (
    "encoding/json"
    "fmt"
    "net/http"
    "strings"
    "sync"

    "github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginabi"
    "github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
)

const PluginVersion = "0.1.0"

const (
    commandCodeProvider = "commandcode"
    personaProvider     = "persona"

    commandSelectorHeader = "X-CPA-CommandCode-Key"
    commandAffinityHeader  = "X-CPA-Unified-CommandCode-Affinity"
    personaAffinityHeader  = "X-CPA-Unified-Persona-Affinity"
)

type HostCaller interface {
    Call(method string, payload any) (json.RawMessage, error)
}

type RPCError struct {
    Code       string
    Message    string
    Retryable  bool
    HTTPStatus int
}

func (e *RPCError) Error() string {
    if e == nil {
        return ""
    }
    return e.Message
}

type Adapter struct {
    host    HostCaller
    command *affinityController
    persona *affinityController

    quota *quotaController

    pendingMu sync.Mutex
    pending   map[string]pendingRequest
}

type pendingRequest struct {
    CommandIdentity string
    PersonaIdentity string
    Model           string
    AuthID          string
    Provider        string
}

type registration struct {
    SchemaVersion uint32                   `json:"schema_version"`
    Metadata      pluginapi.Metadata       `json:"metadata"`
    Capabilities  registrationCapabilities `json:"capabilities"`
}

type registrationCapabilities struct {
    Scheduler              bool `json:"scheduler"`
    RequestInterceptor     bool `json:"request_interceptor"`
    RequestLifecyclePlugin bool `json:"request_lifecycle_plugin"`
}

func New(host HostCaller) *Adapter {
    return &Adapter{
        host:    host,
        command: newAffinityController(commandCodeProvider, commandAffinityHeader, true, true),
        persona: newAffinityController(personaProvider, personaAffinityHeader, false, false),
        quota:   newQuotaController(host),
        pending: make(map[string]pendingRequest),
    }
}

func pluginRegistration() registration {
    return registration{
        SchemaVersion: pluginabi.SchemaVersion,
        Metadata: pluginapi.Metadata{
            Name:             "CPA Unified Scheduler",
            Version:          PluginVersion,
            Author:           "nonlog",
            GitHubRepository: "https://github.com/nonlog/cpa-unified-scheduler",
        },
        Capabilities: registrationCapabilities{
            Scheduler:              true,
            RequestInterceptor:     true,
            RequestLifecyclePlugin: true,
        },
    }
}

func (a *Adapter) Handle(method string, raw []byte) (any, error) {
    switch method {
    case pluginabi.MethodPluginRegister, pluginabi.MethodPluginReconfigure:
        return pluginRegistration(), nil
    case pluginabi.MethodPluginQuiesce, pluginabi.MethodPluginShutdown:
        return struct{}{}, nil

    case pluginabi.MethodSchedulerPick:
        var req pluginapi.SchedulerPickRequest
        if err := json.Unmarshal(raw, &req); err != nil {
            return nil, fmt.Errorf("decode scheduler.pick: %w", err)
        }
        return a.pick(req)

    case pluginabi.MethodRequestInterceptBefore:
        var req pluginapi.RequestInterceptRequest
        if err := json.Unmarshal(raw, &req); err != nil {
            return nil, fmt.Errorf("decode request.intercept_before: %w", err)
        }
        return a.interceptBefore(req), nil

    case pluginabi.MethodRequestInterceptAfter:
        var req pluginapi.RequestInterceptRequest
        if err := json.Unmarshal(raw, &req); err != nil {
            return nil, fmt.Errorf("decode request.intercept_after: %w", err)
        }
        return a.interceptAfter(req), nil

    case pluginabi.MethodRequestComplete:
        var completion pluginapi.RequestCompletion
        if err := json.Unmarshal(raw, &completion); err != nil {
            return nil, fmt.Errorf("decode request.complete: %w", err)
        }
        a.complete(completion)
        return struct{}{}, nil
    default:
        return nil, &RPCError{Code: "unknown_method", Message: "unknown method: " + strings.TrimSpace(method), HTTPStatus: http.StatusBadRequest}
    }
}

func (a *Adapter) pick(req pluginapi.SchedulerPickRequest) (pluginapi.SchedulerPickResponse, error) {
    provider := candidateProvider(req.Candidates)
    switch provider {
    case commandCodeProvider:
        filtered, err := a.quota.prepare(req)
        if err != nil {
            return pluginapi.SchedulerPickResponse{}, err
        }
        if err := validateCommandSelector(filtered); err != nil {
            return pluginapi.SchedulerPickResponse{}, err
        }
        if a.command.strictUnavailable(filtered) {
            return pluginapi.SchedulerPickResponse{}, &RPCError{
                Code:       "key_affinity_unavailable",
                Message:    "pinned session Key is unavailable and affinity failover is disabled",
                HTTPStatus: http.StatusServiceUnavailable,
            }
        }
        return a.command.pick(filtered), nil
    case personaProvider:
        if a.persona.strictUnavailable(req) {
            return pluginapi.SchedulerPickResponse{}, &RPCError{
                Code:       "key_affinity_unavailable",
                Message:    "pinned session Key is unavailable and affinity failover is disabled",
                HTTPStatus: http.StatusServiceUnavailable,
            }
        }
        return a.persona.pick(req), nil
    default:
        return pluginapi.SchedulerPickResponse{Handled: false}, nil
    }
}

func candidateProvider(candidates []pluginapi.SchedulerAuthCandidate) string {
    if len(candidates) == 0 {
        return ""
    }
    provider := strings.ToLower(strings.TrimSpace(candidates[0].Provider))
    if provider == "" {
        return ""
    }
    for _, candidate := range candidates[1:] {
        if strings.ToLower(strings.TrimSpace(candidate.Provider)) != provider {
            return ""
        }
    }
    return provider
}

func validateCommandSelector(req pluginapi.SchedulerPickRequest) error {
    selector := strings.TrimSpace(firstHeader(req.Options.Headers, commandSelectorHeader))
    if selector == "" || strings.EqualFold(selector, "auto") {
        return nil
    }
    for _, candidate := range req.Candidates {
        if strings.EqualFold(strings.TrimSpace(candidate.Provider), commandCodeProvider) &&
            strings.EqualFold(strings.TrimSpace(candidate.Attributes["key_id"]), selector) {
            return nil
        }
    }
    return &RPCError{
        Code:       "commandcode_key_unavailable",
        Message:    "Command Code key " + fmt.Sprintf("%q", selector) + " is not available",
        HTTPStatus: http.StatusServiceUnavailable,
        Retryable:  true,
    }
}

func (a *Adapter) interceptBefore(req pluginapi.RequestInterceptRequest) pluginapi.RequestInterceptResponse {
    headers := cloneHeader(req.Headers)
    if headers == nil {
        headers = make(http.Header)
    }
    headers.Del(commandAffinityHeader)
    headers.Del(personaAffinityHeader)

    commandIdentity := ""
    selector := strings.TrimSpace(headers.Get(commandSelectorHeader))
    if selector == "" || strings.EqualFold(selector, "auto") {
        commandIdentity = deriveAffinityIdentity(req.Metadata, headers, req.Body, true, "cpa-unified-commandcode-affinity")
    }
    personaIdentity := deriveAffinityIdentity(req.Metadata, headers, req.Body, false, "cpa-unified-persona-affinity")

    if commandIdentity != "" {
        headers.Set(commandAffinityHeader, commandIdentity)
    }
    if personaIdentity != "" {
        headers.Set(personaAffinityHeader, personaIdentity)
    }

    if req.RequestID != "" && (commandIdentity != "" || personaIdentity != "") {
        a.pendingMu.Lock()
        a.pending[req.RequestID] = pendingRequest{
            CommandIdentity: commandIdentity,
            PersonaIdentity: personaIdentity,
            Model:           firstNonEmpty(req.RequestedModel, req.Model),
        }
        trimPending(a.pending)
        a.pendingMu.Unlock()
    }

    return pluginapi.RequestInterceptResponse{Headers: headers, Body: req.Body}
}

func (a *Adapter) interceptAfter(req pluginapi.RequestInterceptRequest) pluginapi.RequestInterceptResponse {
    headers := cloneHeader(req.Headers)
    if headers == nil {
        headers = make(http.Header)
    }
    headers.Del(commandAffinityHeader)
    headers.Del(personaAffinityHeader)

    if req.RequestID != "" {
        authID := metadataString(req.Metadata, "selected_auth_id", "pinned_auth_id", "auth_id")
        provider := strings.ToLower(metadataString(req.Metadata, "selected_auth_provider", "auth_provider", "provider"))
        if provider == "" {
            provider = providerFromAuthID(authID)
        }
        a.pendingMu.Lock()
        p := a.pending[req.RequestID]
        if p.Model == "" {
            p.Model = firstNonEmpty(req.RequestedModel, req.Model)
        }
        p.AuthID = authID
        p.Provider = provider
        a.pending[req.RequestID] = p
        trimPending(a.pending)
        a.pendingMu.Unlock()
    }

    return pluginapi.RequestInterceptResponse{
        Headers:      headers,
        Body:         req.Body,
        ClearHeaders: []string{commandAffinityHeader, personaAffinityHeader},
    }
}

func (a *Adapter) complete(completion pluginapi.RequestCompletion) {
    a.pendingMu.Lock()
    p := a.pending[completion.RequestID]
    delete(a.pending, completion.RequestID)
    a.pendingMu.Unlock()

    authID := firstNonEmpty(p.AuthID, metadataString(completion.Metadata, "selected_auth_id", "pinned_auth_id", "auth_id"))
    provider := p.Provider
    if provider == "" {
        provider = strings.ToLower(metadataString(completion.Metadata, "selected_auth_provider", "auth_provider", "provider"))
    }
    if provider == "" {
        provider = providerFromAuthID(authID)
    }

    model := firstNonEmpty(p.Model, completion.RequestedModel, completion.Model)
    switch provider {
    case commandCodeProvider:
        identity := p.CommandIdentity
        if identity == "" {
            identity = deriveAffinityIdentity(completion.Metadata, nil, nil, true, "cpa-unified-commandcode-affinity")
        }
        a.command.complete(identity, model, authID, completion)
    case personaProvider:
        identity := p.PersonaIdentity
        if identity == "" {
            identity = deriveAffinityIdentity(completion.Metadata, nil, nil, false, "cpa-unified-persona-affinity")
        }
        a.persona.complete(identity, model, authID, completion)
    }
}

func providerFromAuthID(authID string) string {
    authID = strings.ToLower(strings.TrimSpace(authID))
    switch {
    case strings.HasPrefix(authID, "commandcode-provider:"):
        return commandCodeProvider
    case strings.HasPrefix(authID, "persona-provider:"):
        return personaProvider
    default:
        return ""
    }
}

func trimPending(m map[string]pendingRequest) {
    const maxPending = 100000
    if len(m) <= maxPending {
        return
    }
    target := maxPending * 9 / 10
    for key := range m {
        delete(m, key)
        if len(m) <= target {
            break
        }
    }
}

func cloneHeader(in http.Header) http.Header {
    if len(in) == 0 {
        return nil
    }
    out := make(http.Header, len(in))
    for key, values := range in {
        out[key] = append([]string(nil), values...)
    }
    return out
}
