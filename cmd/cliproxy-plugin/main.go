package main

/*
#include <stdint.h>
#include <stdlib.h>

typedef struct {
	void* ptr;
	size_t len;
} cliproxy_buffer;

typedef int (*cliproxy_host_call_fn)(void*, const char*, const uint8_t*, size_t, cliproxy_buffer*);
typedef void (*cliproxy_host_free_fn)(void*, size_t);

typedef struct {
	uint32_t abi_version;
	void* host_ctx;
	cliproxy_host_call_fn call;
	cliproxy_host_free_fn free_buffer;
} cliproxy_host_api;

typedef int (*cliproxy_plugin_call_fn)(char*, uint8_t*, size_t, cliproxy_buffer*);
typedef void (*cliproxy_plugin_free_fn)(void*, size_t);
typedef void (*cliproxy_plugin_shutdown_fn)(void);

typedef struct {
	uint32_t abi_version;
	cliproxy_plugin_call_fn call;
	cliproxy_plugin_free_fn free_buffer;
	cliproxy_plugin_shutdown_fn shutdown;
} cliproxy_plugin_api;

extern int cliproxyPluginCall(char*, uint8_t*, size_t, cliproxy_buffer*);
extern void cliproxyPluginFree(void*, size_t);
extern void cliproxyPluginShutdown(void);

static const cliproxy_host_api* stored_host;

static void store_host_api(const cliproxy_host_api* host) {
	stored_host = host;
}

static int call_host_api(const char* method, const uint8_t* request, size_t request_len, cliproxy_buffer* response) {
	if (stored_host == NULL || stored_host->call == NULL) {
		return 1;
	}
	return stored_host->call(stored_host->host_ctx, method, request, request_len, response);
}

static void free_host_buffer(void* ptr, size_t len) {
	if (stored_host != NULL && stored_host->free_buffer != NULL && ptr != NULL) {
		stored_host->free_buffer(ptr, len);
	}
}
*/
import "C"

import (
	"encoding/json"
	"fmt"
	"sync"
	"unsafe"

	scheduler "github.com/nonlog/cpa-unified-scheduler/scheduler"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginabi"
)

var (
	adapterMu sync.RWMutex
	adapter   = scheduler.New(cHostCaller{})
)

type cHostCaller struct{}

func main() {}

//export cliproxy_plugin_init
func cliproxy_plugin_init(host *C.cliproxy_host_api, plugin *C.cliproxy_plugin_api) C.int {
	if plugin == nil {
		return 1
	}
	C.store_host_api(host)
	adapterMu.Lock()
	adapter = scheduler.New(cHostCaller{})
	adapterMu.Unlock()
	plugin.abi_version = C.uint32_t(pluginabi.ABIVersion)
	plugin.call = C.cliproxy_plugin_call_fn(C.cliproxyPluginCall)
	plugin.free_buffer = C.cliproxy_plugin_free_fn(C.cliproxyPluginFree)
	plugin.shutdown = C.cliproxy_plugin_shutdown_fn(C.cliproxyPluginShutdown)
	return 0
}

//export cliproxyPluginCall
func cliproxyPluginCall(method *C.char, request *C.uint8_t, requestLen C.size_t, response *C.cliproxy_buffer) C.int {
	if response != nil {
		response.ptr = nil
		response.len = 0
	}
	if method == nil {
		writeResponse(response, errorEnvelope(&scheduler.RPCError{Code: "invalid_method", Message: "method is required"}))
		return 1
	}
	var raw []byte
	if request != nil && requestLen > 0 {
		raw = C.GoBytes(unsafe.Pointer(request), C.int(requestLen))
	}
	adapterMu.RLock()
	current := adapter
	adapterMu.RUnlock()
	result, err := current.Handle(C.GoString(method), raw)
	if err != nil {
		writeResponse(response, errorEnvelope(err))
		return 1
	}
	writeResponse(response, okEnvelope(result))
	return 0
}

//export cliproxyPluginFree
func cliproxyPluginFree(ptr unsafe.Pointer, length C.size_t) {
	if ptr != nil {
		C.free(ptr)
	}
	_ = length
}

//export cliproxyPluginShutdown
func cliproxyPluginShutdown() {}

func (cHostCaller) Call(method string, payload any) (json.RawMessage, error) {
	rawPayload, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("marshal host callback %s: %w", method, err)
	}
	cMethod := C.CString(method)
	defer C.free(unsafe.Pointer(cMethod))
	var response C.cliproxy_buffer
	var requestPtr *C.uint8_t
	if len(rawPayload) > 0 {
		allocated := C.CBytes(rawPayload)
		if allocated == nil {
			return nil, fmt.Errorf("allocate host callback %s", method)
		}
		defer C.free(allocated)
		requestPtr = (*C.uint8_t)(allocated)
	}
	code := C.call_host_api(cMethod, requestPtr, C.size_t(len(rawPayload)), &response)
	var rawResponse []byte
	if response.ptr != nil && response.len > 0 {
		rawResponse = C.GoBytes(response.ptr, C.int(response.len))
	}
	if response.ptr != nil {
		C.free_host_buffer(response.ptr, response.len)
	}
	if len(rawResponse) == 0 {
		return nil, fmt.Errorf("host callback %s returned no response, code=%d", method, int(code))
	}
	var envelope pluginabi.Envelope
	if err := json.Unmarshal(rawResponse, &envelope); err != nil {
		return nil, fmt.Errorf("decode host callback %s: %w", method, err)
	}
	if !envelope.OK {
		if envelope.Error != nil {
			return nil, fmt.Errorf("%s: %s", envelope.Error.Code, envelope.Error.Message)
		}
		return nil, fmt.Errorf("host callback %s failed", method)
	}
	if code != 0 {
		return nil, fmt.Errorf("host callback %s returned code=%d", method, int(code))
	}
	return append(json.RawMessage(nil), envelope.Result...), nil
}

func okEnvelope(result any) []byte {
	raw, err := json.Marshal(result)
	if err != nil {
		return errorEnvelope(err)
	}
	envelope, _ := json.Marshal(pluginabi.Envelope{OK: true, Result: raw})
	return envelope
}

func errorEnvelope(err error) []byte {
	pluginError := &pluginabi.Error{Code: "plugin_error", Message: err.Error()}
	if typed, ok := err.(*scheduler.RPCError); ok {
		pluginError.Code = typed.Code
		pluginError.Message = typed.Message
		pluginError.Retryable = typed.Retryable
		pluginError.HTTPStatus = typed.HTTPStatus
	}
	raw, _ := json.Marshal(pluginabi.Envelope{OK: false, Error: pluginError})
	return raw
}

func writeResponse(response *C.cliproxy_buffer, raw []byte) {
	if response == nil || len(raw) == 0 {
		return
	}
	ptr := C.CBytes(raw)
	if ptr == nil {
		return
	}
	response.ptr = ptr
	response.len = C.size_t(len(raw))
}
