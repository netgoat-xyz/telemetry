package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

const testIngestKey = "test-ingest-key"

func testServer() *Server {
	server := NewServer("127.0.0.1:9091")
	server.ingestKey = []byte(testIngestKey)
	return server
}

func telemetryBody(instanceID, eventType string, errors uint64) []byte {
	payload := Payload{
		InstanceID:  instanceID,
		Hostname:    instanceID + ".example.test",
		GoVersion:   "go1.26.3",
		OS:          "linux",
		Arch:        "amd64",
		CPUCores:    4,
		RAMTotalMB:  8192,
		DiskTotalMB: 102400,
		DiskFreeMB:  51200,
		Uptime:      "1m0s",
		EventType:   eventType,
		Timestamp:   time.Now(),
		App: &AppStats{
			Requests:    100,
			TotalErrors: errors,
		},
	}
	body, err := json.Marshal(payload)
	if err != nil {
		panic(err)
	}
	return body
}

func request(handler http.Handler, method, path string, body []byte, headers map[string]string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, bytes.NewReader(body))
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	for key, value := range headers {
		req.Header.Set(key, value)
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, req)
	return response
}

func TestTelemetryIngestionRequiresConfiguredKey(t *testing.T) {
	server := testServer()
	handler := server.handler()
	body := telemetryBody("agent-one", "startup", 2)

	for name, headers := range map[string]map[string]string{
		"missing": {},
		"wrong":   {"X-Telemetry-Key": "not-the-key"},
	} {
		t.Run(name, func(t *testing.T) {
			response := request(handler, http.MethodPost, "/api/telemetry", body, headers)
			if response.Code != http.StatusUnauthorized {
				t.Fatalf("status = %d, want %d; body=%s", response.Code, http.StatusUnauthorized, response.Body.String())
			}
		})
	}

	response := request(handler, http.MethodPost, "/api/telemetry", body, map[string]string{"X-Telemetry-Key": testIngestKey})
	if response.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want %d; body=%s", response.Code, http.StatusNoContent, response.Body.String())
	}
	if server.total != 1 || server.eventCount != 1 || len(server.agents) != 1 {
		t.Fatalf("unexpected state: total=%d events=%d agents=%d", server.total, server.eventCount, len(server.agents))
	}
}

func TestLegacyTelemetryEndpointsRemainCompatible(t *testing.T) {
	server := testServer()
	handler := server.handler()
	headers := map[string]string{"X-Telemetry-Key": testIngestKey}

	for index, path := range []string{"/api", "/"} {
		response := request(handler, http.MethodPost, path, telemetryBody(fmt.Sprintf("legacy-%d", index), "heartbeat", 0), headers)
		if response.Code != http.StatusNoContent {
			t.Fatalf("POST %s status = %d, want %d; body=%s", path, response.Code, http.StatusNoContent, response.Body.String())
		}
	}
}

func TestTelemetryValidationAndBodyLimit(t *testing.T) {
	server := testServer()
	handler := server.handler()
	headers := map[string]string{"X-Telemetry-Key": testIngestKey}

	tests := []struct {
		name   string
		body   []byte
		status int
	}{
		{name: "malformed JSON", body: []byte(`{"instance_id":`), status: http.StatusBadRequest},
		{name: "trailing JSON", body: append(telemetryBody("agent", "startup", 0), []byte(` {}`)...), status: http.StatusBadRequest},
		{name: "missing instance", body: []byte(`{"event_type":"startup"}`), status: http.StatusUnprocessableEntity},
		{name: "unknown event", body: []byte(`{"instance_id":"agent","event_type":"arbitrary"}`), status: http.StatusUnprocessableEntity},
		{name: "negative metrics", body: []byte(`{"instance_id":"agent","event_type":"heartbeat","cpu_cores":-1}`), status: http.StatusUnprocessableEntity},
		{name: "oversized", body: []byte(`{"instance_id":"agent","event_type":"heartbeat","padding":"` + strings.Repeat("x", maxTelemetryBodyBytes) + `"}`), status: http.StatusRequestEntityTooLarge},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			response := request(handler, http.MethodPost, "/api/telemetry", test.body, headers)
			if response.Code != test.status {
				t.Fatalf("status = %d, want %d; body=%s", response.Code, test.status, response.Body.String())
			}
		})
	}
	if server.total != 0 {
		t.Fatalf("invalid requests changed total to %d", server.total)
	}
}

func TestErrorTotalsAndShutdownStatusTrackLatestSnapshot(t *testing.T) {
	server := testServer()
	handler := server.handler()
	headers := map[string]string{"X-Telemetry-Key": testIngestKey}

	for _, test := range []struct {
		eventType string
		errors    uint64
	}{
		{eventType: "startup", errors: 12},
		{eventType: "heartbeat", errors: 3},
		{eventType: "shutdown", errors: 3},
	} {
		response := request(handler, http.MethodPost, "/api/telemetry", telemetryBody("agent-one", test.eventType, test.errors), headers)
		if response.Code != http.StatusNoContent {
			t.Fatalf("status = %d; body=%s", response.Code, response.Body.String())
		}
	}

	if server.errors != 3 {
		t.Fatalf("errors = %d, want latest total 3", server.errors)
	}
	agent := cloneAgent(server.agents["agent-one"], time.Now())
	if agent.Status != "offline" || agent.LastEvent != "shutdown" {
		t.Fatalf("agent status=%q last_event=%q, want offline/shutdown", agent.Status, agent.LastEvent)
	}
}

func TestEventRingRetainsNewestEventsWithoutGrowing(t *testing.T) {
	server := testServer()
	for index := 0; index < maxEvents+7; index++ {
		server.appendEventLocked(Event{InstanceID: fmt.Sprintf("agent-%05d", index)})
	}

	if server.eventCount != maxEvents || len(server.events) != maxEvents {
		t.Fatalf("eventCount=%d len=%d, want %d", server.eventCount, len(server.events), maxEvents)
	}
	result := server.recentEventsLocked(maxEvents, "")
	if result[0].InstanceID != fmt.Sprintf("agent-%05d", maxEvents+6) {
		t.Fatalf("newest event = %q", result[0].InstanceID)
	}
	if result[len(result)-1].InstanceID != "agent-00007" {
		t.Fatalf("oldest retained event = %q", result[len(result)-1].InstanceID)
	}
}

func TestProtectedAPIAndEventLimit(t *testing.T) {
	originalUsers := adminUsers
	originalSecret := jwtSecret
	adminUsers = map[string]string{"operator": "correct-horse"}
	jwtSecret = []byte("0123456789abcdef0123456789abcdef")
	t.Cleanup(func() {
		adminUsers = originalUsers
		jwtSecret = originalSecret
	})

	server := testServer()
	for index := 0; index < 5; index++ {
		server.appendEventLocked(Event{InstanceID: fmt.Sprintf("agent-%d", index)})
	}
	handler := server.handler()

	unauthorized := request(handler, http.MethodGet, "/api/events", nil, nil)
	if unauthorized.Code != http.StatusUnauthorized {
		t.Fatalf("unauthorized status = %d", unauthorized.Code)
	}

	login := request(handler, http.MethodPost, "/api/login", []byte(`{"username":"operator","password":"correct-horse"}`), nil)
	if login.Code != http.StatusOK {
		t.Fatalf("login status = %d; body=%s", login.Code, login.Body.String())
	}
	var session struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(login.Body.Bytes(), &session); err != nil {
		t.Fatal(err)
	}

	events := request(handler, http.MethodGet, "/api/events?limit=2", nil, map[string]string{"Authorization": "Bearer " + session.Token})
	if events.Code != http.StatusOK {
		t.Fatalf("events status = %d; body=%s", events.Code, events.Body.String())
	}
	var rows []Event
	if err := json.Unmarshal(events.Body.Bytes(), &rows); err != nil {
		t.Fatal(err)
	}
	if len(rows) != 2 || rows[0].InstanceID != "agent-4" {
		t.Fatalf("unexpected events: %#v", rows)
	}

	badLimit := request(handler, http.MethodGet, "/api/events?limit=0", nil, map[string]string{"Authorization": "Bearer " + session.Token})
	if badLimit.Code != http.StatusBadRequest {
		t.Fatalf("bad limit status = %d", badLimit.Code)
	}
}

func TestConcurrentIngestAndAgentReads(t *testing.T) {
	server := testServer()
	handler := server.handler()
	headers := map[string]string{"X-Telemetry-Key": testIngestKey}

	var wait sync.WaitGroup
	for worker := 0; worker < 6; worker++ {
		wait.Add(1)
		go func(worker int) {
			defer wait.Done()
			for index := 0; index < 100; index++ {
				id := fmt.Sprintf("agent-%d", index%8)
				if worker%2 == 0 {
					request(handler, http.MethodPost, "/api/telemetry", telemetryBody(id, "heartbeat", uint64(index)), headers)
					continue
				}
				server.mu.RLock()
				if agent := server.agents[id]; agent != nil {
					_ = cloneAgent(agent, time.Now())
				}
				server.mu.RUnlock()
			}
		}(worker)
	}
	wait.Wait()
}

func TestDashboardIsEmbeddedAndHealthIsPublic(t *testing.T) {
	server := testServer()
	handler := server.handler()

	originalDirectory, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	temporaryDirectory := t.TempDir()
	if err := os.Chdir(temporaryDirectory); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(originalDirectory) })

	dashboard := request(handler, http.MethodGet, "/", nil, nil)
	if dashboard.Code != http.StatusOK || !strings.Contains(dashboard.Body.String(), "Telemetry Server") {
		t.Fatalf("dashboard status=%d body=%q", dashboard.Code, dashboard.Body.String())
	}
	health := request(handler, http.MethodGet, "/health", nil, nil)
	if health.Code != http.StatusOK || !strings.Contains(health.Body.String(), `"status":"ok"`) || !strings.Contains(health.Body.String(), `"cas_enabled":false`) {
		t.Fatalf("health status=%d body=%q", health.Code, health.Body.String())
	}
}

func TestListenAddressDefaultsToLoopbackAndValidatesPorts(t *testing.T) {
	t.Setenv("TELEMETRY_ADDR", "")
	address, err := listenAddress(nil)
	if err != nil || address != "127.0.0.1:9091" {
		t.Fatalf("address=%q err=%v", address, err)
	}
	address, err = listenAddress([]string{"9191"})
	if err != nil || address != "127.0.0.1:9191" {
		t.Fatalf("address=%q err=%v", address, err)
	}
	if _, err := listenAddress([]string{"70000"}); err == nil {
		t.Fatal("expected invalid port error")
	}
}
