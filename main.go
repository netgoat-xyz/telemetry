package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	_ "embed"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

var jwtSecret []byte
var adminUsers = map[string]string{}
var configuredIngestKey []byte
var usingDefaultAdmin bool
var usingEphemeralJWT bool

const jwtHeader = `{"alg":"HS256","typ":"JWT"}`

//go:embed static/index.html
var dashboardHTML []byte

func init() {
	secret := os.Getenv("TELEMETRY_JWT_SECRET")
	if secret == "" {
		generated := make([]byte, 32)
		if _, err := rand.Read(generated); err != nil {
			panic(fmt.Sprintf("generate ephemeral JWT secret: %v", err))
		}
		jwtSecret = generated
		usingEphemeralJWT = true
	} else {
		jwtSecret = []byte(secret)
	}

	username := os.Getenv("TELEMETRY_ADMIN_USERNAME")
	if username == "" {
		username = "admin"
	}
	pass := os.Getenv("TELEMETRY_ADMIN_PASSWORD")
	if pass == "" {
		pass = "admin"
		usingDefaultAdmin = true
	}
	adminUsers[username] = pass
	configuredIngestKey = []byte(os.Getenv("TELEMETRY_INGEST_KEY"))
}

type JWTClaims struct {
	Sub string `json:"sub"`
	Exp int64  `json:"exp"`
	Iat int64  `json:"iat"`
}

func createToken(username string) (string, error) {
	claims := JWTClaims{
		Sub: username,
		Exp: time.Now().Add(24 * time.Hour).Unix(),
		Iat: time.Now().Unix(),
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}

	encHeader := base64.RawURLEncoding.EncodeToString([]byte(jwtHeader))
	encPayload := base64.RawURLEncoding.EncodeToString(payload)

	message := encHeader + "." + encPayload
	mac := hmac.New(sha256.New, jwtSecret)
	mac.Write([]byte(message))
	sig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))

	return message + "." + sig, nil
}

func validateToken(token string) (string, bool) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return "", false
	}
	if parts[0] != base64.RawURLEncoding.EncodeToString([]byte(jwtHeader)) {
		return "", false
	}

	message := parts[0] + "." + parts[1]
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return "", false
	}

	mac := hmac.New(sha256.New, jwtSecret)
	mac.Write([]byte(message))
	expected := mac.Sum(nil)

	if subtle.ConstantTimeCompare(sig, expected) != 1 {
		return "", false
	}

	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", false
	}

	var claims JWTClaims
	if err := json.Unmarshal(payload, &claims); err != nil {
		return "", false
	}

	now := time.Now().Unix()
	if claims.Sub == "" || claims.Exp <= now || claims.Iat <= 0 || claims.Iat > now+60 {
		return "", false
	}
	if _, ok := adminUsers[claims.Sub]; !ok {
		return "", false
	}

	return claims.Sub, true
}

type Payload struct {
	InstanceID  string    `json:"instance_id"`
	Hostname    string    `json:"hostname"`
	GoVersion   string    `json:"go_version"`
	OS          string    `json:"os"`
	Arch        string    `json:"arch"`
	Kernel      string    `json:"kernel"`
	CPUModel    string    `json:"cpu_model"`
	CPUCores    int       `json:"cpu_cores"`
	RAMTotalMB  int64     `json:"ram_total_mb"`
	DiskTotalMB int64     `json:"disk_total_mb"`
	DiskFreeMB  int64     `json:"disk_free_mb"`
	Uptime      string    `json:"uptime"`
	EventType   string    `json:"event_type"`
	Timestamp   time.Time `json:"timestamp"`
	App         *AppStats `json:"app,omitempty"`
}

type ErrorInfo struct {
	Kind     string    `json:"kind"`
	Message  string    `json:"message"`
	Count    uint64    `json:"count"`
	LastSeen time.Time `json:"last_seen"`
}

type AppStats struct {
	Routes           int               `json:"routes"`
	Users            int               `json:"users"`
	Requests         uint64            `json:"requests"`
	Blocked          uint64            `json:"blocked"`
	ProxyErrors      uint64            `json:"proxy_errors"`
	TotalErrors      uint64            `json:"total_errors"`
	AvgLatency       float64           `json:"avg_latency_ms"`
	StatusCodes      map[string]uint64 `json:"status_codes,omitempty"`
	BlockReasons     map[string]uint64 `json:"block_reasons,omitempty"`
	ErrorStatusCodes map[string]uint64 `json:"error_status_codes,omitempty"`
	RecentErrors     []ErrorInfo       `json:"recent_errors,omitempty"`
}

type Event struct {
	InstanceID  string    `json:"instance_id"`
	Hostname    string    `json:"hostname"`
	EventType   string    `json:"event_type"`
	Timestamp   time.Time `json:"timestamp"`
	GoVersion   string    `json:"go_version"`
	OS          string    `json:"os"`
	Arch        string    `json:"arch"`
	Kernel      string    `json:"kernel"`
	CPUModel    string    `json:"cpu_model"`
	CPUCores    int       `json:"cpu_cores"`
	RAMTotalMB  int64     `json:"ram_total_mb"`
	DiskTotalMB int64     `json:"disk_total_mb"`
	DiskFreeMB  int64     `json:"disk_free_mb"`
	Uptime      string    `json:"uptime"`
	App         *AppStats `json:"app,omitempty"`
}

type Agent struct {
	InstanceID  string    `json:"instance_id"`
	Hostname    string    `json:"hostname"`
	GoVersion   string    `json:"go_version"`
	OS          string    `json:"os"`
	Arch        string    `json:"arch"`
	Kernel      string    `json:"kernel"`
	CPUModel    string    `json:"cpu_model"`
	CPUCores    int       `json:"cpu_cores"`
	RAMTotalMB  int64     `json:"ram_total_mb"`
	DiskTotalMB int64     `json:"disk_total_mb"`
	DiskFreeMB  int64     `json:"disk_free_mb"`
	Uptime      string    `json:"uptime"`
	App         *AppStats `json:"app,omitempty"`
	FirstSeen   time.Time `json:"first_seen"`
	LastSeen    time.Time `json:"last_seen"`
	Heartbeats  int       `json:"heartbeats"`
	Status      string    `json:"status"`
	LastEvent   string    `json:"last_event_type"`
}

type ServerStats struct {
	Uptime      string `json:"uptime"`
	Agents      int    `json:"agent_count"`
	Events      uint64 `json:"total_events"`
	TotalErrors uint64 `json:"total_errors"`
	StartedAt   string `json:"started_at"`
}

type Server struct {
	mu         sync.RWMutex
	agents     map[string]*Agent
	events     []Event
	eventStart int
	eventCount int
	total      uint64
	errors     uint64
	started    time.Time
	address    string
	ingestKey  []byte
}

const (
	maxEvents               = 5000
	maxAgents               = 10000
	defaultEventLimit       = 200
	maxEventLimit           = 1000
	maxTelemetryBodyBytes   = 128 << 10
	maxLoginBodyBytes       = 4 << 10
	maxInstanceIDBytes      = 160
	maxTelemetryStringBytes = 512
	maxMetricMapEntries     = 128
	maxRecentErrors         = 32
)

var errBodyTooLarge = errors.New("request body too large")

const (
	ansiReset = "\x1b[0m"
	ansiDim   = "\x1b[2m"
	ansiBold  = "\x1b[1m"
	ansiBlue  = "\x1b[34m"
	ansiGreen = "\x1b[32m"
	ansiAmber = "\x1b[33m"
	ansiRed   = "\x1b[31m"
	ansiCyan  = "\x1b[36m"
)

func NewServer(address string) *Server {
	return &Server{
		agents:    make(map[string]*Agent),
		events:    make([]Event, maxEvents),
		started:   time.Now(),
		address:   address,
		ingestKey: append([]byte(nil), configuredIngestKey...),
	}
}

func (s *Server) authMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		if !strings.HasPrefix(auth, "Bearer ") || len(auth) == len("Bearer ") {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
			return
		}
		token := strings.TrimPrefix(auth, "Bearer ")
		if _, ok := validateToken(token); !ok {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid or expired token"})
			return
		}
		next(w, r)
	}
}

func (s *Server) ingestAuthMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if len(s.ingestKey) > 0 && !constantTimeEqual(r.Header.Get("X-Telemetry-Key"), string(s.ingestKey)) {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid telemetry key"})
			return
		}
		next(w, r)
	}
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		if strings.HasPrefix(r.URL.Path, "/api") {
			w.Header().Set("Cache-Control", "no-store")
		}
		next.ServeHTTP(w, r)
	})
}

func constantTimeEqual(left, right string) bool {
	leftHash := sha256.Sum256([]byte(left))
	rightHash := sha256.Sum256([]byte(right))
	return subtle.ConstantTimeCompare(leftHash[:], rightHash[:]) == 1
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	var creds struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := decodeJSONBody(w, r, &creds, maxLoginBodyBytes); err != nil {
		writeDecodeError(w, err)
		return
	}

	expectedPass, ok := adminUsers[creds.Username]
	if !ok {
		expectedPass = "invalid-credential-placeholder"
	}
	validPassword := constantTimeEqual(creds.Password, expectedPass)
	if !ok || !validPassword {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid username or password"})
		return
	}

	token, err := createToken(creds.Username)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to create token"})
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"token": token,
		"user":  creds.Username,
	})
}

func (s *Server) handleAgents(w http.ResponseWriter, r *http.Request) {
	s.mu.RLock()

	ids := make([]string, 0, len(s.agents))
	for id := range s.agents {
		ids = append(ids, id)
	}
	sort.Strings(ids)

	agents := make([]Agent, len(ids))
	now := time.Now()
	for i, id := range ids {
		agents[i] = cloneAgent(s.agents[id], now)
	}
	s.mu.RUnlock()

	writeJSON(w, http.StatusOK, agents)
}

func (s *Server) handleAgentDetail(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")

	s.mu.RLock()
	a, ok := s.agents[id]
	if !ok {
		s.mu.RUnlock()
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "agent not found"})
		return
	}

	agent := cloneAgent(a, time.Now())
	agentEvents := s.recentEventsLocked(maxEventLimit, id)
	s.mu.RUnlock()

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"agent":  agent,
		"events": agentEvents,
	})
}

func (s *Server) handleStats(w http.ResponseWriter, r *http.Request) {
	s.mu.RLock()

	stats := ServerStats{
		Uptime:      time.Since(s.started).Round(time.Second).String(),
		Agents:      len(s.agents),
		Events:      s.total,
		TotalErrors: s.errors,
		StartedAt:   s.started.Format(time.RFC3339),
	}
	s.mu.RUnlock()

	writeJSON(w, http.StatusOK, stats)
}

func (s *Server) handleEvents(w http.ResponseWriter, r *http.Request) {
	limit, err := eventLimit(r)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	s.mu.RLock()
	result := s.recentEventsLocked(limit, "")
	s.mu.RUnlock()

	writeJSON(w, http.StatusOK, result)
}

func (s *Server) handleTelemetry(w http.ResponseWriter, r *http.Request) {
	var p Payload
	if err := decodeJSONBody(w, r, &p, maxTelemetryBodyBytes); err != nil {
		writeDecodeError(w, err)
		return
	}
	if err := validatePayload(&p); err != nil {
		writeJSON(w, http.StatusUnprocessableEntity, map[string]string{"error": err.Error()})
		return
	}

	now := time.Now()
	eventApp := cloneAppStats(p.App)
	agentApp := cloneAppStats(p.App)

	s.mu.Lock()
	a, ok := s.agents[p.InstanceID]
	if !ok && len(s.agents) >= maxAgents {
		s.mu.Unlock()
		writeJSON(w, http.StatusTooManyRequests, map[string]string{"error": "agent capacity reached"})
		return
	}

	s.total++

	event := Event{
		InstanceID:  p.InstanceID,
		Hostname:    p.Hostname,
		EventType:   p.EventType,
		Timestamp:   now,
		GoVersion:   p.GoVersion,
		OS:          p.OS,
		Arch:        p.Arch,
		Kernel:      p.Kernel,
		CPUModel:    p.CPUModel,
		CPUCores:    p.CPUCores,
		RAMTotalMB:  p.RAMTotalMB,
		DiskTotalMB: p.DiskTotalMB,
		DiskFreeMB:  p.DiskFreeMB,
		Uptime:      p.Uptime,
		App:         eventApp,
	}
	s.appendEventLocked(event)

	if !ok {
		a = &Agent{
			InstanceID: p.InstanceID,
			FirstSeen:  now,
		}
		s.agents[p.InstanceID] = a
	}
	previousErrors := eventErrors(a.App)
	a.Hostname = p.Hostname
	a.GoVersion = p.GoVersion
	a.OS = p.OS
	a.Arch = p.Arch
	a.Kernel = p.Kernel
	a.CPUModel = p.CPUModel
	a.CPUCores = p.CPUCores
	a.RAMTotalMB = p.RAMTotalMB
	a.DiskTotalMB = p.DiskTotalMB
	a.DiskFreeMB = p.DiskFreeMB
	a.Uptime = p.Uptime
	a.App = agentApp
	a.LastSeen = now
	a.Heartbeats++
	a.LastEvent = p.EventType
	currentErrors := eventErrors(a.App)
	s.errors = s.errors - previousErrors + currentErrors
	s.mu.Unlock()

	logLine("telemetry", p.EventType, fmt.Sprintf("agent=%s host=%s errors=%d", trunc(p.InstanceID, 8), ifBlank(p.Hostname, "-"), eventErrors(event.App)))

	w.WriteHeader(http.StatusNoContent)
}

func decodeJSONBody(w http.ResponseWriter, r *http.Request, dst any, limit int64) error {
	r.Body = http.MaxBytesReader(w, r.Body, limit)
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(dst); err != nil {
		var maxErr *http.MaxBytesError
		if errors.As(err, &maxErr) {
			return errBodyTooLarge
		}
		return fmt.Errorf("invalid JSON body: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		if err == nil {
			return errors.New("request body must contain one JSON object")
		}
		var maxErr *http.MaxBytesError
		if errors.As(err, &maxErr) {
			return errBodyTooLarge
		}
		return errors.New("request body must contain one JSON object")
	}
	return nil
}

func writeDecodeError(w http.ResponseWriter, err error) {
	status := http.StatusBadRequest
	message := "invalid request body"
	if errors.Is(err, errBodyTooLarge) {
		status = http.StatusRequestEntityTooLarge
		message = errBodyTooLarge.Error()
	}
	writeJSON(w, status, map[string]string{"error": message})
}

func validatePayload(p *Payload) error {
	if strings.TrimSpace(p.InstanceID) == "" {
		return errors.New("instance_id is required")
	}
	if len(p.InstanceID) > maxInstanceIDBytes {
		return fmt.Errorf("instance_id exceeds %d bytes", maxInstanceIDBytes)
	}
	if p.EventType != "startup" && p.EventType != "heartbeat" && p.EventType != "shutdown" {
		return errors.New("event_type must be startup, heartbeat, or shutdown")
	}
	for name, value := range map[string]string{
		"hostname": p.Hostname, "go_version": p.GoVersion, "os": p.OS,
		"arch": p.Arch, "kernel": p.Kernel, "cpu_model": p.CPUModel, "uptime": p.Uptime,
	} {
		if len(value) > maxTelemetryStringBytes {
			return fmt.Errorf("%s exceeds %d bytes", name, maxTelemetryStringBytes)
		}
	}
	if p.CPUCores < 0 || p.RAMTotalMB < 0 || p.DiskTotalMB < 0 || p.DiskFreeMB < 0 {
		return errors.New("system metrics cannot be negative")
	}
	if p.DiskTotalMB > 0 && p.DiskFreeMB > p.DiskTotalMB {
		return errors.New("disk_free_mb cannot exceed disk_total_mb")
	}
	if p.App == nil {
		return nil
	}
	if p.App.Routes < 0 || p.App.Users < 0 || p.App.AvgLatency < 0 {
		return errors.New("application metrics cannot be negative")
	}
	for name, values := range map[string]map[string]uint64{
		"status_codes":       p.App.StatusCodes,
		"block_reasons":      p.App.BlockReasons,
		"error_status_codes": p.App.ErrorStatusCodes,
	} {
		if len(values) > maxMetricMapEntries {
			return fmt.Errorf("%s exceeds %d entries", name, maxMetricMapEntries)
		}
		for key := range values {
			if len(key) > maxTelemetryStringBytes {
				return fmt.Errorf("%s contains an oversized key", name)
			}
		}
	}
	if len(p.App.RecentErrors) > maxRecentErrors {
		return fmt.Errorf("recent_errors exceeds %d entries", maxRecentErrors)
	}
	for _, recent := range p.App.RecentErrors {
		if len(recent.Kind) > maxTelemetryStringBytes || len(recent.Message) > maxTelemetryStringBytes*2 {
			return errors.New("recent_errors contains an oversized value")
		}
	}
	return nil
}

func writeJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data)
}

func (s *Server) appendEventLocked(event Event) {
	if s.eventCount < maxEvents {
		index := (s.eventStart + s.eventCount) % maxEvents
		s.events[index] = event
		s.eventCount++
		return
	}
	s.events[s.eventStart] = event
	s.eventStart = (s.eventStart + 1) % maxEvents
}

func (s *Server) recentEventsLocked(limit int, instanceID string) []Event {
	if limit > s.eventCount {
		limit = s.eventCount
	}
	result := make([]Event, 0, limit)
	for offset := 0; offset < s.eventCount && len(result) < limit; offset++ {
		index := (s.eventStart + s.eventCount - 1 - offset) % maxEvents
		event := s.events[index]
		if instanceID == "" || event.InstanceID == instanceID {
			result = append(result, event)
		}
	}
	return result
}

func eventLimit(r *http.Request) (int, error) {
	value := r.URL.Query().Get("limit")
	if value == "" {
		return defaultEventLimit, nil
	}
	limit, err := strconv.Atoi(value)
	if err != nil || limit < 1 || limit > maxEventLimit {
		return 0, fmt.Errorf("limit must be between 1 and %d", maxEventLimit)
	}
	return limit, nil
}

func cloneAgent(src *Agent, now time.Time) Agent {
	status := "online"
	if src.LastEvent == "shutdown" || now.Sub(src.LastSeen) > 5*time.Minute {
		status = "offline"
	}
	out := *src
	out.App = cloneAppStats(src.App)
	out.Status = status
	return out
}

func cloneAppStats(src *AppStats) *AppStats {
	if src == nil {
		return nil
	}
	out := *src
	out.StatusCodes = cloneStringUint64Map(src.StatusCodes)
	out.BlockReasons = cloneStringUint64Map(src.BlockReasons)
	out.ErrorStatusCodes = cloneStringUint64Map(src.ErrorStatusCodes)
	if len(src.RecentErrors) > 0 {
		out.RecentErrors = append([]ErrorInfo(nil), src.RecentErrors...)
	}
	return &out
}

func cloneStringUint64Map(src map[string]uint64) map[string]uint64 {
	if len(src) == 0 {
		return nil
	}
	out := make(map[string]uint64, len(src))
	for k, v := range src {
		out[k] = v
	}
	return out
}

func eventErrors(app *AppStats) uint64 {
	if app == nil {
		return 0
	}
	return app.TotalErrors
}

func logLine(scope, label, message string) {
	ts := time.Now().Format("15:04:05")
	if os.Getenv("NO_COLOR") != "" {
		fmt.Fprintf(os.Stderr, "%s %-12s %-9s %s\n", ts, scope, strings.ToUpper(label), message)
		return
	}
	fmt.Fprintf(os.Stderr, "%s%s%s %s%-12s%s %s%-9s%s %s\n",
		ansiDim, ts, ansiReset,
		ansiCyan, scope, ansiReset,
		logColor(label), strings.ToUpper(label), ansiReset,
		message)
}

func logColor(label string) string {
	switch strings.ToLower(label) {
	case "startup", "start", "info", "listening":
		return ansiGreen
	case "shutdown", "error", "fatal":
		return ansiRed
	case "warn", "clear":
		return ansiAmber
	case "heartbeat":
		return ansiBlue
	default:
		return ansiBold
	}
}

func ifBlank(s, fallback string) string {
	if strings.TrimSpace(s) == "" {
		return fallback
	}
	return s
}

func (s *Server) printAgents() {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if len(s.agents) == 0 {
		fmt.Println("  No agents connected.")
		return
	}

	ids := make([]string, 0, len(s.agents))
	for id := range s.agents {
		ids = append(ids, id)
	}
	sort.Strings(ids)

	fmt.Printf("\n  %-36s %-20s %-10s %-8s %-12s %-10s\n", "Instance ID", "Hostname", "OS/Arch", "Go", "Heartbeats", "Last Seen")
	fmt.Println(strings.Repeat("-", 100))
	for _, id := range ids {
		a := s.agents[id]
		fmt.Printf("  %-36s %-20s %-10s %-8s %-12d %-10s\n",
			trunc(a.InstanceID, 34), trunc(a.Hostname, 18),
			a.OS+"/"+a.Arch, a.GoVersion, a.Heartbeats,
			a.LastSeen.Format("15:04:05"))
	}
}

func (s *Server) printStats() {
	s.mu.RLock()
	defer s.mu.RUnlock()

	fmt.Printf("\n  Telemetry Server Stats:\n")
	fmt.Printf("    Uptime:          %s\n", time.Since(s.started).Round(time.Second))
	fmt.Printf("    Connected agents:  %d\n", len(s.agents))
	fmt.Printf("    Total events:    %d\n", s.total)
}

func (s *Server) clear() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.agents = make(map[string]*Agent)
	s.events = make([]Event, maxEvents)
	s.eventStart = 0
	s.eventCount = 0
	s.total = 0
	s.errors = 0
	logLine("repl", "clear", "telemetry data cleared")
}

func trunc(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "\u2026"
}

func (s *Server) handler() http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("POST /api/login", s.handleLogin)
	mux.HandleFunc("GET /api/agents", s.authMiddleware(s.handleAgents))
	mux.HandleFunc("GET /api/agents/{id}", s.authMiddleware(s.handleAgentDetail))
	mux.HandleFunc("GET /api/stats", s.authMiddleware(s.handleStats))
	mux.HandleFunc("GET /api/events", s.authMiddleware(s.handleEvents))
	mux.HandleFunc("POST /api", s.ingestAuthMiddleware(s.handleTelemetry))
	mux.HandleFunc("POST /api/telemetry", s.ingestAuthMiddleware(s.handleTelemetry))
	mux.HandleFunc("GET /health", s.handleHealth)
	mux.HandleFunc("GET /api/health", s.handleHealth)
	mux.HandleFunc("GET /static/index.html", serveDashboard)

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/api/") || r.URL.Path == "/api" {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "endpoint not found"})
			return
		}
		if r.Method == http.MethodGet {
			serveDashboard(w, r)
			return
		}
		if r.Method == http.MethodPost && r.URL.Path == "/" {
			s.ingestAuthMiddleware(s.handleTelemetry)(w, r)
			return
		}
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
	})
	return securityHeaders(mux)
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"status":         "ok",
		"uptime_seconds": int64(time.Since(s.started).Seconds()),
	})
}

func serveDashboard(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	http.ServeContent(w, r, "index.html", time.Time{}, bytes.NewReader(dashboardHTML))
}

func listenAddress(args []string) (string, error) {
	address := os.Getenv("TELEMETRY_ADDR")
	if address == "" {
		address = "127.0.0.1:9091"
	}
	if len(args) > 1 {
		return "", errors.New("usage: telemetry-server [port|host:port]")
	}
	if len(args) == 1 {
		value := strings.TrimSpace(args[0])
		if value == "" {
			return "", errors.New("listen address cannot be empty")
		}
		if _, err := strconv.Atoi(value); err == nil {
			address = net.JoinHostPort("127.0.0.1", value)
		} else {
			address = value
		}
	}
	if strings.HasPrefix(address, ":") {
		address = "0.0.0.0" + address
	}
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return "", fmt.Errorf("invalid listen address %q: %w", address, err)
	}
	portNumber, err := strconv.Atoi(port)
	if err != nil || portNumber < 1 || portNumber > 65535 {
		return "", fmt.Errorf("invalid listen port %q", port)
	}
	if host == "" {
		return "", errors.New("listen address must include a host")
	}
	return address, nil
}

func main() {
	address, err := listenAddress(os.Args[1:])
	if err != nil {
		logLine("server", "fatal", err.Error())
		os.Exit(2)
	}

	srv := NewServer(address)

	server := &http.Server{
		Addr:              address,
		Handler:           srv.handler(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    16 << 10,
	}

	ctx, stopSignals := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stopSignals()
	shutdown := make(chan struct{}, 1)
	serveErrors := make(chan error, 1)

	go func() {
		logLine("server", "listening", fmt.Sprintf("addr=%s dashboard=http://%s api=http://%s/api/", address, address, address))
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			serveErrors <- err
		}
	}()

	if usingDefaultAdmin {
		logLine("auth", "warn", "using default admin password; set TELEMETRY_ADMIN_PASSWORD")
	}
	if usingEphemeralJWT {
		logLine("auth", "warn", "using an ephemeral JWT secret; set TELEMETRY_JWT_SECRET to preserve sessions across restarts")
	}
	if len(srv.ingestKey) == 0 {
		logLine("auth", "warn", "telemetry ingestion is unauthenticated; set TELEMETRY_INGEST_KEY")
	}

	go func() {
		logLine("repl", "start", "type help for commands")
		scanner := bufio.NewScanner(os.Stdin)
		for {
			fmt.Fprint(os.Stderr, "> ")
			if !scanner.Scan() {
				return
			}
			cmd := strings.TrimSpace(scanner.Text())
			switch {
			case cmd == "":
				continue
			case cmd == "help":
				fmt.Fprint(os.Stderr, "\n  Commands:\n    agents      List connected agents\n    stats       Show server statistics\n    clear       Clear all telemetry data\n    help        Show this help\n    exit, quit  Shutdown server\n")
			case cmd == "agents":
				srv.printAgents()
			case cmd == "stats":
				srv.printStats()
			case cmd == "clear":
				srv.clear()
			case cmd == "exit" || cmd == "quit":
				logLine("repl", "shutdown", "bye")
				select {
				case shutdown <- struct{}{}:
				default:
				}
				return
			default:
				logLine("repl", "warn", fmt.Sprintf("unknown command=%s", cmd))
			}
		}
	}()

	select {
	case <-ctx.Done():
		logLine("server", "shutdown", "signal received")
	case <-shutdown:
	case err := <-serveErrors:
		logLine("server", "error", err.Error())
		return
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := server.Shutdown(shutdownCtx); err != nil {
		logLine("server", "error", fmt.Sprintf("graceful shutdown: %v", err))
	}
}
