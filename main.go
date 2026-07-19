package main

import (
	"bufio"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"sort"
	"strings"
	"sync"
	"time"
)

var jwtSecret []byte
var adminUsers = map[string]string{}

func init() {
	secret := os.Getenv("TELEMETRY_JWT_SECRET")
	if secret == "" {
		secret = "telemetry-dev-secret"
	}
	jwtSecret = []byte(secret)

	pass := os.Getenv("TELEMETRY_ADMIN_PASSWORD")
	if pass == "" {
		pass = "admin"
	}
	adminUsers["admin"] = pass
}

type JWTClaims struct {
	Sub string `json:"sub"`
	Exp int64  `json:"exp"`
	Iat int64  `json:"iat"`
}

func createToken(username string) (string, error) {
	header := `{"alg":"HS256","typ":"JWT"}`
	claims := JWTClaims{
		Sub: username,
		Exp: time.Now().Add(24 * time.Hour).Unix(),
		Iat: time.Now().Unix(),
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}

	encHeader := base64.RawURLEncoding.EncodeToString([]byte(header))
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

	if time.Now().Unix() > claims.Exp {
		return "", false
	}

	return claims.Sub, true
}

type Payload struct {
	InstanceID string    `json:"instance_id"`
	Hostname   string    `json:"hostname"`
	GoVersion  string    `json:"go_version"`
	OS         string    `json:"os"`
	Arch       string    `json:"arch"`
	Kernel     string    `json:"kernel"`
	CPUModel   string    `json:"cpu_model"`
	CPUCores   int       `json:"cpu_cores"`
	RAMTotalMB int64     `json:"ram_total_mb"`
	DiskTotalMB int64    `json:"disk_total_mb"`
	DiskFreeMB int64     `json:"disk_free_mb"`
	Uptime     string    `json:"uptime"`
	EventType  string    `json:"event_type"`
	Timestamp  time.Time `json:"timestamp"`
	App        *AppStats `json:"app,omitempty"`
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
	InstanceID string    `json:"instance_id"`
	Hostname   string    `json:"hostname"`
	EventType  string    `json:"event_type"`
	Timestamp  time.Time `json:"timestamp"`
	GoVersion  string    `json:"go_version"`
	OS         string    `json:"os"`
	Arch       string    `json:"arch"`
	Kernel     string    `json:"kernel"`
	CPUModel   string    `json:"cpu_model"`
	CPUCores   int       `json:"cpu_cores"`
	RAMTotalMB int64     `json:"ram_total_mb"`
	DiskTotalMB int64    `json:"disk_total_mb"`
	DiskFreeMB int64     `json:"disk_free_mb"`
	Uptime     string    `json:"uptime"`
	App        *AppStats `json:"app,omitempty"`
}

type Agent struct {
	InstanceID string    `json:"instance_id"`
	Hostname   string    `json:"hostname"`
	GoVersion  string    `json:"go_version"`
	OS         string    `json:"os"`
	Arch       string    `json:"arch"`
	Kernel     string    `json:"kernel"`
	CPUModel   string    `json:"cpu_model"`
	CPUCores   int       `json:"cpu_cores"`
	RAMTotalMB int64     `json:"ram_total_mb"`
	DiskTotalMB int64    `json:"disk_total_mb"`
	DiskFreeMB int64     `json:"disk_free_mb"`
	Uptime     string    `json:"uptime"`
	App        *AppStats `json:"app,omitempty"`
	FirstSeen  time.Time `json:"first_seen"`
	LastSeen   time.Time `json:"last_seen"`
	Heartbeats int       `json:"heartbeats"`
	Status     string    `json:"status"`
}

type ServerStats struct {
	Uptime      string `json:"uptime"`
	Agents      int    `json:"agent_count"`
	Events      int    `json:"total_events"`
	TotalErrors uint64 `json:"total_errors"`
	StartedAt   string `json:"started_at"`
}

type Server struct {
	mu      sync.RWMutex
	agents  map[string]*Agent
	events  []Event
	total   int
	errors  uint64
	started time.Time
	port    string
}

const maxEvents = 5000

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

func NewServer(port string) *Server {
	return &Server{
		agents:  make(map[string]*Agent),
		events:  make([]Event, 0, maxEvents),
		started: time.Now(),
		port:    port,
	}
}

func (s *Server) authMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		auth := r.Header.Get("Authorization")
		if !strings.HasPrefix(auth, "Bearer ") {
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

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	var creds struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&creds); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}

	expectedPass, ok := adminUsers[creds.Username]
	if !ok || subtle.ConstantTimeCompare([]byte(creds.Password), []byte(expectedPass)) != 1 {
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
	w.Header().Set("Content-Type", "application/json")
	s.mu.RLock()
	defer s.mu.RUnlock()

	ids := make([]string, 0, len(s.agents))
	for id := range s.agents {
		ids = append(ids, id)
	}
	sort.Strings(ids)

	agents := make([]Agent, len(ids))
	for i, id := range ids {
		a := s.agents[id]
		status := "online"
		if time.Since(a.LastSeen) > 5*time.Minute {
			status = "offline"
		}
		agents[i] = Agent{
			InstanceID: a.InstanceID,
			Hostname:   a.Hostname,
			GoVersion:  a.GoVersion,
			OS:         a.OS,
			Arch:       a.Arch,
			Kernel:     a.Kernel,
			CPUModel:   a.CPUModel,
			CPUCores:   a.CPUCores,
			RAMTotalMB: a.RAMTotalMB,
			DiskTotalMB: a.DiskTotalMB,
			DiskFreeMB: a.DiskFreeMB,
			Uptime:     a.Uptime,
			App:        cloneAppStats(a.App),
			FirstSeen:  a.FirstSeen,
			LastSeen:   a.LastSeen,
			Heartbeats: a.Heartbeats,
			Status:     status,
		}
	}

	writeJSON(w, http.StatusOK, agents)
}

func (s *Server) handleAgentDetail(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	id := r.PathValue("id")

	s.mu.RLock()
	a, ok := s.agents[id]
	if !ok {
		s.mu.RUnlock()
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "agent not found"})
		return
	}

	status := "online"
	if time.Since(a.LastSeen) > 5*time.Minute {
		status = "offline"
	}

	agentEvents := make([]Event, 0)
	for _, e := range s.events {
		if e.InstanceID == id {
			agentEvents = append(agentEvents, e)
		}
	}
	s.mu.RUnlock()

	for i, j := 0, len(agentEvents)-1; i < j; i, j = i+1, j-1 {
		agentEvents[i], agentEvents[j] = agentEvents[j], agentEvents[i]
	}

	agent := Agent{
		InstanceID: a.InstanceID,
		Hostname:   a.Hostname,
		GoVersion:  a.GoVersion,
		OS:         a.OS,
		Arch:       a.Arch,
		Kernel:     a.Kernel,
		CPUModel:   a.CPUModel,
		CPUCores:   a.CPUCores,
		RAMTotalMB: a.RAMTotalMB,
		DiskTotalMB: a.DiskTotalMB,
		DiskFreeMB: a.DiskFreeMB,
		Uptime:     a.Uptime,
		App:        cloneAppStats(a.App),
		FirstSeen:  a.FirstSeen,
		LastSeen:   a.LastSeen,
		Heartbeats: a.Heartbeats,
		Status:     status,
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"agent":  agent,
		"events": agentEvents,
	})
}

func (s *Server) handleStats(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	s.mu.RLock()
	defer s.mu.RUnlock()

	stats := ServerStats{
		Uptime:      time.Since(s.started).Round(time.Second).String(),
		Agents:      len(s.agents),
		Events:      s.total,
		TotalErrors: s.errors,
		StartedAt:   s.started.Format(time.RFC3339),
	}

	writeJSON(w, http.StatusOK, stats)
}

func (s *Server) handleEvents(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	s.mu.RLock()
	defer s.mu.RUnlock()

	result := make([]Event, len(s.events))
	for i, e := range s.events {
		result[len(s.events)-1-i] = e
	}

	writeJSON(w, http.StatusOK, result)
}

func (s *Server) handleTelemetry(w http.ResponseWriter, r *http.Request) {
	var p Payload
	if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	s.mu.Lock()
	s.total++

	event := Event{
		InstanceID:  p.InstanceID,
		Hostname:    p.Hostname,
		EventType:   p.EventType,
		Timestamp:   time.Now(),
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
		App:         cloneAppStats(p.App),
	}
	if len(s.events) >= maxEvents {
		s.events = s.events[1:]
	}
	s.events = append(s.events, event)

	a, ok := s.agents[p.InstanceID]
	if !ok {
		a = &Agent{
			InstanceID: p.InstanceID,
			FirstSeen:  time.Now(),
		}
		s.agents[p.InstanceID] = a
	}
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
	a.App = cloneAppStats(p.App)
	a.LastSeen = time.Now()
	a.Heartbeats++
	s.errors = s.totalErrorsLocked()
	s.mu.Unlock()

	logLine("telemetry", p.EventType, fmt.Sprintf("agent=%s host=%s errors=%d", trunc(p.InstanceID, 8), ifBlank(p.Hostname, "-"), eventErrors(event.App)))

	w.WriteHeader(http.StatusOK)
}

func writeJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data)
}

func (s *Server) totalErrorsLocked() uint64 {
	var total uint64
	for _, a := range s.agents {
		if a.App != nil {
			total += a.App.TotalErrors
		}
	}
	return total
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
	s.events = make([]Event, 0, maxEvents)
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

func main() {
	port := ":9091"
	if len(os.Args) > 1 {
		port = os.Args[1]
	}
	if !strings.HasPrefix(port, ":") {
		port = ":" + port
	}

	srv := NewServer(port)

	mux := http.NewServeMux()

	mux.HandleFunc("POST /api/login", srv.handleLogin)
	mux.HandleFunc("GET /api/agents", srv.authMiddleware(srv.handleAgents))
	mux.HandleFunc("GET /api/agents/{id}", srv.authMiddleware(srv.handleAgentDetail))
	mux.HandleFunc("GET /api/stats", srv.authMiddleware(srv.handleStats))
	mux.HandleFunc("GET /api/events", srv.authMiddleware(srv.handleEvents))
	mux.HandleFunc("POST /api/telemetry", srv.handleTelemetry)

	mux.Handle("GET /static/", http.StripPrefix("/static/", http.FileServer(http.Dir("static"))))

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path

		if strings.HasPrefix(path, "/api/") {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusNotFound)
			json.NewEncoder(w).Encode(map[string]string{"error": "endpoint not found"})
			return
		}

		if r.Method == "GET" {
			http.ServeFile(w, r, "static/index.html")
			return
		}

		if r.Method == "POST" {
			srv.handleTelemetry(w, r)
			return
		}

		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	})

	server := &http.Server{
		Addr:              port,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
	}

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt)

	go func() {
		logLine("server", "listening", fmt.Sprintf("addr=%s dashboard=http://localhost%s api=http://localhost%s/api/", port, port, port))
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logLine("server", "error", err.Error())
			os.Exit(1)
		}
	}()

	go func() {
		<-stop
		logLine("server", "shutdown", "shutting down")
		server.Close()
		os.Exit(0)
	}()

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
				server.Close()
				os.Exit(0)
			default:
				logLine("repl", "warn", fmt.Sprintf("unknown command=%s", cmd))
			}
		}
	}()

	select {}
}
