package handlers

import (
	"net"
	"net/http"
	"time"

	"bty/src/go/internal/c2"
)

// Router sets up all HTTP routes with middleware.
type Router struct {
	server      *c2.Server
	rateLimiter *c2.RateLimiter
}

// NewRouter creates a new router with middleware.
func NewRouter(server *c2.Server) *Router {
	return &Router{
		server:      server,
		rateLimiter: c2.NewRateLimiter(60, time.Minute),
	}
}

// Setup configures all API routes and returns the mux.
func (r *Router) Setup() *http.ServeMux {
	mux := http.NewServeMux()

	// Start rate limiter cleanup
	go func() {
		ticker := time.NewTicker(5 * time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-r.server.Quit():
				return
			case <-ticker.C:
				r.rateLimiter.Cleanup()
			}
		}
	}()

	// Middleware chain
	cors := r.corsMiddleware()
	auth := r.authMiddleware()
	admin := r.adminMiddleware()
	audit := r.auditMiddleware()
	rate := c2.RateLimitMiddleware(r.rateLimiter)
	perm := r.requirePermission

	// Public endpoints
	mux.HandleFunc("/api/login", cors(audit(rate(r.handleLogin))))
	mux.HandleFunc("/api/refresh", cors(audit(rate(r.handleRefresh))))
	mux.HandleFunc("/api/health", cors(audit(rate(r.handleHealth))))

	// Sessions
	mux.HandleFunc("/api/sessions", cors(auth(audit(rate(perm("sessions:list")(r.handleListSessions))))))
	mux.HandleFunc("/api/sessions/", cors(auth(audit(rate(r.handleSessionDetail)))))

	// Commands
	mux.HandleFunc("/api/cmd", cors(auth(audit(rate(perm("commands:execute")(r.handleCommand))))))
	mux.HandleFunc("/api/broadcast", cors(auth(audit(rate(perm("commands:broadcast")(r.handleBroadcast))))))

	// Modules
	mux.HandleFunc("/api/modules", cors(auth(audit(rate(r.handleModules)))))
	mux.HandleFunc("/api/modules/push", cors(auth(audit(rate(r.handleModulePush)))))
	mux.HandleFunc("/api/modules/", cors(auth(audit(rate(r.handleModuleDelete)))))

	// Infrastructure
	mux.HandleFunc("/api/socks", cors(auth(audit(rate(r.handleSOCKS)))))
	mux.HandleFunc("/api/vault", cors(auth(audit(rate(r.handleVault)))))
	mux.HandleFunc("/api/files", cors(auth(audit(rate(r.handleFiles)))))
	mux.HandleFunc("/api/files/download/", cors(auth(audit(rate(r.handleFileDownload)))))
	mux.HandleFunc("/api/portfwd", cors(auth(audit(rate(r.handlePortFwd)))))

	// Operators (admin only)
	mux.HandleFunc("/api/operators", cors(auth(admin(audit(rate(r.handleOperators))))))
	mux.HandleFunc("/api/operators/", cors(auth(admin(audit(rate(r.handleOperatorDelete))))))

	// Team collaboration
	mux.HandleFunc("/api/notes", cors(auth(audit(rate(r.handleNotes)))))
	mux.HandleFunc("/api/lock", cors(auth(audit(rate(r.handleLock)))))
	mux.HandleFunc("/api/profiles", cors(auth(audit(rate(r.handleProfiles)))))

	// Reporting
	mux.HandleFunc("/api/report", cors(auth(audit(rate(r.handleReport)))))

	// SIEM webhooks (admin only)
	mux.HandleFunc("/api/webhooks", cors(auth(admin(audit(rate(r.handleWebhooks))))))

	// mTLS certificate generation (admin only)
	mux.HandleFunc("/api/mtls/cert", cors(auth(admin(audit(rate(r.handleMTLSCert))))))

	// SPA frontend
	r.serveSPA(mux)

	return mux
}

// corsMiddleware adds security headers and CORS.
func (r *Router) corsMiddleware() func(http.HandlerFunc) http.HandlerFunc {
	return func(next http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, req *http.Request) {
			w.Header().Set("X-Content-Type-Options", "nosniff")
			w.Header().Set("X-Frame-Options", "DENY")
			w.Header().Set("X-XSS-Protection", "0")
			w.Header().Set("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
			w.Header().Set("Content-Security-Policy", "default-src 'self'")

			origin := req.Header.Get("Origin")
			if origin != "" {
				allowed := map[string]bool{
					"http://localhost:9090":  true,
					"http://127.0.0.1:9090":  true,
					"http://localhost:5173":  true,
				}
				if allowed[origin] {
					w.Header().Set("Access-Control-Allow-Origin", origin)
				}
			}
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")

			if req.Method == "OPTIONS" {
				w.WriteHeader(200)
				return
			}
			next(w, req)
		}
	}
}

// authMiddleware validates JWT tokens.
func (r *Router) authMiddleware() func(http.HandlerFunc) http.HandlerFunc {
	return func(next http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, req *http.Request) {
			authHeader := req.Header.Get("Authorization")
			if authHeader == "" {
				w.Header().Set("WWW-Authenticate", `Bearer realm="BTY C2"`)
				http.Error(w, `{"error":"missing token"}`, 401)
				return
			}

			token := authHeader
			if len(authHeader) > 7 && authHeader[:7] == "Bearer " {
				token = authHeader[7:]
			}

			username, role, err := r.server.TokenManager().ValidateToken(token)
			if err != nil {
				r.server.DB().LogAction(0, "auth_failed", req.RemoteAddr)
				http.Error(w, `{"error":"invalid or expired token"}`, 401)
				return
			}

			req.Header.Set("X-Auth-User", username)
			req.Header.Set("X-Auth-Role", role)
			next(w, req)
		}
	}
}

// adminMiddleware restricts access to admin users.
func (r *Router) adminMiddleware() func(http.HandlerFunc) http.HandlerFunc {
	return func(next http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, req *http.Request) {
			if req.Header.Get("X-Auth-Role") != "admin" {
				http.Error(w, `{"error":"admin access required"}`, 403)
				return
			}
			next(w, req)
		}
	}
}

// auditMiddleware logs API calls.
func (r *Router) auditMiddleware() func(http.HandlerFunc) http.HandlerFunc {
	return func(next http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, req *http.Request) {
			ip, _, _ := net.SplitHostPort(req.RemoteAddr)
			if ip == "" {
				ip = req.RemoteAddr
			}
			user := req.Header.Get("X-Auth-User")
			if user == "" {
				user = "anonymous"
			}
			r.server.DB().LogAction(0, "api_call", req.Method+" "+req.URL.Path+" from "+ip+" by "+user)
			next(w, req)
		}
	}
}

// requirePermission checks RBAC permissions.
func (r *Router) requirePermission(permission string) func(http.HandlerFunc) http.HandlerFunc {
	return func(next http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, req *http.Request) {
			role := req.Header.Get("X-Auth-Role")
			if role == "" {
				http.Error(w, `{"error":"authentication required"}`, 401)
				return
			}
			if !r.server.RBAC().HasPermission(role, permission) {
				r.server.DB().LogAction(0, "auth_denied", req.Method+" "+req.URL.Path+" by "+req.Header.Get("X-Auth-User")+" ("+role+")")
				http.Error(w, `{"error":"insufficient permissions"}`, 403)
				return
			}
			next(w, req)
		}
	}
}
