// Package callin is the inbound half: Oddjob reaching into Jaws.
//
// This is the smaller and more dangerous of the two channels. It is an
// HTTP listener on a privileged process, so it does as little as
// possible: report status, and ask the loop to poll now. It cannot be
// used to run anything — tasking arrives over the outbound channel,
// where the agent authenticated the server, not the other way round.
//
// Disabled unless --listen is given, bound to loopback by default, and
// refuses to start without a key.
package callin

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"time"
)

type Waker interface {
	Wake()
	Status() map[string]any
}

type Server struct {
	key  string
	wake Waker
	srv  *http.Server
}

func New(addr, key string, w Waker) *Server {
	s := &Server{key: key, wake: w}
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", s.health)
	mux.HandleFunc("/status", s.auth(s.status))
	mux.HandleFunc("/poll", s.auth(s.poll))
	s.srv = &http.Server{
		Addr:    addr,
		Handler: mux,
		// Bounded so a half-open connection cannot pin a goroutine on
		// an agent that may run for months.
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
	return s
}

// auth compares in constant time. The key is the only thing between
// this endpoint and anyone who can reach the port.
func (s *Server) auth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		got := r.Header.Get("X-Jaws-Call-In-Key")
		if got == "" {
			if a := r.Header.Get("Authorization"); len(a) > 7 &&
				(a[:7] == "Bearer " || a[:7] == "bearer ") {
				got = a[7:]
			}
		}
		if subtle.ConstantTimeCompare([]byte(got), []byte(s.key)) != 1 {
			http.Error(w, `{"error":"bad or missing call-in key"}`,
				http.StatusUnauthorized)
			return
		}
		next(w, r)
	}
}

// health is deliberately unauthenticated and says nothing: it exists
// so a load balancer or systemd can tell the process is alive without
// being handed a key.
func (s *Server) health(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Server) status(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, s.wake.Status())
}

func (s *Server) poll(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "POST"})
		return
	}
	s.wake.Wake()
	writeJSON(w, http.StatusAccepted, map[string]any{"ok": true, "woken": true})
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func (s *Server) Start() {
	go func() {
		log.Printf("call-in API listening on %s", s.srv.Addr)
		if err := s.srv.ListenAndServe(); err != nil &&
			!errors.Is(err, http.ErrServerClosed) {
			log.Printf("call-in API stopped: %v", err)
		}
	}()
}

func (s *Server) Stop(ctx context.Context) {
	_ = s.srv.Shutdown(ctx)
}
