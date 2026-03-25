package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strings"
)

type Config struct {
	ListenAddr string
}

type Server struct {
	srv *http.Server
}

func Start(ctx context.Context, cfg Config) (*Server, error) {
	addr := strings.TrimSpace(cfg.ListenAddr)
	if addr == "" {
		return nil, nil
	}

	mux := http.NewServeMux()
	registerRoutes(mux)

	srv := &http.Server{
		Addr:    addr,
		Handler: mux,
	}

	log.Printf("starting HTTP API on %s", addr)

	go func() {
		<-ctx.Done()
		_ = srv.Shutdown(context.Background())
	}()

	go func() {
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Printf("api server failed: %v", err)
		}
	}()

	return &Server{srv: srv}, nil
}

func (s *Server) Shutdown(ctx context.Context) error {
	if s == nil || s.srv == nil {
		return nil
	}
	return s.srv.Shutdown(ctx)
}

func registerRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/api/requests/recent", handleRecentRequests)
	mux.HandleFunc("/api/requests/top-threats", handleTopThreats)
	mux.HandleFunc("/api/fingerprints/top-common", handleTopFingerprints)
	mux.HandleFunc("/api/stats/timeseries", handleTimeseries)
	mux.HandleFunc("/api/stats/total", handleTotals)
}

func handleRecentRequests(w http.ResponseWriter, r *http.Request) {
	// TODO: Populate with the 10 most recent TLS handshakes once they are persisted with threat scores.
	respondNotImplemented(w, "recent TLS handshakes with threat scores and verdicts")
}

func handleTopThreats(w http.ResponseWriter, r *http.Request) {
	// TODO: Return highest threat scored requests once scoring results are stored.
	respondNotImplemented(w, "stored TLS handshakes with matched signatures and threat scores")
}

func handleTopFingerprints(w http.ResponseWriter, r *http.Request) {
	// TODO: Calculate common JA3 fingerprints after storing handshake fingerprints and counts.
	respondNotImplemented(w, "persisted JA3 fingerprints with counts and average threat scores")
}

func handleTimeseries(w http.ResponseWriter, r *http.Request) {
	// TODO: Emit hourly request counts by verdict once handshake metadata is recorded over time.
	respondNotImplemented(w, "timeseries of handshake counts segmented by verdict")
}

func handleTotals(w http.ResponseWriter, r *http.Request) {
	// TODO: Serve totals by verdict after capturing and persisting handshake verdicts.
	respondNotImplemented(w, "total request counts grouped by verdict")
}

func respondNotImplemented(w http.ResponseWriter, missing string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusNotImplemented)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"error":  "not implemented",
		"reason": fmt.Sprintf("requires %s", missing),
	})
}
