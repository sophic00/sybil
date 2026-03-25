package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"time"
)

func RegisterRoutes(mux *http.ServeMux, store Store) {
	if mux == nil {
		return
	}

	mux.Handle("/api/stats/total", apiHandler(store, func(r *http.Request) (any, error) {
		return store.TotalStats(r.Context())
	}))
	mux.Handle("/api/stats/timeseries", apiHandler(store, func(r *http.Request) (any, error) {
		return store.Timeseries(r.Context(), time.Now())
	}))
	mux.Handle("/api/requests/recent", apiHandler(store, func(r *http.Request) (any, error) {
		return store.RecentRequests(r.Context(), defaultRecentLimit)
	}))
	mux.Handle("/api/requests/top-threats", apiHandler(store, func(r *http.Request) (any, error) {
		return store.TopThreats(r.Context(), defaultTopLimit, time.Now())
	}))
	mux.Handle("/api/fingerprints/top-common", apiHandler(store, func(r *http.Request) (any, error) {
		return store.TopCommonFingerprints(r.Context(), defaultTopLimit)
	}))
	mux.Handle("/api/fingerprints/frequent-last-hour", apiHandler(store, func(r *http.Request) (any, error) {
		return store.FrequentFingerprintsLastHour(r.Context(), time.Now(), 2)
	}))
	mux.Handle("/api/fingerprints/top-last-hour", apiHandler(store, func(r *http.Request) (any, error) {
		return store.TopFingerprintsLastHour(r.Context(), time.Now(), 10)
	}))
}

type routeFunc func(r *http.Request) (any, error)

func apiHandler(store Store, fn routeFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		applyCORS(w)
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		if r.Method != http.MethodGet {
			writeError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		if store == nil {
			writeError(w, http.StatusServiceUnavailable, "api store unavailable")
			return
		}

		payload, err := fn(r)
		if err != nil {
			status := http.StatusInternalServerError
			if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
				status = http.StatusRequestTimeout
			}
			writeError(w, status, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, payload)
	})
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]string{"error": message})
}

func applyCORS(w http.ResponseWriter) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
}
