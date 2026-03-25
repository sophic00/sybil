package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/sophic00/sybil/internal/risk"
)

type fakeStore struct {
	total       TotalStats
	timeseries  []TimeseriesEntry
	recent      []TLSRequest
	topThreats  []TLSRequest
	topCommon   []FingerprintEntry
	readErr     error
	recordCalls int
}

func (f *fakeStore) Record(context.Context, RequestObservation) error {
	f.recordCalls++
	return nil
}

func (f *fakeStore) TotalStats(context.Context) (TotalStats, error) {
	return f.total, f.readErr
}

func (f *fakeStore) Timeseries(context.Context, time.Time) ([]TimeseriesEntry, error) {
	return f.timeseries, f.readErr
}

func (f *fakeStore) RecentRequests(context.Context, int) ([]TLSRequest, error) {
	return f.recent, f.readErr
}

func (f *fakeStore) TopThreats(context.Context, int, time.Time) ([]TLSRequest, error) {
	return f.topThreats, f.readErr
}

func (f *fakeStore) TopCommonFingerprints(context.Context, int) ([]FingerprintEntry, error) {
	return f.topCommon, f.readErr
}

func TestRegisterRoutesTotalStats(t *testing.T) {
	mux := http.NewServeMux()
	RegisterRoutes(mux, &fakeStore{
		total: TotalStats{Total: 10, Clean: 8, Suspicious: 1, Malicious: 1},
	})

	req := httptest.NewRequest(http.MethodGet, "/api/stats/total", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("unexpected status: %d", rec.Code)
	}
	if got := rec.Header().Get("Access-Control-Allow-Origin"); got != "*" {
		t.Fatalf("unexpected cors header: %q", got)
	}

	var payload TotalStats
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}
	if payload.Total != 10 || payload.Clean != 8 || payload.Suspicious != 1 || payload.Malicious != 1 {
		t.Fatalf("unexpected payload: %+v", payload)
	}
}

func TestRegisterRoutesStoreUnavailable(t *testing.T) {
	mux := http.NewServeMux()
	RegisterRoutes(mux, nil)

	req := httptest.NewRequest(http.MethodGet, "/api/requests/recent", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("unexpected status: %d", rec.Code)
	}
}

func TestVerdictFromAssessment(t *testing.T) {
	cases := []struct {
		name       string
		assessment risk.Assessment
		want       string
	}{
		{
			name: "clean",
			assessment: risk.Assessment{
				Score:  20,
				Action: risk.ActionAllow,
			},
			want: "clean",
		},
		{
			name: "suspicious",
			assessment: risk.Assessment{
				Score:  78,
				Action: risk.ActionRateLimit,
			},
			want: "suspicious",
		},
		{
			name: "malicious",
			assessment: risk.Assessment{
				Score:  95,
				Action: risk.ActionBlock,
			},
			want: "malicious",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := verdictFromAssessment(tc.assessment); got != tc.want {
				t.Fatalf("unexpected verdict: got %q want %q", got, tc.want)
			}
		})
	}
}

func TestFingerprintLabelPrefersLookupIdentity(t *testing.T) {
	assessment := &risk.Assessment{
		Summary: risk.FingerprintSummary{
			ApplicationFamily: "chrome",
			OSFamily:          "windows",
		},
		Lookup: &risk.FingerprintRecord{
			Application: "Chrome 120+",
			OS:          "Windows",
		},
	}

	if got := fingerprintLabel(assessment); got != "Chrome 120+ (Windows)" {
		t.Fatalf("unexpected label: %q", got)
	}
}
