package api

import (
	"context"
	"time"
)

type TotalStats struct {
	Total      int64 `json:"total"`
	Malicious  int64 `json:"malicious"`
	Suspicious int64 `json:"suspicious"`
	Clean      int64 `json:"clean"`
}

type TimeseriesEntry struct {
	Timestamp  time.Time `json:"timestamp"`
	Hour       string    `json:"hour"`
	Total      int64     `json:"total"`
	Clean      int64     `json:"clean"`
	Suspicious int64     `json:"suspicious"`
	Malicious  int64     `json:"malicious"`
}

type TLSRequest struct {
	ID               int64     `json:"id"`
	Timestamp        time.Time `json:"timestamp"`
	SourceIP         string    `json:"source_ip"`
	DestinationIP    string    `json:"destination_ip"`
	JA3Hash          string    `json:"ja3_hash"`
	Fingerprint      string    `json:"fingerprint"`
	ThreatScore      int       `json:"threat_score"`
	Verdict          string    `json:"verdict"`
	MatchedSignature string    `json:"matched_signature,omitempty"`
	FingerprintKind  string    `json:"fingerprint_kind,omitempty"`
	JA4Fingerprint   string    `json:"ja4_fingerprint,omitempty"`
}

type FingerprintEntry struct {
	JA3Hash         string `json:"ja3_hash"`
	Fingerprint     string `json:"fingerprint"`
	Count           int64  `json:"count"`
	AvgThreatScore  int    `json:"avg_threat_score"`
	Label           string `json:"label"`
	FingerprintKind string `json:"fingerprint_kind,omitempty"`
	JA4Fingerprint  string `json:"ja4_fingerprint,omitempty"`
}

type RequestObservation struct {
	Timestamp        time.Time
	SourceIP         string
	DestinationIP    string
	JA4Fingerprint   string
	Fingerprint      string
	FingerprintKind  string
	ThreatScore      int
	Verdict          string
	MatchedSignature string
	Label            string
}

type Store interface {
	Record(ctx context.Context, obs RequestObservation) error
	TotalStats(ctx context.Context) (TotalStats, error)
	Timeseries(ctx context.Context, now time.Time) ([]TimeseriesEntry, error)
	RecentRequests(ctx context.Context, limit int) ([]TLSRequest, error)
	TopThreats(ctx context.Context, limit int, now time.Time) ([]TLSRequest, error)
	TopCommonFingerprints(ctx context.Context, limit int) ([]FingerprintEntry, error)
}
