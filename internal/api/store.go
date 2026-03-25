package api

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"strconv"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"
)

const (
	defaultRecentLimit      = 10
	defaultTopLimit         = 10
	hourRetention           = 48 * time.Hour
	requestRetention        = 25 * time.Hour
	fingerprintTopScoreBase = 1_000_000_0000
)

type RedisStore struct {
	client redis.Cmdable
	prefix string
}

func NewRedisStore(client redis.Cmdable, prefix string) *RedisStore {
	return &RedisStore{
		client: client,
		prefix: strings.Trim(strings.TrimSpace(prefix), ":"),
	}
}

func (s *RedisStore) Record(ctx context.Context, obs RequestObservation) error {
	if strings.TrimSpace(obs.JA4Fingerprint) == "" {
		return fmt.Errorf("missing ja4 fingerprint")
	}
	if obs.Timestamp.IsZero() {
		obs.Timestamp = time.Now().UTC()
	} else {
		obs.Timestamp = obs.Timestamp.UTC()
	}
	if strings.TrimSpace(obs.Fingerprint) == "" {
		obs.Fingerprint = obs.JA4Fingerprint
	}
	if strings.TrimSpace(obs.FingerprintKind) == "" {
		obs.FingerprintKind = "ja4"
	}
	if obs.Label == "" {
		obs.Label = "Unknown JA4 Client"
	}

	id, err := s.client.Incr(ctx, s.key("api", "requests", "seq")).Result()
	if err != nil {
		return err
	}

	request := TLSRequest{
		ID:               id,
		Timestamp:        obs.Timestamp,
		SourceIP:         obs.SourceIP,
		DestinationIP:    obs.DestinationIP,
		JA3Hash:          obs.JA4Fingerprint,
		Fingerprint:      obs.Fingerprint,
		ThreatScore:      obs.ThreatScore,
		Verdict:          normalizeVerdict(obs.Verdict),
		MatchedSignature: obs.MatchedSignature,
		FingerprintKind:  obs.FingerprintKind,
		JA4Fingerprint:   obs.JA4Fingerprint,
	}

	payload, err := json.Marshal(request)
	if err != nil {
		return err
	}

	hourKey := s.hourKey(obs.Timestamp)
	requestKey := s.key("api", "request", strconv.FormatInt(id, 10))
	memberID := strconv.FormatInt(id, 10)
	verdict := normalizeVerdict(obs.Verdict)

	pipe := s.client.TxPipeline()
	pipe.HIncrBy(ctx, s.key("api", "stats", "total"), "total", 1)
	pipe.HIncrBy(ctx, s.key("api", "stats", "total"), verdict, 1)

	pipe.HIncrBy(ctx, hourKey, "total", 1)
	pipe.HIncrBy(ctx, hourKey, verdict, 1)
	pipe.Expire(ctx, hourKey, hourRetention)

	pipe.LPush(ctx, s.key("api", "requests", "recent"), payload)
	pipe.LTrim(ctx, s.key("api", "requests", "recent"), 0, defaultRecentLimit-1)

	pipe.Set(ctx, requestKey, payload, requestRetention)
	pipe.ZAdd(ctx, s.key("api", "requests", "top_threats"), redis.Z{
		Score:  topThreatScore(request.ThreatScore, obs.Timestamp),
		Member: memberID,
	})
	pipe.ZAdd(ctx, s.key("api", "requests", "top_threats_by_time"), redis.Z{
		Score:  float64(obs.Timestamp.Unix()),
		Member: memberID,
	})

	pipe.ZIncrBy(ctx, s.key("api", "fingerprints", "counts"), 1, obs.JA4Fingerprint)
	pipe.HIncrBy(ctx, s.key("api", "fingerprints", "scores"), obs.JA4Fingerprint, int64(obs.ThreatScore))
	pipe.HSet(ctx, s.key("api", "fingerprints", "display"), obs.JA4Fingerprint, obs.Fingerprint)
	pipe.HSet(ctx, s.key("api", "fingerprints", "labels"), obs.JA4Fingerprint, obs.Label)
	pipe.HSet(ctx, s.key("api", "fingerprints", "kinds"), obs.JA4Fingerprint, obs.FingerprintKind)

	_, err = pipe.Exec(ctx)
	return err
}

func (s *RedisStore) TotalStats(ctx context.Context) (TotalStats, error) {
	values, err := s.client.HGetAll(ctx, s.key("api", "stats", "total")).Result()
	if err != nil {
		return TotalStats{}, err
	}
	return TotalStats{
		Total:      parseInt64(values["total"]),
		Malicious:  parseInt64(values["malicious"]),
		Suspicious: parseInt64(values["suspicious"]),
		Clean:      parseInt64(values["clean"]),
	}, nil
}

func (s *RedisStore) Timeseries(ctx context.Context, now time.Time) ([]TimeseriesEntry, error) {
	now = now.UTC().Truncate(time.Hour)
	start := now.Add(-23 * time.Hour)

	pipe := s.client.Pipeline()
	cmds := make([]*redis.MapStringStringCmd, 0, 24)
	timestamps := make([]time.Time, 0, 24)
	for ts := start; !ts.After(now); ts = ts.Add(time.Hour) {
		timestamps = append(timestamps, ts)
		cmds = append(cmds, pipe.HGetAll(ctx, s.hourKey(ts)))
	}
	if _, err := pipe.Exec(ctx); err != nil && err != redis.Nil {
		return nil, err
	}

	series := make([]TimeseriesEntry, 0, len(cmds))
	for idx, cmd := range cmds {
		values := cmd.Val()
		ts := timestamps[idx]
		series = append(series, TimeseriesEntry{
			Timestamp:  ts,
			Hour:       ts.Format("15:04"),
			Total:      parseInt64(values["total"]),
			Clean:      parseInt64(values["clean"]),
			Suspicious: parseInt64(values["suspicious"]),
			Malicious:  parseInt64(values["malicious"]),
		})
	}
	return series, nil
}

func (s *RedisStore) RecentRequests(ctx context.Context, limit int) ([]TLSRequest, error) {
	if limit <= 0 {
		limit = defaultRecentLimit
	}

	values, err := s.client.LRange(ctx, s.key("api", "requests", "recent"), 0, int64(limit-1)).Result()
	if err != nil {
		return nil, err
	}

	out := make([]TLSRequest, 0, len(values))
	for _, raw := range values {
		request, ok := decodeRequest(raw)
		if !ok {
			continue
		}
		out = append(out, request)
	}
	return out, nil
}

func (s *RedisStore) TopThreats(ctx context.Context, limit int, now time.Time) ([]TLSRequest, error) {
	if limit <= 0 {
		limit = defaultTopLimit
	}
	if err := s.pruneTopThreats(ctx, now); err != nil {
		return nil, err
	}

	ids, err := s.client.ZRevRange(ctx, s.key("api", "requests", "top_threats"), 0, int64(limit-1)).Result()
	if err != nil {
		return nil, err
	}
	return s.loadRequestsByID(ctx, ids)
}

func (s *RedisStore) TopCommonFingerprints(ctx context.Context, limit int) ([]FingerprintEntry, error) {
	if limit <= 0 {
		limit = defaultTopLimit
	}

	ranked, err := s.client.ZRevRangeWithScores(ctx, s.key("api", "fingerprints", "counts"), 0, int64(limit-1)).Result()
	if err != nil {
		return nil, err
	}
	if len(ranked) == 0 {
		return []FingerprintEntry{}, nil
	}

	fields := make([]string, 0, len(ranked))
	for _, member := range ranked {
		fingerprint, _ := member.Member.(string)
		fields = append(fields, fingerprint)
	}

	pipe := s.client.Pipeline()
	scoreCmd := pipe.HMGet(ctx, s.key("api", "fingerprints", "scores"), fields...)
	displayCmd := pipe.HMGet(ctx, s.key("api", "fingerprints", "display"), fields...)
	labelCmd := pipe.HMGet(ctx, s.key("api", "fingerprints", "labels"), fields...)
	kindCmd := pipe.HMGet(ctx, s.key("api", "fingerprints", "kinds"), fields...)
	if _, err := pipe.Exec(ctx); err != nil && err != redis.Nil {
		return nil, err
	}

	out := make([]FingerprintEntry, 0, len(ranked))
	for idx, member := range ranked {
		fingerprint, _ := member.Member.(string)
		count := int64(math.Round(member.Score))
		totalScore := parseAnyInt64(scoreCmd.Val()[idx])
		display := stringValue(displayCmd.Val()[idx])
		if display == "" {
			display = fingerprint
		}
		label := stringValue(labelCmd.Val()[idx])
		if label == "" {
			label = "Unknown JA4 Client"
		}
		kind := stringValue(kindCmd.Val()[idx])
		if kind == "" {
			kind = "ja4"
		}
		avg := 0
		if count > 0 {
			avg = int(math.Round(float64(totalScore) / float64(count)))
		}
		out = append(out, FingerprintEntry{
			JA3Hash:         fingerprint,
			Fingerprint:     display,
			Count:           count,
			AvgThreatScore:  avg,
			Label:           label,
			FingerprintKind: kind,
			JA4Fingerprint:  fingerprint,
		})
	}

	return out, nil
}

func (s *RedisStore) loadRequestsByID(ctx context.Context, ids []string) ([]TLSRequest, error) {
	if len(ids) == 0 {
		return []TLSRequest{}, nil
	}

	keys := make([]string, 0, len(ids))
	for _, id := range ids {
		keys = append(keys, s.key("api", "request", id))
	}

	values, err := s.client.MGet(ctx, keys...).Result()
	if err != nil {
		return nil, err
	}

	out := make([]TLSRequest, 0, len(values))
	stale := make([]string, 0)
	for idx, raw := range values {
		if raw == nil {
			stale = append(stale, ids[idx])
			continue
		}
		request, ok := decodeRequest(stringValue(raw))
		if !ok {
			stale = append(stale, ids[idx])
			continue
		}
		out = append(out, request)
	}

	if len(stale) > 0 {
		_, _ = s.client.ZRem(ctx, s.key("api", "requests", "top_threats"), toMembers(stale)...).Result()
		_, _ = s.client.ZRem(ctx, s.key("api", "requests", "top_threats_by_time"), toMembers(stale)...).Result()
	}

	return out, nil
}

func (s *RedisStore) pruneTopThreats(ctx context.Context, now time.Time) error {
	if now.IsZero() {
		now = time.Now().UTC()
	} else {
		now = now.UTC()
	}
	cutoff := now.Add(-24 * time.Hour).Unix()

	stale, err := s.client.ZRangeByScore(ctx, s.key("api", "requests", "top_threats_by_time"), &redis.ZRangeBy{
		Min: "-inf",
		Max: strconv.FormatInt(cutoff-1, 10),
	}).Result()
	if err != nil && err != redis.Nil {
		return err
	}
	if len(stale) == 0 {
		return nil
	}

	pipe := s.client.TxPipeline()
	pipe.ZRem(ctx, s.key("api", "requests", "top_threats_by_time"), toMembers(stale)...)
	pipe.ZRem(ctx, s.key("api", "requests", "top_threats"), toMembers(stale)...)
	_, err = pipe.Exec(ctx)
	return err
}

func (s *RedisStore) hourKey(ts time.Time) string {
	return s.key("api", "stats", "hour", strconv.FormatInt(ts.UTC().Truncate(time.Hour).Unix(), 10))
}

func (s *RedisStore) key(parts ...string) string {
	base := strings.Trim(strings.TrimSpace(s.prefix), ":")
	if base == "" {
		base = "sybil:risk"
	}
	return base + ":" + strings.Join(parts, ":")
}

func topThreatScore(score int, ts time.Time) float64 {
	return float64(score)*fingerprintTopScoreBase + float64(ts.UTC().Unix())
}

func normalizeVerdict(verdict string) string {
	switch strings.ToLower(strings.TrimSpace(verdict)) {
	case "malicious":
		return "malicious"
	case "suspicious":
		return "suspicious"
	default:
		return "clean"
	}
}

func decodeRequest(raw string) (TLSRequest, bool) {
	var request TLSRequest
	if err := json.Unmarshal([]byte(raw), &request); err != nil {
		return TLSRequest{}, false
	}
	return request, true
}

func parseInt64(raw string) int64 {
	value, err := strconv.ParseInt(strings.TrimSpace(raw), 10, 64)
	if err != nil {
		return 0
	}
	return value
}

func parseAnyInt64(raw any) int64 {
	switch value := raw.(type) {
	case nil:
		return 0
	case string:
		return parseInt64(value)
	case []byte:
		return parseInt64(string(value))
	case int64:
		return value
	case int:
		return int64(value)
	case float64:
		return int64(math.Round(value))
	default:
		return 0
	}
}

func stringValue(raw any) string {
	switch value := raw.(type) {
	case nil:
		return ""
	case string:
		return value
	case []byte:
		return string(value)
	default:
		return fmt.Sprint(value)
	}
}

func toMembers(values []string) []any {
	out := make([]any, 0, len(values))
	for _, value := range values {
		out = append(out, value)
	}
	return out
}
