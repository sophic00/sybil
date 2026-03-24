package config

import (
	"flag"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestLoadUsesDefaultsAndTomlOverrides(t *testing.T) {
	tmp := t.TempDir()
	path := filepath.Join(tmp, "sybil.toml")
	content := []byte(`backend = "ebpf"
iface = "eth0"
port = 443
redis_addr = "localhost:6379"
ja4_lookup_timeout = "5s"
risk_use_host_fallback = false
`)
	if err := os.WriteFile(path, content, 0o644); err != nil {
		t.Fatalf("WriteFile error: %v", err)
	}

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load error: %v", err)
	}
	if cfg.Backend != "ebpf" || cfg.Iface != "eth0" || cfg.Port != 443 {
		t.Fatalf("unexpected config values: %+v", cfg)
	}
	if cfg.RiskKeyPrefix != "sybil:risk" {
		t.Fatalf("expected default risk key prefix, got %q", cfg.RiskKeyPrefix)
	}
	if cfg.JA4LookupTimeout != 5*time.Second {
		t.Fatalf("expected timeout 5s, got %s", cfg.JA4LookupTimeout)
	}
	if cfg.RiskUseHostFallback {
		t.Fatalf("expected risk_use_host_fallback false")
	}
}

func TestApplyFlagOverridesWinsOverToml(t *testing.T) {
	fs := flag.NewFlagSet("test", flag.ContinueOnError)

	base := Default()
	values := base
	configPath := ""

	fs.StringVar(&configPath, "config", "", "")
	fs.StringVar(&values.Backend, "backend", base.Backend, "")
	fs.StringVar(&values.Iface, "iface", base.Iface, "")
	fs.UintVar(&values.Port, "port", base.Port, "")
	fs.StringVar(&values.RedisAddr, "redis-addr", base.RedisAddr, "")
	fs.DurationVar(&values.JA4LookupTimeout, "ja4-lookup-timeout", base.JA4LookupTimeout, "")

	if err := fs.Parse([]string{"-backend", "ebpf", "-redis-addr", "127.0.0.1:6379"}); err != nil {
		t.Fatalf("Parse error: %v", err)
	}

	cfg := Default()
	cfg.Backend = "pcap"
	cfg.RedisAddr = "from-toml:6379"
	cfg.JA4LookupTimeout = 10 * time.Second

	ApplyFlagOverrides(fs, &cfg, values)

	if cfg.Backend != "ebpf" {
		t.Fatalf("expected backend from flags, got %q", cfg.Backend)
	}
	if cfg.RedisAddr != "127.0.0.1:6379" {
		t.Fatalf("expected redis addr from flags, got %q", cfg.RedisAddr)
	}
	if cfg.JA4LookupTimeout != 10*time.Second {
		t.Fatalf("expected timeout to remain from toml when not flagged, got %s", cfg.JA4LookupTimeout)
	}
}
