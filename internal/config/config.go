package config

import (
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/BurntSushi/toml"
)

type Config struct {
	Backend             string        `toml:"backend"`
	Iface               string        `toml:"iface"`
	Port                uint          `toml:"port"`
	HelloOut            string        `toml:"hello_out"`
	ExitAfterHello      bool          `toml:"exit_after_hello"`
	RedisAddr           string        `toml:"redis_addr"`
	RedisPassword       string        `toml:"redis_password"`
	RedisDB             int           `toml:"redis_db"`
	RiskKeyPrefix       string        `toml:"risk_key_prefix"`
	JA4LookupURL        string        `toml:"ja4_lookup_url"`
	JA4LookupTimeout    time.Duration `toml:"ja4_lookup_timeout"`
	RiskUseHostFallback bool          `toml:"risk_use_host_fallback"`
}

func Default() Config {
	return Config{
		Backend:             "pcap",
		Iface:               "lo",
		Port:                0,
		HelloOut:            "",
		ExitAfterHello:      false,
		RedisAddr:           "",
		RedisPassword:       "",
		RedisDB:             0,
		RiskKeyPrefix:       "sybil:risk",
		JA4LookupURL:        "",
		JA4LookupTimeout:    2 * time.Second,
		RiskUseHostFallback: true,
	}
}

func Load(path string) (Config, error) {
	cfg := Default()
	if path == "" {
		return cfg, nil
	}

	content, err := os.ReadFile(path)
	if err != nil {
		return Config{}, fmt.Errorf("read config %q: %w", path, err)
	}
	if _, err := toml.Decode(string(content), &cfg); err != nil {
		return Config{}, fmt.Errorf("decode config %q: %w", path, err)
	}

	return cfg, nil
}

func ApplyFlagOverrides(fs *flag.FlagSet, cfg *Config, values Config) {
	overrides := map[string]func(){
		"backend":                func() { cfg.Backend = values.Backend },
		"iface":                  func() { cfg.Iface = values.Iface },
		"port":                   func() { cfg.Port = values.Port },
		"hello-out":              func() { cfg.HelloOut = values.HelloOut },
		"exit-after-hello":       func() { cfg.ExitAfterHello = values.ExitAfterHello },
		"redis-addr":             func() { cfg.RedisAddr = values.RedisAddr },
		"redis-password":         func() { cfg.RedisPassword = values.RedisPassword },
		"redis-db":               func() { cfg.RedisDB = values.RedisDB },
		"risk-key-prefix":        func() { cfg.RiskKeyPrefix = values.RiskKeyPrefix },
		"ja4-lookup-url":         func() { cfg.JA4LookupURL = values.JA4LookupURL },
		"ja4-lookup-timeout":     func() { cfg.JA4LookupTimeout = values.JA4LookupTimeout },
		"risk-use-host-fallback": func() { cfg.RiskUseHostFallback = values.RiskUseHostFallback },
	}

	fs.Visit(func(f *flag.Flag) {
		if apply, ok := overrides[f.Name]; ok {
			apply()
		}
	})
}
