package db

import (
	"database/sql"
	"fmt"
	"net/url"
	"os"
	"strings"

	_ "github.com/tursodatabase/go-libsql"
)

type SQLiteConfig struct {
	Driver    string
	DSN       string
	AuthToken string
}

func OpenSQLite(cfg SQLiteConfig) (*sql.DB, error) {
	driver := strings.TrimSpace(cfg.Driver)
	if driver == "" {
		driver = "libsql"
	}

	dsn := strings.TrimSpace(cfg.DSN)
	if dsn == "" {
		return nil, fmt.Errorf("missing libsql dsn")
	}
	if token := strings.TrimSpace(cfg.AuthToken); token != "" {
		parsed, err := url.Parse(dsn)
		if err != nil {
			return nil, fmt.Errorf("parse libsql dsn: %w", err)
		}
		query := parsed.Query()
		if query.Get("authToken") == "" {
			query.Set("authToken", token)
		}
		parsed.RawQuery = query.Encode()
		dsn = parsed.String()
	}

	conn, err := sql.Open(driver, dsn)
	if err != nil {
		return nil, fmt.Errorf("open %s database: %w", driver, err)
	}

	if err := conn.Ping(); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("ping %s database: %w", driver, err)
	}

	return conn, nil
}

func OpenSQLiteFromEnv() (*sql.DB, error) {
	dsn := strings.TrimSpace(os.Getenv("DB_URL"))
	if dsn == "" {
		return nil, fmt.Errorf("missing DB_URL environment variable")
	}

	return OpenSQLite(SQLiteConfig{
		Driver:    "libsql",
		DSN:       dsn,
		AuthToken: strings.TrimSpace(os.Getenv("AUTH_TOKEN")),
	})
}
