package db

import (
	"database/sql"
	"fmt"

	_ "github.com/mattn/go-sqlite3"
)

const schema = `
CREATE TABLE IF NOT EXISTS scans (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	domain TEXT NOT NULL,
	scan_mode TEXT NOT NULL,
	started_at TIMESTAMP NOT NULL,
	completed_at TIMESTAMP,
	total_subdomains INTEGER DEFAULT 0,
	validated_subdomains INTEGER DEFAULT 0,
	sources_used TEXT,
	config_snapshot TEXT,
	status TEXT DEFAULT 'running',
	UNIQUE(domain, started_at)
);

CREATE INDEX IF NOT EXISTS idx_scans_domain ON scans(domain);
CREATE INDEX IF NOT EXISTS idx_scans_started ON scans(started_at);

CREATE TABLE IF NOT EXISTS subdomains (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	scan_id INTEGER NOT NULL,
	domain TEXT NOT NULL,
	first_seen TIMESTAMP NOT NULL,
	last_seen TIMESTAMP NOT NULL,
	confidence INTEGER DEFAULT 0,
	validated BOOLEAN DEFAULT 0,
	status TEXT DEFAULT 'active',
	FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_subdomains_scan ON subdomains(scan_id);
CREATE INDEX IF NOT EXISTS idx_subdomains_domain ON subdomains(domain);
CREATE INDEX IF NOT EXISTS idx_subdomains_confidence ON subdomains(confidence);

CREATE TABLE IF NOT EXISTS subdomain_sources (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	subdomain_id INTEGER NOT NULL,
	source TEXT NOT NULL,
	discovered_at TIMESTAMP NOT NULL,
	FOREIGN KEY (subdomain_id) REFERENCES subdomains(id) ON DELETE CASCADE,
	UNIQUE(subdomain_id, source)
);

CREATE INDEX IF NOT EXISTS idx_sources_subdomain ON subdomain_sources(subdomain_id);

CREATE TABLE IF NOT EXISTS dns_records (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	subdomain_id INTEGER NOT NULL,
	record_type TEXT NOT NULL,
	value TEXT NOT NULL,
	ttl INTEGER,
	discovered_at TIMESTAMP NOT NULL,
	FOREIGN KEY (subdomain_id) REFERENCES subdomains(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_dns_subdomain ON dns_records(subdomain_id);
CREATE INDEX IF NOT EXISTS idx_dns_type ON dns_records(record_type);

CREATE TABLE IF NOT EXISTS http_info (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	subdomain_id INTEGER NOT NULL,
	status_code INTEGER,
	title TEXT,
	server TEXT,
	content_type TEXT,
	response_time INTEGER,
	screenshot_path TEXT,
	checked_at TIMESTAMP NOT NULL,
	FOREIGN KEY (subdomain_id) REFERENCES subdomains(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_http_subdomain ON http_info(subdomain_id);
CREATE INDEX IF NOT EXISTS idx_http_status ON http_info(status_code);

CREATE TABLE IF NOT EXISTS tls_info (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	subdomain_id INTEGER NOT NULL,
	subject TEXT,
	issuer TEXT,
	not_before TIMESTAMP,
	not_after TIMESTAMP,
	valid BOOLEAN DEFAULT 0,
	organization TEXT,
	checked_at TIMESTAMP NOT NULL,
	FOREIGN KEY (subdomain_id) REFERENCES subdomains(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_tls_subdomain ON tls_info(subdomain_id);

CREATE TABLE IF NOT EXISTS technologies (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	subdomain_id INTEGER NOT NULL,
	technology TEXT NOT NULL,
	version TEXT,
	confidence INTEGER,
	detected_at TIMESTAMP NOT NULL,
	FOREIGN KEY (subdomain_id) REFERENCES subdomains(id) ON DELETE CASCADE,
	UNIQUE(subdomain_id, technology)
);

CREATE INDEX IF NOT EXISTS idx_tech_subdomain ON technologies(subdomain_id);
CREATE INDEX IF NOT EXISTS idx_tech_name ON technologies(technology);

CREATE TABLE IF NOT EXISTS cloud_assets (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	scan_id INTEGER NOT NULL,
	provider TEXT NOT NULL,
	bucket TEXT NOT NULL,
	region TEXT,
	asset_type TEXT NOT NULL,
	url TEXT NOT NULL,
	accessible BOOLEAN,
	discovered_at TIMESTAMP NOT NULL,
	FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE,
	UNIQUE(scan_id, provider, bucket)
);

CREATE INDEX IF NOT EXISTS idx_cloud_scan ON cloud_assets(scan_id);
CREATE INDEX IF NOT EXISTS idx_cloud_provider ON cloud_assets(provider);

CREATE TABLE IF NOT EXISTS changes (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	domain TEXT NOT NULL,
	subdomain TEXT NOT NULL,
	change_type TEXT NOT NULL,
	old_value TEXT,
	new_value TEXT,
	detected_at TIMESTAMP NOT NULL,
	scan_id_old INTEGER,
	scan_id_new INTEGER,
	FOREIGN KEY (scan_id_old) REFERENCES scans(id),
	FOREIGN KEY (scan_id_new) REFERENCES scans(id)
);

CREATE INDEX IF NOT EXISTS idx_changes_domain ON changes(domain);
CREATE INDEX IF NOT EXISTS idx_changes_type ON changes(change_type);
CREATE INDEX IF NOT EXISTS idx_changes_detected ON changes(detected_at);

CREATE TABLE IF NOT EXISTS metadata (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	subdomain_id INTEGER NOT NULL,
	key TEXT NOT NULL,
	value TEXT,
	updated_at TIMESTAMP NOT NULL,
	FOREIGN KEY (subdomain_id) REFERENCES subdomains(id) ON DELETE CASCADE,
	UNIQUE(subdomain_id, key)
);

CREATE INDEX IF NOT EXISTS idx_metadata_subdomain ON metadata(subdomain_id);
CREATE INDEX IF NOT EXISTS idx_metadata_key ON metadata(key);
`

// InitDB initializes the database with schema
func InitDB(dbPath string) (*sql.DB, error) {
	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}
	
	// Enable foreign keys
	if _, err := db.Exec("PRAGMA foreign_keys = ON"); err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to enable foreign keys: %w", err)
	}
	
	// Set performance optimizations
	pragmas := []string{
		"PRAGMA journal_mode = WAL",
		"PRAGMA synchronous = NORMAL",
		"PRAGMA cache_size = -64000",
		"PRAGMA temp_store = MEMORY",
	}
	
	for _, pragma := range pragmas {
		if _, err := db.Exec(pragma); err != nil {
			db.Close()
			return nil, fmt.Errorf("failed to set pragma: %w", err)
		}
	}
	
	// Create schema
	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to create schema: %w", err)
	}
	
	return db, nil
}

// MigrateDB applies any pending migrations
func MigrateDB(db *sql.DB) error {
	// Future migrations will be added here
	// For now, just ensure schema is current
	
	return nil
}