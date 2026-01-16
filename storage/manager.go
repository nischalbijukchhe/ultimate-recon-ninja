package storage

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"github.com/yourusername/usr/internal/types"
	"github.com/yourusername/usr/storage/db"
	"go.uber.org/zap"
)

// Manager handles all storage operations
type Manager struct {
	db     *sql.DB
	logger *zap.Logger
}

// NewManager creates a new storage manager
func NewManager(dbPath string, logger *zap.Logger) (*Manager, error) {
	database, err := db.InitDB(dbPath)
	if err != nil {
		return nil, err
	}
	
	return &Manager{
		db:     database,
		logger: logger,
	}, nil
}

// Close closes the database connection
func (m *Manager) Close() error {
	return m.db.Close()
}

// CreateScan creates a new scan entry
func (m *Manager) CreateScan(ctx context.Context, domain, mode string, sourcesUsed []string) (int64, error) {
	sourcesJSON, _ := json.Marshal(sourcesUsed)
	
	result, err := m.db.ExecContext(ctx,
		`INSERT INTO scans (domain, scan_mode, started_at, sources_used, status) 
		 VALUES (?, ?, ?, ?, 'running')`,
		domain, mode, time.Now(), string(sourcesJSON),
	)
	if err != nil {
		return 0, err
	}
	
	return result.LastInsertId()
}

// CompleteScan marks a scan as complete
func (m *Manager) CompleteScan(ctx context.Context, scanID int64, totalSubdomains, validatedSubdomains int) error {
	_, err := m.db.ExecContext(ctx,
		`UPDATE scans 
		 SET completed_at = ?, total_subdomains = ?, validated_subdomains = ?, status = 'completed'
		 WHERE id = ?`,
		time.Now(), totalSubdomains, validatedSubdomains, scanID,
	)
	
	return err
}

// SaveSubdomain saves a subdomain to the database
func (m *Manager) SaveSubdomain(ctx context.Context, scanID int64, sub *types.Subdomain) error {
	tx, err := m.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	
	// Insert subdomain
	result, err := tx.ExecContext(ctx,
		`INSERT INTO subdomains (scan_id, domain, first_seen, last_seen, confidence, validated, status)
		 VALUES (?, ?, ?, ?, ?, ?, 'active')`,
		scanID, sub.Domain, sub.FirstSeen, sub.LastSeen, sub.Confidence, sub.Validated,
	)
	if err != nil {
		return err
	}
	
	subdomainID, err := result.LastInsertId()
	if err != nil {
		return err
	}
	
	// Insert sources
	for _, source := range sub.Sources {
		_, err := tx.ExecContext(ctx,
			`INSERT OR IGNORE INTO subdomain_sources (subdomain_id, source, discovered_at)
			 VALUES (?, ?, ?)`,
			subdomainID, source, time.Now(),
		)
		if err != nil {
			return err
		}
	}
	
	// Insert DNS records
	if sub.DNSRecords != nil {
		for _, ip := range sub.DNSRecords.A {
			_, err := tx.ExecContext(ctx,
				`INSERT INTO dns_records (subdomain_id, record_type, value, discovered_at)
				 VALUES (?, 'A', ?, ?)`,
				subdomainID, ip, time.Now(),
			)
			if err != nil {
				return err
			}
		}
		
		for _, cname := range sub.DNSRecords.CNAME {
			_, err := tx.ExecContext(ctx,
				`INSERT INTO dns_records (subdomain_id, record_type, value, discovered_at)
				 VALUES (?, 'CNAME', ?, ?)`,
				subdomainID, cname, time.Now(),
			)
			if err != nil {
				return err
			}
		}
	}
	
	// Insert HTTP info
	if sub.HTTP != nil {
		_, err := tx.ExecContext(ctx,
			`INSERT INTO http_info (subdomain_id, status_code, title, server, content_type, response_time, checked_at)
			 VALUES (?, ?, ?, ?, ?, ?, ?)`,
			subdomainID, sub.HTTP.StatusCode, sub.HTTP.Title, sub.HTTP.Server,
			sub.HTTP.ContentType, sub.HTTP.ResponseTime.Milliseconds(), time.Now(),
		)
		if err != nil {
			return err
		}
		
		// Insert technologies
		for _, tech := range sub.HTTP.Technologies {
			_, err := tx.ExecContext(ctx,
				`INSERT OR IGNORE INTO technologies (subdomain_id, technology, detected_at)
				 VALUES (?, ?, ?)`,
				subdomainID, tech, time.Now(),
			)
			if err != nil {
				return err
			}
		}
	}
	
	// Insert TLS info
	if sub.TLS != nil {
		_, err := tx.ExecContext(ctx,
			`INSERT INTO tls_info (subdomain_id, subject, issuer, not_before, not_after, valid, organization, checked_at)
			 VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
			subdomainID, sub.TLS.Subject, sub.TLS.Issuer, sub.TLS.NotBefore,
			sub.TLS.NotAfter, sub.TLS.Valid, sub.TLS.Organization, time.Now(),
		)
		if err != nil {
			return err
		}
	}
	
	// Insert metadata
	for key, value := range sub.Metadata {
		valueJSON, _ := json.Marshal(value)
		_, err := tx.ExecContext(ctx,
			`INSERT OR REPLACE INTO metadata (subdomain_id, key, value, updated_at)
			 VALUES (?, ?, ?, ?)`,
			subdomainID, key, string(valueJSON), time.Now(),
		)
		if err != nil {
			return err
		}
	}
	
	return tx.Commit()
}

// GetLatestScan retrieves the most recent scan for a domain
func (m *Manager) GetLatestScan(ctx context.Context, domain string) (int64, error) {
	var scanID int64
	err := m.db.QueryRowContext(ctx,
		`SELECT id FROM scans WHERE domain = ? AND status = 'completed' 
		 ORDER BY completed_at DESC LIMIT 1`,
		domain,
	).Scan(&scanID)
	
	if err == sql.ErrNoRows {
		return 0, nil
	}
	
	return scanID, err
}

// GetScanSubdomains retrieves all subdomains from a scan
func (m *Manager) GetScanSubdomains(ctx context.Context, scanID int64) ([]string, error) {
	rows, err := m.db.QueryContext(ctx,
		`SELECT domain FROM subdomains WHERE scan_id = ? AND status = 'active'`,
		scanID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	
	var subdomains []string
	for rows.Next() {
		var domain string
		if err := rows.Scan(&domain); err != nil {
			return nil, err
		}
		subdomains = append(subdomains, domain)
	}
	
	return subdomains, rows.Err()
}

// GetSubdomainHistory retrieves historical data for a subdomain
func (m *Manager) GetSubdomainHistory(ctx context.Context, domain string) ([]*SubdomainSnapshot, error) {
	rows, err := m.db.QueryContext(ctx,
		`SELECT s.id, s.scan_id, s.first_seen, s.last_seen, s.confidence, s.validated,
		        sc.started_at as scan_time
		 FROM subdomains s
		 JOIN scans sc ON s.scan_id = sc.id
		 WHERE s.domain = ?
		 ORDER BY s.last_seen DESC`,
		domain,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	
	var history []*SubdomainSnapshot
	for rows.Next() {
		snap := &SubdomainSnapshot{}
		if err := rows.Scan(&snap.ID, &snap.ScanID, &snap.FirstSeen, &snap.LastSeen,
			&snap.Confidence, &snap.Validated, &snap.ScanTime); err != nil {
			return nil, err
		}
		history = append(history, snap)
	}
	
	return history, rows.Err()
}

// SubdomainSnapshot represents a point-in-time subdomain state
type SubdomainSnapshot struct {
	ID         int64
	ScanID     int64
	FirstSeen  time.Time
	LastSeen   time.Time
	Confidence int
	Validated  bool
	ScanTime   time.Time
}

// SaveChange records a detected change
func (m *Manager) SaveChange(ctx context.Context, domain, subdomain, changeType, oldValue, newValue string, oldScanID, newScanID int64) error {
	_, err := m.db.ExecContext(ctx,
		`INSERT INTO changes (domain, subdomain, change_type, old_value, new_value, detected_at, scan_id_old, scan_id_new)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		domain, subdomain, changeType, oldValue, newValue, time.Now(), oldScanID, newScanID,
	)
	
	return err
}

// GetRecentChanges retrieves recent changes for a domain
func (m *Manager) GetRecentChanges(ctx context.Context, domain string, limit int) ([]*Change, error) {
	rows, err := m.db.QueryContext(ctx,
		`SELECT subdomain, change_type, old_value, new_value, detected_at
		 FROM changes
		 WHERE domain = ?
		 ORDER BY detected_at DESC
		 LIMIT ?`,
		domain, limit,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	
	var changes []*Change
	for rows.Next() {
		change := &Change{}
		if err := rows.Scan(&change.Subdomain, &change.ChangeType, &change.OldValue,
			&change.NewValue, &change.DetectedAt); err != nil {
			return nil, err
		}
		changes = append(changes, change)
	}
	
	return changes, rows.Err()
}

// Change represents a detected change
type Change struct {
	Subdomain  string
	ChangeType string
	OldValue   string
	NewValue   string
	DetectedAt time.Time
}

// GetStatistics retrieves storage statistics
func (m *Manager) GetStatistics(ctx context.Context) (*Statistics, error) {
	stats := &Statistics{}
	
	// Total scans
	err := m.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM scans`).Scan(&stats.TotalScans)
	if err != nil {
		return nil, err
	}
	
	// Total subdomains
	err = m.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM subdomains WHERE status = 'active'`).Scan(&stats.TotalSubdomains)
	if err != nil {
		return nil, err
	}
	
	// Total changes
	err = m.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM changes`).Scan(&stats.TotalChanges)
	if err != nil {
		return nil, err
	}
	
	return stats, nil
}

// Statistics contains storage statistics
type Statistics struct {
	TotalScans      int
	TotalSubdomains int
	TotalChanges    int
}