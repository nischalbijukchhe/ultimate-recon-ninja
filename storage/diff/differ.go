package diff

import (
	"context"
	"fmt"

	"github.com/yourusername/usr/storage"
	"go.uber.org/zap"
)

// Differ compares scan results to detect changes
type Differ struct {
	storage *storage.Manager
	logger  *zap.Logger
}

// NewDiffer creates a new diff engine
func NewDiffer(storage *storage.Manager, logger *zap.Logger) *Differ {
	return &Differ{
		storage: storage,
		logger:  logger,
	}
}

// DiffResult contains the comparison results
type DiffResult struct {
	Domain        string
	OldScanID     int64
	NewScanID     int64
	Added         []string
	Removed       []string
	Unchanged     []string
	TotalOld      int
	TotalNew      int
	ChangePercent float64
}

// Compare compares two scans and returns differences
func (d *Differ) Compare(ctx context.Context, domain string, oldScanID, newScanID int64) (*DiffResult, error) {
	d.logger.Info("Comparing scans",
		zap.String("domain", domain),
		zap.Int64("old_scan", oldScanID),
		zap.Int64("new_scan", newScanID),
	)
	
	// Get subdomains from both scans
	oldSubdomains, err := d.storage.GetScanSubdomains(ctx, oldScanID)
	if err != nil {
		return nil, fmt.Errorf("failed to get old scan subdomains: %w", err)
	}
	
	newSubdomains, err := d.storage.GetScanSubdomains(ctx, newScanID)
	if err != nil {
		return nil, fmt.Errorf("failed to get new scan subdomains: %w", err)
	}
	
	// Create maps for efficient lookup
	oldMap := make(map[string]bool)
	for _, sub := range oldSubdomains {
		oldMap[sub] = true
	}
	
	newMap := make(map[string]bool)
	for _, sub := range newSubdomains {
		newMap[sub] = true
	}
	
	result := &DiffResult{
		Domain:    domain,
		OldScanID: oldScanID,
		NewScanID: newScanID,
		TotalOld:  len(oldSubdomains),
		TotalNew:  len(newSubdomains),
	}
	
	// Find added subdomains
	for _, sub := range newSubdomains {
		if !oldMap[sub] {
			result.Added = append(result.Added, sub)
		}
	}
	
	// Find removed subdomains
	for _, sub := range oldSubdomains {
		if !newMap[sub] {
			result.Removed = append(result.Removed, sub)
		}
	}
	
	// Find unchanged subdomains
	for _, sub := range newSubdomains {
		if oldMap[sub] {
			result.Unchanged = append(result.Unchanged, sub)
		}
	}
	
	// Calculate change percentage
	totalChanges := len(result.Added) + len(result.Removed)
	totalSubdomains := len(oldSubdomains) + len(newSubdomains)
	if totalSubdomains > 0 {
		result.ChangePercent = (float64(totalChanges) / float64(totalSubdomains)) * 100
	}
	
	d.logger.Info("Diff complete",
		zap.Int("added", len(result.Added)),
		zap.Int("removed", len(result.Removed)),
		zap.Int("unchanged", len(result.Unchanged)),
		zap.Float64("change_percent", result.ChangePercent),
	)
	
	return result, nil
}

// CompareLatest compares current scan with the most recent historical scan
func (d *Differ) CompareLatest(ctx context.Context, domain string, currentScanID int64) (*DiffResult, error) {
	// Get previous scan
	previousScanID, err := d.storage.GetLatestScan(ctx, domain)
	if err != nil {
		return nil, err
	}
	
	if previousScanID == 0 || previousScanID == currentScanID {
		d.logger.Info("No previous scan found for comparison", zap.String("domain", domain))
		return nil, fmt.Errorf("no previous scan available")
	}
	
	return d.Compare(ctx, domain, previousScanID, currentScanID)
}

// SaveChanges persists detected changes to the database
func (d *Differ) SaveChanges(ctx context.Context, result *DiffResult) error {
	d.logger.Info("Saving changes to database",
		zap.String("domain", result.Domain),
		zap.Int("total_changes", len(result.Added)+len(result.Removed)),
	)
	
	// Save added subdomains
	for _, subdomain := range result.Added {
		err := d.storage.SaveChange(ctx, result.Domain, subdomain, "added", "", subdomain,
			result.OldScanID, result.NewScanID)
		if err != nil {
			d.logger.Error("Failed to save change",
				zap.String("subdomain", subdomain),
				zap.Error(err),
			)
		}
	}
	
	// Save removed subdomains
	for _, subdomain := range result.Removed {
		err := d.storage.SaveChange(ctx, result.Domain, subdomain, "removed", subdomain, "",
			result.OldScanID, result.NewScanID)
		if err != nil {
			d.logger.Error("Failed to save change",
				zap.String("subdomain", subdomain),
				zap.Error(err),
			)
		}
	}
	
	d.logger.Info("Changes saved successfully")
	
	return nil
}

// GenerateReport creates a human-readable diff report
func (d *Differ) GenerateReport(result *DiffResult) string {
	report := fmt.Sprintf("Subdomain Change Report for %s\n", result.Domain)
	report += "=" + repeatString("=", len(result.Domain)+30) + "\n\n"
	
	report += fmt.Sprintf("Previous Scan: %d subdomains\n", result.TotalOld)
	report += fmt.Sprintf("Current Scan:  %d subdomains\n", result.TotalNew)
	report += fmt.Sprintf("Change Rate:   %.2f%%\n\n", result.ChangePercent)
	
	if len(result.Added) > 0 {
		report += fmt.Sprintf("NEW SUBDOMAINS (%d):\n", len(result.Added))
		report += repeatString("-", 50) + "\n"
		for _, sub := range result.Added {
			report += fmt.Sprintf("+ %s\n", sub)
		}
		report += "\n"
	}
	
	if len(result.Removed) > 0 {
		report += fmt.Sprintf("REMOVED SUBDOMAINS (%d):\n", len(result.Removed))
		report += repeatString("-", 50) + "\n"
		for _, sub := range result.Removed {
			report += fmt.Sprintf("- %s\n", sub)
		}
		report += "\n"
	}
	
	if len(result.Added) == 0 && len(result.Removed) == 0 {
		report += "No changes detected.\n"
	}
	
	return report
}

// DetectTrends analyzes historical changes to identify patterns
func (d *Differ) DetectTrends(ctx context.Context, domain string, limit int) (*TrendAnalysis, error) {
	changes, err := d.storage.GetRecentChanges(ctx, domain, limit)
	if err != nil {
		return nil, err
	}
	
	analysis := &TrendAnalysis{
		Domain:      domain,
		TotalChanges: len(changes),
	}
	
	// Count change types
	addedCount := 0
	removedCount := 0
	
	for _, change := range changes {
		switch change.ChangeType {
		case "added":
			addedCount++
		case "removed":
			removedCount++
		}
	}
	
	analysis.AddedCount = addedCount
	analysis.RemovedCount = removedCount
	
	// Determine trend
	if addedCount > removedCount*2 {
		analysis.Trend = "rapid_growth"
	} else if removedCount > addedCount*2 {
		analysis.Trend = "rapid_decline"
	} else if addedCount > removedCount {
		analysis.Trend = "growth"
	} else if removedCount > addedCount {
		analysis.Trend = "decline"
	} else {
		analysis.Trend = "stable"
	}
	
	d.logger.Info("Trend analysis complete",
		zap.String("domain", domain),
		zap.String("trend", analysis.Trend),
		zap.Int("added", addedCount),
		zap.Int("removed", removedCount),
	)
	
	return analysis, nil
}

// TrendAnalysis contains trend information
type TrendAnalysis struct {
	Domain       string
	TotalChanges int
	AddedCount   int
	RemovedCount int
	Trend        string // rapid_growth, growth, stable, decline, rapid_decline
}

func repeatString(s string, count int) string {
	result := ""
	for i := 0; i < count; i++ {
		result += s
	}
	return result
}