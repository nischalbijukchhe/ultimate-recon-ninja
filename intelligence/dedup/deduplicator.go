package dedup

import (
	"context"
	"crypto/sha256"
	"fmt"
	"sort"
	"strings"

	"github.com/yourusername/usr/internal/types"
	"go.uber.org/zap"
)

// Deduplicator removes duplicate and similar subdomains
type Deduplicator struct {
	logger *zap.Logger
}

// NewDeduplicator creates a new deduplication engine
func NewDeduplicator(logger *zap.Logger) *Deduplicator {
	return &Deduplicator{
		logger: logger,
	}
}

// Deduplicate removes exact duplicates and merges metadata
func (d *Deduplicator) Deduplicate(ctx context.Context, subdomains []*types.Subdomain) []*types.Subdomain {
	if len(subdomains) == 0 {
		return subdomains
	}
	
	d.logger.Info("Starting deduplication", zap.Int("input_count", len(subdomains)))
	
	// Map by domain name
	domainMap := make(map[string]*types.Subdomain)
	
	for _, sub := range subdomains {
		normalized := strings.ToLower(strings.TrimSpace(sub.Domain))
		
		if existing, exists := domainMap[normalized]; exists {
			// Merge with existing entry
			d.merge(existing, sub)
		} else {
			// New entry
			sub.Domain = normalized
			domainMap[normalized] = sub
		}
	}
	
	// Convert back to slice
	result := make([]*types.Subdomain, 0, len(domainMap))
	for _, sub := range domainMap {
		result = append(result, sub)
	}
	
	d.logger.Info("Deduplication complete",
		zap.Int("input_count", len(subdomains)),
		zap.Int("output_count", len(result)),
		zap.Int("removed", len(subdomains)-len(result)),
	)
	
	return result
}

// merge combines metadata from two subdomain entries
func (d *Deduplicator) merge(target, source *types.Subdomain) {
	// Merge sources
	sourceSet := make(map[string]bool)
	for _, s := range target.Sources {
		sourceSet[s] = true
	}
	for _, s := range source.Sources {
		if !sourceSet[s] {
			target.Sources = append(target.Sources, s)
			sourceSet[s] = true
		}
	}
	
	// Merge IPs
	if len(source.IP) > 0 {
		ipSet := make(map[string]bool)
		for _, ip := range target.IP {
			ipSet[ip] = true
		}
		for _, ip := range source.IP {
			if !ipSet[ip] {
				target.IP = append(target.IP, ip)
				ipSet[ip] = true
			}
		}
	}
	
	// Use earliest first seen
	if source.FirstSeen.Before(target.FirstSeen) {
		target.FirstSeen = source.FirstSeen
	}
	
	// Use latest last seen
	if source.LastSeen.After(target.LastSeen) {
		target.LastSeen = source.LastSeen
	}
	
	// Merge validation status (true if either is validated)
	if source.Validated {
		target.Validated = true
	}
	
	// Keep best HTTP info (highest status code)
	if source.HTTP != nil {
		if target.HTTP == nil {
			target.HTTP = source.HTTP
		} else if source.HTTP.StatusCode > target.HTTP.StatusCode {
			target.HTTP = source.HTTP
		}
	}
	
	// Keep valid TLS info
	if source.TLS != nil && source.TLS.Valid {
		if target.TLS == nil || !target.TLS.Valid {
			target.TLS = source.TLS
		}
	}
	
	// Merge DNS records
	if source.DNSRecords != nil {
		if target.DNSRecords == nil {
			target.DNSRecords = source.DNSRecords
		} else {
			d.mergeDNSRecords(target.DNSRecords, source.DNSRecords)
		}
	}
	
	// Merge metadata
	if target.Metadata == nil {
		target.Metadata = make(map[string]interface{})
	}
	for k, v := range source.Metadata {
		if _, exists := target.Metadata[k]; !exists {
			target.Metadata[k] = v
		}
	}
}

// mergeDNSRecords merges DNS records
func (d *Deduplicator) mergeDNSRecords(target, source *types.DNSRecords) {
	target.A = d.mergeStringSlice(target.A, source.A)
	target.AAAA = d.mergeStringSlice(target.AAAA, source.AAAA)
	target.CNAME = d.mergeStringSlice(target.CNAME, source.CNAME)
	target.MX = d.mergeStringSlice(target.MX, source.MX)
	target.NS = d.mergeStringSlice(target.NS, source.NS)
	target.TXT = d.mergeStringSlice(target.TXT, source.TXT)
}

// mergeStringSlice merges two string slices removing duplicates
func (d *Deduplicator) mergeStringSlice(a, b []string) []string {
	seen := make(map[string]bool)
	result := make([]string, 0, len(a)+len(b))
	
	for _, s := range a {
		if !seen[s] {
			result = append(result, s)
			seen[s] = true
		}
	}
	
	for _, s := range b {
		if !seen[s] {
			result = append(result, s)
			seen[s] = true
		}
	}
	
	return result
}

// RemoveSimilar removes subdomains that are too similar (fuzzy dedup)
func (d *Deduplicator) RemoveSimilar(ctx context.Context, subdomains []*types.Subdomain, threshold float64) []*types.Subdomain {
	if len(subdomains) == 0 || threshold >= 1.0 {
		return subdomains
	}
	
	d.logger.Info("Removing similar subdomains",
		zap.Int("count", len(subdomains)),
		zap.Float64("threshold", threshold),
	)
	
	// Group by fingerprint
	groups := make(map[string][]*types.Subdomain)
	
	for _, sub := range subdomains {
		fingerprint := d.fingerprint(sub.Domain)
		groups[fingerprint] = append(groups[fingerprint], sub)
	}
	
	// Keep best from each group
	var result []*types.Subdomain
	removedCount := 0
	
	for _, group := range groups {
		if len(group) == 1 {
			result = append(result, group[0])
			continue
		}
		
		// Sort by confidence
		sort.Slice(group, func(i, j int) bool {
			return group[i].Confidence > group[j].Confidence
		})
		
		// Keep the highest confidence one
		result = append(result, group[0])
		removedCount += len(group) - 1
	}
	
	d.logger.Info("Similar removal complete",
		zap.Int("removed", removedCount),
		zap.Int("remaining", len(result)),
	)
	
	return result
}

// fingerprint creates a fingerprint for similarity detection
func (d *Deduplicator) fingerprint(domain string) string {
	// Extract subdomain part
	parts := strings.Split(domain, ".")
	if len(parts) == 0 {
		return domain
	}
	
	subdomain := parts[0]
	
	// Normalize
	normalized := strings.ToLower(subdomain)
	
	// Remove common suffixes/prefixes for grouping
	normalized = strings.TrimPrefix(normalized, "www")
	normalized = strings.TrimPrefix(normalized, "www-")
	normalized = strings.TrimSuffix(normalized, "-prod")
	normalized = strings.TrimSuffix(normalized, "-dev")
	normalized = strings.TrimSuffix(normalized, "-staging")
	
	// Remove numbers for pattern matching
	var builder strings.Builder
	for _, r := range normalized {
		if (r >= 'a' && r <= 'z') || r == '-' {
			builder.WriteRune(r)
		}
	}
	
	pattern := builder.String()
	
	// Create hash of pattern
	hash := sha256.Sum256([]byte(pattern))
	return fmt.Sprintf("%x", hash[:8])
}

// RemoveWildcards filters out wildcard DNS results
func (d *Deduplicator) RemoveWildcards(ctx context.Context, subdomains []*types.Subdomain, wildcardPatterns []string) []*types.Subdomain {
	if len(wildcardPatterns) == 0 {
		return subdomains
	}
	
	d.logger.Info("Filtering wildcard matches",
		zap.Int("count", len(subdomains)),
		zap.Strings("patterns", wildcardPatterns),
	)
	
	var filtered []*types.Subdomain
	removedCount := 0
	
	for _, sub := range subdomains {
		isWildcard := false
		
		// Check if any IP matches wildcard patterns
		for _, ip := range sub.IP {
			for _, pattern := range wildcardPatterns {
				if ip == pattern {
					isWildcard = true
					break
				}
			}
			if isWildcard {
				break
			}
		}
		
		if !isWildcard {
			filtered = append(filtered, sub)
		} else {
			removedCount++
		}
	}
	
	d.logger.Info("Wildcard filtering complete",
		zap.Int("removed", removedCount),
		zap.Int("remaining", len(filtered)),
	)
	
	return filtered
}

// RemoveNoise removes low-quality results
func (d *Deduplicator) RemoveNoise(ctx context.Context, subdomains []*types.Subdomain) []*types.Subdomain {
	d.logger.Info("Removing noise", zap.Int("count", len(subdomains)))
	
	var filtered []*types.Subdomain
	removedCount := 0
	
	for _, sub := range subdomains {
		if d.isNoise(sub) {
			removedCount++
			continue
		}
		filtered = append(filtered, sub)
	}
	
	d.logger.Info("Noise removal complete",
		zap.Int("removed", removedCount),
		zap.Int("remaining", len(filtered)),
	)
	
	return filtered
}

// isNoise determines if a subdomain is likely noise
func (d *Deduplicator) isNoise(sub *types.Subdomain) bool {
	domain := strings.ToLower(sub.Domain)
	
	// Check for test/temporary patterns
	noisePatterns := []string{
		"wildcard-test",
		"test-test-test",
		"asdfasdf",
		"xxxxxxxxxx",
		"localhost",
		"invalid",
		"example",
		"_domainkey",
		"_dmarc",
	}
	
	for _, pattern := range noisePatterns {
		if strings.Contains(domain, pattern) {
			return true
		}
	}
	
	// Very long random-looking strings
	parts := strings.Split(domain, ".")
	if len(parts) > 0 && len(parts[0]) > 60 {
		return true
	}
	
	// Too many consecutive numbers or hyphens
	if strings.Count(parts[0], "0123456789") > 20 {
		return true
	}
	
	if strings.Count(parts[0], "-") > 8 {
		return true
	}
	
	return false
}

// GetStatistics returns deduplication statistics
func (d *Deduplicator) GetStatistics(original, deduplicated []*types.Subdomain) map[string]int {
	return map[string]int{
		"original_count":     len(original),
		"deduplicated_count": len(deduplicated),
		"removed_count":      len(original) - len(deduplicated),
	}
}