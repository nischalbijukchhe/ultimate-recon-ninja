package scorer

import (
	"context"
	"math"
	"strings"
	"time"

	"github.com/yourusername/usr/internal/types"
	"go.uber.org/zap"
)

// Scorer calculates confidence scores for discovered subdomains
type Scorer struct {
	logger *zap.Logger
	
	// Source reliability weights
	sourceWeights map[string]int
}

// NewScorer creates a new scoring engine
func NewScorer(logger *zap.Logger) *Scorer {
	return &Scorer{
		logger: logger,
		sourceWeights: map[string]int{
			// Passive sources (high reliability)
			"crtsh":                 15,
			"certificate_transparency": 15,
			"virustotal":            12,
			"passive_dns":           12,
			"wayback_machine":       10,
			"common_crawl":          8,
			"shodan":                10,
			"censys":                10,
			
			// Active sources (medium reliability - requires validation)
			"dns_bruteforce":        8,
			"permutations":          6,
			"recursive":             7,
			
			// Web sources (medium-high reliability)
			"http_probing":          10,
			"js_parsing":            9,
			"cloud_assets":          11,
			
			// AI sources (lower weight - needs validation)
			"ai-enhanced":           5,
			"ai_patterns":           6,
			"ai_mutations":          4,
		},
	}
}

// Score calculates a comprehensive confidence score for a subdomain
func (s *Scorer) Score(ctx context.Context, subdomain *types.Subdomain) int {
	var score float64
	
	// Component 1: Source credibility (max 40 points)
	sourceScore := s.calculateSourceScore(subdomain.Sources)
	score += math.Min(sourceScore, 40)
	
	// Component 2: Validation status (max 30 points)
	validationScore := s.calculateValidationScore(subdomain)
	score += validationScore
	
	// Component 3: Response quality (max 20 points)
	responseScore := s.calculateResponseScore(subdomain)
	score += responseScore
	
	// Component 4: Pattern confidence (max 10 points)
	patternScore := s.calculatePatternScore(subdomain)
	score += patternScore
	
	// Normalize to 0-100
	finalScore := int(math.Min(score, 100))
	
	s.logger.Debug("Subdomain scored",
		zap.String("domain", subdomain.Domain),
		zap.Int("score", finalScore),
		zap.Float64("source_score", sourceScore),
		zap.Float64("validation_score", validationScore),
		zap.Float64("response_score", responseScore),
		zap.Float64("pattern_score", patternScore),
	)
	
	return finalScore
}

// calculateSourceScore evaluates score based on sources
func (s *Scorer) calculateSourceScore(sources []string) float64 {
	if len(sources) == 0 {
		return 0
	}
	
	var totalWeight float64
	seen := make(map[string]bool)
	
	for _, source := range sources {
		if seen[source] {
			continue
		}
		seen[source] = true
		
		weight := s.sourceWeights[source]
		if weight == 0 {
			weight = 5 // Default weight for unknown sources
		}
		
		totalWeight += float64(weight)
	}
	
	// Multiple sources boost confidence
	multiplicityBonus := math.Log2(float64(len(seen))) * 5
	
	return totalWeight + multiplicityBonus
}

// calculateValidationScore evaluates validation status
func (s *Scorer) calculateValidationScore(subdomain *types.Subdomain) float64 {
	var score float64
	
	// DNS validation (15 points)
	if subdomain.Validated && len(subdomain.IP) > 0 {
		score += 15
		
		// Multiple IPs indicate real infrastructure
		if len(subdomain.IP) > 1 {
			score += 3
		}
	}
	
	// HTTP validation (10 points)
	if subdomain.HTTP != nil {
		if subdomain.HTTP.StatusCode >= 200 && subdomain.HTTP.StatusCode < 400 {
			score += 10
		} else if subdomain.HTTP.StatusCode >= 400 && subdomain.HTTP.StatusCode < 500 {
			score += 5 // Still exists, just restricted
		}
	}
	
	// TLS validation (5 points)
	if subdomain.TLS != nil && subdomain.TLS.Valid {
		score += 5
	}
	
	return score
}

// calculateResponseScore evaluates HTTP response quality
func (s *Scorer) calculateResponseScore(subdomain *types.Subdomain) float64 {
	if subdomain.HTTP == nil {
		return 0
	}
	
	var score float64
	
	// Status code indicates active service
	if subdomain.HTTP.StatusCode > 0 {
		score += 5
	}
	
	// Title indicates real content
	if subdomain.HTTP.Title != "" && len(subdomain.HTTP.Title) > 3 {
		score += 5
	}
	
	// Server header indicates real infrastructure
	if subdomain.HTTP.Server != "" {
		score += 3
	}
	
	// Technologies indicate development
	if len(subdomain.HTTP.Technologies) > 0 {
		score += 7
	}
	
	return score
}

// calculatePatternScore evaluates naming pattern confidence
func (s *Scorer) calculatePatternScore(subdomain *types.Subdomain) float64 {
	domain := subdomain.Domain
	
	var score float64
	
	// Common patterns are more reliable
	if hasCommonPattern(domain) {
		score += 5
	}
	
	// Short, simple names are more likely to be real
	parts := strings.Split(domain, ".")
	if len(parts) > 0 && len(parts[0]) < 15 {
		score += 3
	}
	
	// Avoid suspicious patterns
	if hasSuspiciousPattern(domain) {
		score -= 5
	}
	
	// Ensure non-negative
	if score < 0 {
		score = 0
	}
	
	return score
}

// BatchScore scores multiple subdomains efficiently
func (s *Scorer) BatchScore(ctx context.Context, subdomains []*types.Subdomain) {
	for _, subdomain := range subdomains {
		select {
		case <-ctx.Done():
			return
		default:
			subdomain.Confidence = s.Score(ctx, subdomain)
		}
	}
	
	s.logger.Info("Batch scoring complete",
		zap.Int("count", len(subdomains)),
	)
}

// hasCommonPattern checks for common subdomain patterns
func hasCommonPattern(domain string) bool {
	commonPatterns := []string{
		"www", "api", "mail", "ftp", "smtp", "pop", "imap",
		"dev", "staging", "stage", "test", "qa", "prod", "production",
		"admin", "portal", "dashboard", "app", "mobile", "m",
		"blog", "shop", "store", "cdn", "static", "assets",
		"vpn", "remote", "secure", "login", "auth",
		"us", "eu", "asia", "uk", "ca",
	}
	
	parts := strings.Split(domain, ".")
	if len(parts) == 0 {
		return false
	}
	
	first := parts[0]
	
	for _, pattern := range commonPatterns {
		if first == pattern || strings.HasPrefix(first, pattern+"-") || 
		   strings.HasSuffix(first, "-"+pattern) {
			return true
		}
	}
	
	return false
}

// hasSuspiciousPattern checks for suspicious patterns
func hasSuspiciousPattern(domain string) bool {
	suspicious := []string{
		"wildcard-test",
		"random",
		"localhost",
		"invalid",
		"example",
		"test-test-test",
	}
	
	domainLower := strings.ToLower(domain)
	
	for _, pattern := range suspicious {
		if strings.Contains(domainLower, pattern) {
			return true
		}
	}
	
	// Very long subdomain components are suspicious
	parts := strings.Split(domain, ".")
	if len(parts) > 0 && len(parts[0]) > 50 {
		return true
	}
	
	// Too many hyphens
	if strings.Count(parts[0], "-") > 5 {
		return true
	}
	
	return false
}

// RankByConfidence sorts subdomains by confidence score
func (s *Scorer) RankByConfidence(subdomains []*types.Subdomain) []*types.Subdomain {
	ranked := make([]*types.Subdomain, len(subdomains))
	copy(ranked, subdomains)
	
	// Simple bubble sort for small datasets
	// For production, use sort.Slice
	for i := 0; i < len(ranked); i++ {
		for j := i + 1; j < len(ranked); j++ {
			if ranked[j].Confidence > ranked[i].Confidence {
				ranked[i], ranked[j] = ranked[j], ranked[i]
			}
		}
	}
	
	return ranked
}

// FilterByConfidence removes low-confidence subdomains
func (s *Scorer) FilterByConfidence(subdomains []*types.Subdomain, minConfidence int) []*types.Subdomain {
	var filtered []*types.Subdomain
	
	for _, subdomain := range subdomains {
		if subdomain.Confidence >= minConfidence {
			filtered = append(filtered, subdomain)
		}
	}
	
	s.logger.Info("Confidence filtering applied",
		zap.Int("original_count", len(subdomains)),
		zap.Int("filtered_count", len(filtered)),
		zap.Int("min_confidence", minConfidence),
	)
	
	return filtered
}