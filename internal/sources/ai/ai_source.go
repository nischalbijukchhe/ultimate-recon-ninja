package ai

import (
	"context"
	"fmt"
	"time"

	"github.com/yourusername/usr/ai/engine"
	"github.com/yourusername/usr/internal/config"
	"github.com/yourusername/usr/internal/sources"
	"github.com/yourusername/usr/internal/types"
	"go.uber.org/zap"
)

// AISource implements AI-enhanced subdomain discovery
type AISource struct {
	engine  *engine.Engine
	config  *config.Config
	logger  *zap.Logger
	enabled bool
}

// NewAISource creates a new AI-powered source
func NewAISource(cfg *config.Config, logger *zap.Logger) *AISource {
	aiEngine := engine.NewEngine(&cfg.AI, logger)
	
	return &AISource{
		engine:  aiEngine,
		config:  cfg,
		logger:  logger,
		enabled: cfg.AI.Enabled,
	}
}

// Name returns the source identifier
func (a *AISource) Name() string {
	return "ai-enhanced"
}

// Type returns the source category
func (a *AISource) Type() sources.SourceType {
	return sources.TypeAI
}

// IsEnabled checks if the source is enabled
func (a *AISource) IsEnabled() bool {
	return a.enabled
}

// RateLimit returns the rate limit
func (a *AISource) RateLimit() int {
	return 0 // No external API calls
}

// Enumerate performs AI-enhanced subdomain discovery
func (a *AISource) Enumerate(ctx context.Context, domain string) (*types.SourceResult, error) {
	startTime := time.Now()
	
	result := &types.SourceResult{
		Source:   a.Name(),
		Duration: 0,
	}
	
	// Check if AI engine is available
	if !a.engine.IsAvailable(ctx) {
		err := fmt.Errorf("AI engine not available - ensure Ollama is running")
		result.Error = err
		result.Duration = time.Since(startTime)
		return result, err
	}
	
	a.logger.Info("Starting AI-enhanced discovery", zap.String("domain", domain))
	
	var allSubdomains []string
	
	// Phase 1: Generate context-aware wordlist
	wordlist, err := a.engine.GenerateWordlist(ctx, domain, map[string]interface{}{
		"Industry":    inferIndustry(domain),
		"CompanyType": "technology",
	})
	if err != nil {
		a.logger.Error("AI wordlist generation failed", zap.Error(err))
	} else {
		allSubdomains = append(allSubdomains, wordlist...)
		a.logger.Info("AI wordlist generated", zap.Int("count", len(wordlist)))
	}
	
	// Convert to full subdomains
	var fullSubdomains []string
	for _, sub := range allSubdomains {
		fullSubdomains = append(fullSubdomains, fmt.Sprintf("%s.%s", sub, domain))
	}
	
	result.Subdomains = fullSubdomains
	result.Duration = time.Since(startTime)
	
	a.logger.Info("AI-enhanced discovery complete",
		zap.Int("subdomain_count", len(fullSubdomains)),
		zap.Duration("duration", result.Duration),
	)
	
	return result, nil
}

// EnrichWithPatterns uses AI to infer patterns from existing subdomains
func (a *AISource) EnrichWithPatterns(ctx context.Context, domain string, existingSubdomains []string) ([]string, error) {
	if len(existingSubdomains) == 0 {
		return nil, nil
	}
	
	a.logger.Info("Enriching with AI pattern inference",
		zap.String("domain", domain),
		zap.Int("existing_count", len(existingSubdomains)),
	)
	
	// Remove domain suffix for pattern analysis
	bareSubdomains := make([]string, len(existingSubdomains))
	for i, sub := range existingSubdomains {
		bareSubdomains[i] = stripDomain(sub, domain)
	}
	
	patterns, err := a.engine.InferPatterns(ctx, bareSubdomains)
	if err != nil {
		return nil, err
	}
	
	// Convert back to full subdomains
	var enriched []string
	for _, pattern := range patterns {
		enriched = append(enriched, fmt.Sprintf("%s.%s", pattern, domain))
	}
	
	a.logger.Info("Pattern enrichment complete", zap.Int("new_count", len(enriched)))
	
	return enriched, nil
}

// GenerateMutations creates variations of discovered subdomains
func (a *AISource) GenerateMutations(ctx context.Context, domain string, subdomain string) ([]string, error) {
	bare := stripDomain(subdomain, domain)
	
	mutations, err := a.engine.GenerateMutations(ctx, bare)
	if err != nil {
		return nil, err
	}
	
	// Convert to full subdomains
	var fullMutations []string
	for _, mutation := range mutations {
		fullMutations = append(fullMutations, fmt.Sprintf("%s.%s", mutation, domain))
	}
	
	return fullMutations, nil
}

// stripDomain removes the domain suffix from a subdomain
func stripDomain(subdomain, domain string) string {
	if len(subdomain) > len(domain)+1 {
		return subdomain[:len(subdomain)-len(domain)-1]
	}
	return subdomain
}

// inferIndustry attempts to infer industry from domain
func inferIndustry(domain string) string {
	// Simple heuristics - could be enhanced
	if containsAny(domain, []string{"bank", "finance", "capital", "invest"}) {
		return "finance"
	}
	if containsAny(domain, []string{"health", "medical", "pharma", "clinic"}) {
		return "healthcare"
	}
	if containsAny(domain, []string{"tech", "soft", "dev", "cloud"}) {
		return "technology"
	}
	if containsAny(domain, []string{"shop", "store", "retail", "ecommerce"}) {
		return "retail"
	}
	
	return "general"
}

func containsAny(s string, substrs []string) bool {
	for _, substr := range substrs {
		if contains(s, substr) {
			return true
		}
	}
	return false
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && findSubstring(s, substr)
}

func findSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}