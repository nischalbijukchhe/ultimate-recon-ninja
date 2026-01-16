package engine

import (
	"context"
	"fmt"
	"strings"
	"sync"

	"github.com/yourusername/usr/ai/ollama"
	"github.com/yourusername/usr/ai/prompts"
	"github.com/yourusername/usr/internal/config"
	"go.uber.org/zap"
)

// Engine manages AI-enhanced reconnaissance operations
type Engine struct {
	client    *ollama.Client
	config    *config.AIConfig
	logger    *zap.Logger
	
	// Recursion safety
	recursionDepth    int
	maxRecursionDepth int
	recursionMu       sync.Mutex
	
	// Cache to prevent duplicate AI calls
	cache   map[string][]string
	cacheMu sync.RWMutex
}

// NewEngine creates a new AI engine
func NewEngine(cfg *config.AIConfig, logger *zap.Logger) *Engine {
	return &Engine{
		client:            ollama.NewClient(cfg, logger),
		config:            cfg,
		logger:            logger,
		maxRecursionDepth: 3, // Safety limit
		cache:             make(map[string][]string),
	}
}

// IsAvailable checks if AI engine is ready to use
func (e *Engine) IsAvailable(ctx context.Context) bool {
	if !e.config.Enabled {
		return false
	}
	
	return e.client.IsAvailable(ctx)
}

// GenerateWordlist creates a context-aware wordlist
func (e *Engine) GenerateWordlist(ctx context.Context, domain string, context map[string]interface{}) ([]string, error) {
	cacheKey := fmt.Sprintf("wordlist:%s", domain)
	
	// Check cache
	if cached := e.getCache(cacheKey); cached != nil {
		e.logger.Debug("Using cached wordlist", zap.String("domain", domain))
		return cached, nil
	}
	
	e.logger.Info("Generating AI wordlist", zap.String("domain", domain))
	
	vars := map[string]interface{}{
		"Domain": domain,
	}
	
	// Add optional context
	for k, v := range context {
		vars[k] = v
	}
	
	prompt, err := prompts.Render("wordlist_generation", vars)
	if err != nil {
		return nil, fmt.Errorf("failed to render prompt: %w", err)
	}
	
	response, err := e.client.Generate(ctx, prompt)
	if err != nil {
		return nil, fmt.Errorf("AI generation failed: %w", err)
	}
	
	wordlist := e.parseWordlist(response)
	
	// Cache result
	e.setCache(cacheKey, wordlist)
	
	e.logger.Info("AI wordlist generated",
		zap.String("domain", domain),
		zap.Int("count", len(wordlist)),
	)
	
	return wordlist, nil
}

// InferPatterns analyzes existing subdomains and infers patterns
func (e *Engine) InferPatterns(ctx context.Context, subdomains []string) ([]string, error) {
	if len(subdomains) == 0 {
		return nil, fmt.Errorf("no subdomains provided")
	}
	
	cacheKey := fmt.Sprintf("patterns:%s", strings.Join(subdomains[:min(5, len(subdomains))], ","))
	
	if cached := e.getCache(cacheKey); cached != nil {
		e.logger.Debug("Using cached pattern inference")
		return cached, nil
	}
	
	e.logger.Info("Inferring subdomain patterns", zap.Int("subdomain_count", len(subdomains)))
	
	// Limit input size to prevent token overflow
	sampleSize := min(50, len(subdomains))
	sample := strings.Join(subdomains[:sampleSize], "\n")
	
	vars := map[string]interface{}{
		"Subdomains": sample,
	}
	
	prompt, err := prompts.Render("pattern_inference", vars)
	if err != nil {
		return nil, fmt.Errorf("failed to render prompt: %w", err)
	}
	
	response, err := e.client.Generate(ctx, prompt)
	if err != nil {
		return nil, fmt.Errorf("AI generation failed: %w", err)
	}
	
	patterns := e.parseWordlist(response)
	
	e.setCache(cacheKey, patterns)
	
	e.logger.Info("Pattern inference complete", zap.Int("new_suggestions", len(patterns)))
	
	return patterns, nil
}

// GenerateMutations creates variations of a subdomain
func (e *Engine) GenerateMutations(ctx context.Context, subdomain string) ([]string, error) {
	cacheKey := fmt.Sprintf("mutations:%s", subdomain)
	
	if cached := e.getCache(cacheKey); cached != nil {
		return cached, nil
	}
	
	e.logger.Debug("Generating mutations", zap.String("subdomain", subdomain))
	
	vars := map[string]interface{}{
		"Subdomain": subdomain,
	}
	
	prompt, err := prompts.Render("mutation_suggestions", vars)
	if err != nil {
		return nil, fmt.Errorf("failed to render prompt: %w", err)
	}
	
	response, err := e.client.Generate(ctx, prompt)
	if err != nil {
		return nil, fmt.Errorf("AI generation failed: %w", err)
	}
	
	mutations := e.parseWordlist(response)
	
	e.setCache(cacheKey, mutations)
	
	return mutations, nil
}

// RecursiveDiscovery generates related subdomains based on discovered one
func (e *Engine) RecursiveDiscovery(ctx context.Context, subdomain string, purpose string) ([]string, error) {
	// Check recursion depth
	e.recursionMu.Lock()
	if e.recursionDepth >= e.maxRecursionDepth {
		e.recursionMu.Unlock()
		e.logger.Warn("Max recursion depth reached", zap.Int("depth", e.recursionDepth))
		return nil, fmt.Errorf("max recursion depth reached")
	}
	e.recursionDepth++
	e.recursionMu.Unlock()
	
	defer func() {
		e.recursionMu.Lock()
		e.recursionDepth--
		e.recursionMu.Unlock()
	}()
	
	cacheKey := fmt.Sprintf("recursive:%s:%s", subdomain, purpose)
	
	if cached := e.getCache(cacheKey); cached != nil {
		return cached, nil
	}
	
	e.logger.Info("Recursive discovery",
		zap.String("subdomain", subdomain),
		zap.String("purpose", purpose),
		zap.Int("depth", e.recursionDepth),
	)
	
	vars := map[string]interface{}{
		"Subdomain":       subdomain,
		"InferredPurpose": purpose,
	}
	
	prompt, err := prompts.Render("recursive_discovery", vars)
	if err != nil {
		return nil, fmt.Errorf("failed to render prompt: %w", err)
	}
	
	response, err := e.client.Generate(ctx, prompt)
	if err != nil {
		return nil, fmt.Errorf("AI generation failed: %w", err)
	}
	
	suggestions := e.parseWordlist(response)
	
	e.setCache(cacheKey, suggestions)
	
	return suggestions, nil
}

// AnalyzeConfidence uses AI to assess subdomain confidence
func (e *Engine) AnalyzeConfidence(ctx context.Context, subdomain string, metadata map[string]interface{}) (int, string, error) {
	vars := map[string]interface{}{
		"Subdomain": subdomain,
	}
	
	for k, v := range metadata {
		vars[k] = v
	}
	
	prompt, err := prompts.Render("confidence_analysis", vars)
	if err != nil {
		return 0, "", fmt.Errorf("failed to render prompt: %w", err)
	}
	
	response, err := e.client.Generate(ctx, prompt)
	if err != nil {
		return 0, "", fmt.Errorf("AI generation failed: %w", err)
	}
	
	score, reasoning := e.parseConfidenceResponse(response)
	
	return score, reasoning, nil
}

// DetectNoise identifies false positives and noise
func (e *Engine) DetectNoise(ctx context.Context, subdomains []string) (map[string]string, error) {
	if len(subdomains) == 0 {
		return nil, nil
	}
	
	e.logger.Info("Running AI noise detection", zap.Int("subdomain_count", len(subdomains)))
	
	// Limit sample size
	sampleSize := min(100, len(subdomains))
	sample := strings.Join(subdomains[:sampleSize], "\n")
	
	vars := map[string]interface{}{
		"Subdomains": sample,
	}
	
	prompt, err := prompts.Render("noise_detection", vars)
	if err != nil {
		return nil, fmt.Errorf("failed to render prompt: %w", err)
	}
	
	response, err := e.client.Generate(ctx, prompt)
	if err != nil {
		return nil, fmt.Errorf("AI generation failed: %w", err)
	}
	
	noise := e.parseNoiseResponse(response)
	
	e.logger.Info("Noise detection complete", zap.Int("noise_count", len(noise)))
	
	return noise, nil
}

// parseWordlist extracts subdomain names from AI response
func (e *Engine) parseWordlist(response string) []string {
	var wordlist []string
	seen := make(map[string]bool)
	
	lines := strings.Split(response, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		
		// Skip empty lines, explanations, and numbered lists
		if line == "" || strings.HasPrefix(line, "#") || 
		   strings.HasPrefix(line, "//") || strings.Contains(line, ":") {
			continue
		}
		
		// Remove numbering (1. 2. etc)
		parts := strings.Fields(line)
		if len(parts) > 0 {
			word := parts[len(parts)-1]
			word = strings.TrimRight(word, ".,;")
			word = strings.ToLower(word)
			
			// Validate subdomain format
			if isValidSubdomain(word) && !seen[word] {
				wordlist = append(wordlist, word)
				seen[word] = true
			}
		}
	}
	
	return wordlist
}

// parseConfidenceResponse extracts score and reasoning
func (e *Engine) parseConfidenceResponse(response string) (int, string) {
	var score int
	var reasoning string
	
	lines := strings.Split(response, "\n")
	for _, line := range lines {
		if strings.HasPrefix(line, "SCORE:") {
			fmt.Sscanf(line, "SCORE: %d", &score)
		} else if strings.HasPrefix(line, "REASONING:") {
			reasoning = strings.TrimPrefix(line, "REASONING:")
			reasoning = strings.TrimSpace(reasoning)
		}
	}
	
	// Clamp score
	if score < 0 {
		score = 0
	}
	if score > 100 {
		score = 100
	}
	
	return score, reasoning
}

// parseNoiseResponse extracts noise entries
func (e *Engine) parseNoiseResponse(response string) map[string]string {
	noise := make(map[string]string)
	
	lines := strings.Split(response, "\n")
	for _, line := range lines {
		if strings.Contains(line, "|") {
			parts := strings.Split(line, "|")
			if len(parts) == 2 {
				subdomain := strings.TrimSpace(parts[0])
				reason := strings.TrimSpace(parts[1])
				noise[subdomain] = reason
			}
		}
	}
	
	return noise
}

// getCache retrieves cached results
func (e *Engine) getCache(key string) []string {
	e.cacheMu.RLock()
	defer e.cacheMu.RUnlock()
	return e.cache[key]
}

// setCache stores results in cache
func (e *Engine) setCache(key string, value []string) {
	e.cacheMu.Lock()
	defer e.cacheMu.Unlock()
	e.cache[key] = value
}

// isValidSubdomain checks if a string is a valid subdomain component
func isValidSubdomain(s string) bool {
	if len(s) == 0 || len(s) > 63 {
		return false
	}
	
	for _, c := range s {
		if !((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-') {
			return false
		}
	}
	
	return !strings.HasPrefix(s, "-") && !strings.HasSuffix(s, "-")
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}