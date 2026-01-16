package dns

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/yourusername/usr/internal/config"
	"github.com/yourusername/usr/internal/types"
	"go.uber.org/zap"
)

// Engine handles high-performance DNS resolution
type Engine struct {
	config    *config.DNSConfig
	resolvers []string
	logger    *zap.Logger
	
	mu            sync.RWMutex
	resolverIndex int
	
	// Rate limiting
	rateLimiter chan struct{}
	
	// Wildcard detection cache
	wildcardCache map[string]*types.WildcardInfo
	wildcardMu    sync.RWMutex
}

// NewEngine creates a new DNS engine
func NewEngine(cfg *config.DNSConfig, logger *zap.Logger) *Engine {
	e := &Engine{
		config:        cfg,
		resolvers:     cfg.Resolvers,
		logger:        logger,
		wildcardCache: make(map[string]*types.WildcardInfo),
	}
	
	// Initialize rate limiter
	if cfg.RateLimit > 0 {
		e.rateLimiter = make(chan struct{}, cfg.RateLimit)
	}
	
	return e
}

// Resolve resolves a domain to IP addresses
func (e *Engine) Resolve(ctx context.Context, domain string) ([]string, error) {
	// Rate limiting
	if e.rateLimiter != nil {
		select {
		case e.rateLimiter <- struct{}{}:
			defer func() { <-e.rateLimiter }()
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	
	resolver := e.getNextResolver()
	
	var ips []string
	var lastErr error
	
	// Retry logic
	for attempt := 0; attempt <= e.config.Retries; attempt++ {
		if attempt > 0 {
			// Exponential backoff
			backoff := time.Duration(attempt) * 100 * time.Millisecond
			select {
			case <-time.After(backoff):
			case <-ctx.Done():
				return nil, ctx.Err()
			}
			resolver = e.getNextResolver()
		}
		
		ips, lastErr = e.resolveWithResolver(ctx, domain, resolver)
		if lastErr == nil {
			return ips, nil
		}
		
		e.logger.Debug("DNS resolution attempt failed",
			zap.String("domain", domain),
			zap.String("resolver", resolver),
			zap.Int("attempt", attempt+1),
			zap.Error(lastErr),
		)
	}
	
	return nil, fmt.Errorf("failed after %d attempts: %w", e.config.Retries+1, lastErr)
}

// resolveWithResolver performs DNS resolution using a specific resolver
func (e *Engine) resolveWithResolver(ctx context.Context, domain, resolver string) ([]string, error) {
	timeoutCtx, cancel := context.WithTimeout(ctx, time.Duration(e.config.Timeout)*time.Second)
	defer cancel()
	
	r := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			d := net.Dialer{
				Timeout: time.Duration(e.config.Timeout) * time.Second,
			}
			return d.DialContext(ctx, network, net.JoinHostPort(resolver, "53"))
		},
	}
	
	ips, err := r.LookupHost(timeoutCtx, domain)
	if err != nil {
		return nil, err
	}
	
	return ips, nil
}

// ResolveBatch resolves multiple domains concurrently
func (e *Engine) ResolveBatch(ctx context.Context, domains []string, workers int) map[string][]string {
	results := make(map[string][]string)
	resultsMu := sync.Mutex{}
	
	domainChan := make(chan string, len(domains))
	for _, domain := range domains {
		domainChan <- domain
	}
	close(domainChan)
	
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for domain := range domainChan {
				select {
				case <-ctx.Done():
					return
				default:
					ips, err := e.Resolve(ctx, domain)
					if err == nil && len(ips) > 0 {
						resultsMu.Lock()
						results[domain] = ips
						resultsMu.Unlock()
					}
				}
			}
		}()
	}
	
	wg.Wait()
	return results
}

// getNextResolver returns the next resolver in round-robin fashion
func (e *Engine) getNextResolver() string {
	e.mu.Lock()
	defer e.mu.Unlock()
	
	resolver := e.resolvers[e.resolverIndex]
	e.resolverIndex = (e.resolverIndex + 1) % len(e.resolvers)
	
	return resolver
}

// IsWildcard checks if a domain has wildcard DNS
func (e *Engine) IsWildcard(ctx context.Context, domain string) (*types.WildcardInfo, error) {
	// Check cache first
	e.wildcardMu.RLock()
	cached, exists := e.wildcardCache[domain]
	e.wildcardMu.RUnlock()
	
	if exists {
		return cached, nil
	}
	
	// Perform wildcard detection
	info, err := e.detectWildcard(ctx, domain)
	if err != nil {
		return nil, err
	}
	
	// Cache result
	e.wildcardMu.Lock()
	e.wildcardCache[domain] = info
	e.wildcardMu.Unlock()
	
	return info, nil
}

// detectWildcard performs actual wildcard detection
func (e *Engine) detectWildcard(ctx context.Context, domain string) (*types.WildcardInfo, error) {
	info := &types.WildcardInfo{
		TestResults: make(map[string][]string),
		DetectedAt:  time.Now(),
	}
	
	// Generate random subdomains
	testSubdomains := e.generateRandomSubdomains(domain, e.config.WildcardTests)
	
	// Resolve all test subdomains
	resolvedCount := 0
	var patterns []string
	
	for _, testSub := range testSubdomains {
		ips, err := e.Resolve(ctx, testSub)
		if err == nil && len(ips) > 0 {
			info.TestResults[testSub] = ips
			resolvedCount++
			
			// Track IP patterns
			for _, ip := range ips {
				if !contains(patterns, ip) {
					patterns = append(patterns, ip)
				}
			}
		}
	}
	
	// If most random subdomains resolve, it's likely a wildcard
	if resolvedCount >= e.config.WildcardTests-1 {
		info.IsWildcard = true
		info.Patterns = patterns
		
		e.logger.Warn("Wildcard DNS detected",
			zap.String("domain", domain),
			zap.Int("test_count", e.config.WildcardTests),
			zap.Int("resolved_count", resolvedCount),
			zap.Strings("patterns", patterns),
		)
	}
	
	return info, nil
}

// generateRandomSubdomains creates random subdomains for wildcard testing
func (e *Engine) generateRandomSubdomains(domain string, count int) []string {
	subdomains := make([]string, count)
	
	for i := 0; i < count; i++ {
		random := fmt.Sprintf("wildcard-test-%d-%d", time.Now().UnixNano(), i)
		subdomains[i] = fmt.Sprintf("%s.%s", random, domain)
	}
	
	return subdomains
}

// FilterWildcards removes wildcard matches from results
func (e *Engine) FilterWildcards(ctx context.Context, domain string, subdomains []string) ([]string, error) {
	wildcardInfo, err := e.IsWildcard(ctx, domain)
	if err != nil {
		return subdomains, err
	}
	
	if !wildcardInfo.IsWildcard {
		return subdomains, nil
	}
	
	// Filter out subdomains that match wildcard patterns
	var filtered []string
	for _, sub := range subdomains {
		ips, err := e.Resolve(ctx, sub)
		if err != nil || len(ips) == 0 {
			continue
		}
		
		// Check if IPs match wildcard patterns
		isWildcardMatch := false
		for _, ip := range ips {
			if contains(wildcardInfo.Patterns, ip) {
				isWildcardMatch = true
				break
			}
		}
		
		if !isWildcardMatch {
			filtered = append(filtered, sub)
		}
	}
	
	e.logger.Info("Wildcard filtering complete",
		zap.String("domain", domain),
		zap.Int("original_count", len(subdomains)),
		zap.Int("filtered_count", len(filtered)),
	)
	
	return filtered, nil
}

func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}