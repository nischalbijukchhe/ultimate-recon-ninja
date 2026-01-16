package orchestrator

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/yourusername/usr/internal/config"
	"github.com/yourusername/usr/internal/dns"
	"github.com/yourusername/usr/internal/sources"
	"github.com/yourusername/usr/internal/types"
	"go.uber.org/zap"
)

// Orchestrator manages the entire reconnaissance workflow
type Orchestrator struct {
	config   *config.Config
	logger   *zap.Logger
	
	dnsEngine *dns.Engine
	registry  *sources.Registry
	
	// Results management
	results      map[string]*types.Subdomain
	resultsMu    sync.RWMutex
	
	// Statistics
	stats        *Statistics
	statsMu      sync.Mutex
}

// Statistics tracks scan progress and metrics
type Statistics struct {
	StartTime       time.Time
	EndTime         time.Time
	TotalSources    int
	CompletedSources int
	TotalSubdomains int
	ValidatedSubdomains int
	FailedValidations int
	Errors          []error
}

// NewOrchestrator creates a new orchestrator instance
func NewOrchestrator(cfg *config.Config, logger *zap.Logger) *Orchestrator {
	return &Orchestrator{
		config:    cfg,
		logger:    logger,
		dnsEngine: dns.NewEngine(&cfg.DNS, logger),
		registry:  sources.NewRegistry(),
		results:   make(map[string]*types.Subdomain),
		stats: &Statistics{
			StartTime: time.Now(),
		},
	}
}

// RegisterSource adds a source to the orchestrator
func (o *Orchestrator) RegisterSource(source sources.Source) {
	o.registry.Register(source)
	o.logger.Debug("Source registered",
		zap.String("name", source.Name()),
		zap.String("type", string(source.Type())),
	)
}

// Run executes the complete reconnaissance workflow
func (o *Orchestrator) Run(ctx context.Context, domain string) ([]*types.Subdomain, error) {
	o.logger.Info("Starting orchestrated reconnaissance",
		zap.String("domain", domain),
		zap.String("mode", o.config.ScanMode),
	)
	
	// Phase 1: Wildcard Detection
	o.logger.Info("Phase 1: Wildcard detection")
	wildcardInfo, err := o.dnsEngine.IsWildcard(ctx, domain)
	if err != nil {
		o.logger.Warn("Wildcard detection failed", zap.Error(err))
	} else if wildcardInfo.IsWildcard {
		o.logger.Warn("Wildcard DNS detected - filtering will be applied",
			zap.Strings("patterns", wildcardInfo.Patterns),
		)
	}
	
	// Phase 2: Source Enumeration
	o.logger.Info("Phase 2: Source enumeration")
	if err := o.runSources(ctx, domain); err != nil {
		return nil, fmt.Errorf("source enumeration failed: %w", err)
	}
	
	// Phase 3: DNS Validation
	if o.config.Validation.DNSValidation {
		o.logger.Info("Phase 3: DNS validation")
		if err := o.validateDNS(ctx); err != nil {
			o.logger.Error("DNS validation failed", zap.Error(err))
		}
	}
	
	// Phase 4: Wildcard Filtering
	if wildcardInfo != nil && wildcardInfo.IsWildcard {
		o.logger.Info("Phase 4: Wildcard filtering")
		o.filterWildcardResults(ctx, domain, wildcardInfo)
	}
	
	// Phase 5: Confidence Scoring
	o.logger.Info("Phase 5: Confidence scoring")
	o.calculateConfidence()
	
	// Compile final results
	results := o.getFinalResults()
	
	o.stats.EndTime = time.Now()
	o.logStatistics()
	
	return results, nil
}

// runSources executes all enabled sources
func (o *Orchestrator) runSources(ctx context.Context, domain string) error {
	enabledSources := o.registry.GetAll()
	o.stats.TotalSources = len(enabledSources)
	
	if len(enabledSources) == 0 {
		return fmt.Errorf("no enabled sources found")
	}
	
	o.logger.Info("Running enumeration sources",
		zap.Int("source_count", len(enabledSources)),
	)
	
	var wg sync.WaitGroup
	resultsChan := make(chan *types.SourceResult, len(enabledSources))
	
	// Launch sources concurrently
	for _, source := range enabledSources {
		wg.Add(1)
		go func(src sources.Source) {
			defer wg.Done()
			
			o.logger.Debug("Starting source",
				zap.String("source", src.Name()),
				zap.String("type", string(src.Type())),
			)
			
			result, err := src.Enumerate(ctx, domain)
			if err != nil {
				o.logger.Error("Source enumeration failed",
					zap.String("source", src.Name()),
					zap.Error(err),
				)
				o.addError(err)
				return
			}
			
			resultsChan <- result
			
			o.statsMu.Lock()
			o.stats.CompletedSources++
			o.statsMu.Unlock()
			
			o.logger.Info("Source completed",
				zap.String("source", src.Name()),
				zap.Int("subdomains_found", len(result.Subdomains)),
				zap.Duration("duration", result.Duration),
			)
		}(source)
	}
	
	// Wait for all sources to complete
	go func() {
		wg.Wait()
		close(resultsChan)
	}()
	
	// Process results as they arrive
	for result := range resultsChan {
		o.processSourceResult(result)
	}
	
	return nil
}

// processSourceResult processes results from a single source
func (o *Orchestrator) processSourceResult(result *types.SourceResult) {
	o.resultsMu.Lock()
	defer o.resultsMu.Unlock()
	
	for _, subdomain := range result.Subdomains {
		if existing, exists := o.results[subdomain]; exists {
			// Update existing subdomain
			existing.Sources = append(existing.Sources, result.Source)
			existing.LastSeen = time.Now()
		} else {
			// Create new subdomain entry
			o.results[subdomain] = &types.Subdomain{
				Domain:    subdomain,
				Sources:   []string{result.Source},
				FirstSeen: time.Now(),
				LastSeen:  time.Now(),
				Validated: false,
				Metadata:  make(map[string]interface{}),
			}
		}
	}
	
	o.statsMu.Lock()
	o.stats.TotalSubdomains = len(o.results)
	o.statsMu.Unlock()
}

// validateDNS validates all discovered subdomains via DNS
func (o *Orchestrator) validateDNS(ctx context.Context) error {
	o.resultsMu.RLock()
	domains := make([]string, 0, len(o.results))
	for domain := range o.results {
		domains = append(domains, domain)
	}
	o.resultsMu.RUnlock()
	
	o.logger.Info("Validating subdomains via DNS",
		zap.Int("count", len(domains)),
	)
	
	// Batch resolution
	resolved := o.dnsEngine.ResolveBatch(ctx, domains, o.config.DNSWorkers)
	
	// Update results
	o.resultsMu.Lock()
	defer o.resultsMu.Unlock()
	
	for domain, ips := range resolved {
		if sub, exists := o.results[domain]; exists {
			sub.Validated = true
			sub.IP = ips
			
			// Create DNS records
			sub.DNSRecords = &types.DNSRecords{
				A: ips,
			}
			
			o.statsMu.Lock()
			o.stats.ValidatedSubdomains++
			o.statsMu.Unlock()
		}
	}
	
	// Mark unresolved as failed
	for domain, sub := range o.results {
		if !sub.Validated {
			o.statsMu.Lock()
			o.stats.FailedValidations++
			o.statsMu.Unlock()
		}
	}
	
	return nil
}

// filterWildcardResults removes wildcard matches
func (o *Orchestrator) filterWildcardResults(ctx context.Context, domain string, wildcardInfo *types.WildcardInfo) {
	o.resultsMu.Lock()
	defer o.resultsMu.Unlock()
	
	filtered := make(map[string]*types.Subdomain)
	
	for subdomain, sub := range o.results {
		if !sub.Validated {
			filtered[subdomain] = sub
			continue
		}
		
		// Check if IPs match wildcard patterns
		isWildcard := false
		for _, ip := range sub.IP {
			for _, pattern := range wildcardInfo.Patterns {
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
			filtered[subdomain] = sub
		}
	}
	
	removed := len(o.results) - len(filtered)
	o.results = filtered
	
	o.logger.Info("Wildcard filtering complete",
		zap.Int("removed", removed),
		zap.Int("remaining", len(filtered)),
	)
}

// calculateConfidence assigns confidence scores based on multiple factors
func (o *Orchestrator) calculateConfidence() {
	o.resultsMu.Lock()
	defer o.resultsMu.Unlock()
	
	for _, sub := range o.results {
		score := 0
		
		// Multiple sources increase confidence
		score += len(sub.Sources) * 10
		
		// DNS validation adds confidence
		if sub.Validated {
			score += 30
		}
		
		// HTTP validation adds more confidence
		if sub.HTTP != nil {
			score += 20
		}
		
		// TLS validation adds confidence
		if sub.TLS != nil && sub.TLS.Valid {
			score += 10
		}
		
		// Cap at 100
		if score > 100 {
			score = 100
		}
		
		sub.Confidence = score
	}
}

// getFinalResults returns filtered results based on configuration
func (o *Orchestrator) getFinalResults() []*types.Subdomain {
	o.resultsMu.RLock()
	defer o.resultsMu.RUnlock()
	
	var results []*types.Subdomain
	
	for _, sub := range o.results {
		// Apply confidence threshold
		if sub.Confidence >= o.config.Validation.MinConfidence {
			results = append(results, sub)
		}
	}
	
	return results
}

// addError adds an error to statistics
func (o *Orchestrator) addError(err error) {
	o.statsMu.Lock()
	defer o.statsMu.Unlock()
	o.stats.Errors = append(o.stats.Errors, err)
}

// logStatistics logs final scan statistics
func (o *Orchestrator) logStatistics() {
	duration := o.stats.EndTime.Sub(o.stats.StartTime)
	
	o.logger.Info("Reconnaissance complete",
		zap.Duration("duration", duration),
		zap.Int("sources_total", o.stats.TotalSources),
		zap.Int("sources_completed", o.stats.CompletedSources),
		zap.Int("subdomains_total", o.stats.TotalSubdomains),
		zap.Int("subdomains_validated", o.stats.ValidatedSubdomains),
		zap.Int("validation_failures", o.stats.FailedValidations),
		zap.Int("errors", len(o.stats.Errors)),
	)
}

// GetStatistics returns current statistics
func (o *Orchestrator) GetStatistics() Statistics {
	o.statsMu.Lock()
	defer o.statsMu.Unlock()
	return *o.stats
}