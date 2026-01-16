package sources

import (
	"context"

	"github.com/yourusername/usr/internal/types"
)

// Source represents any subdomain enumeration source
type Source interface {
	// Name returns the source identifier
	Name() string
	
	// Type returns the source category (passive, active, web, ai)
	Type() SourceType
	
	// Enumerate performs subdomain discovery
	Enumerate(ctx context.Context, domain string) (*types.SourceResult, error)
	
	// IsEnabled checks if source is configured and available
	IsEnabled() bool
	
	// RateLimit returns requests per second limit (0 = unlimited)
	RateLimit() int
}

// SourceType categorizes enumeration sources
type SourceType string

const (
	TypePassive SourceType = "passive"
	TypeActive  SourceType = "active"
	TypeWeb     SourceType = "web"
	TypeAI      SourceType = "ai"
)

// Registry manages all available sources
type Registry struct {
	sources map[string]Source
}

// NewRegistry creates a new source registry
func NewRegistry() *Registry {
	return &Registry{
		sources: make(map[string]Source),
	}
}

// Register adds a source to the registry
func (r *Registry) Register(source Source) {
	r.sources[source.Name()] = source
}

// Get retrieves a source by name
func (r *Registry) Get(name string) (Source, bool) {
	source, exists := r.sources[name]
	return source, exists
}

// GetByType returns all sources of a specific type
func (r *Registry) GetByType(sourceType SourceType) []Source {
	var result []Source
	for _, source := range r.sources {
		if source.Type() == sourceType && source.IsEnabled() {
			result = append(result, source)
		}
	}
	return result
}

// GetAll returns all enabled sources
func (r *Registry) GetAll() []Source {
	var result []Source
	for _, source := range r.sources {
		if source.IsEnabled() {
			result = append(result, source)
		}
	}
	return result
}

// Count returns the number of registered sources
func (r *Registry) Count() int {
	return len(r.sources)
}

// CountEnabled returns the number of enabled sources
func (r *Registry) CountEnabled() int {
	count := 0
	for _, source := range r.sources {
		if source.IsEnabled() {
			count++
		}
	}
	return count
}