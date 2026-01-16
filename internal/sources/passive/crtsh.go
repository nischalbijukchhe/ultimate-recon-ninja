package passive

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/yourusername/usr/internal/sources"
	"github.com/yourusername/usr/internal/types"
)

// CrtSh implements Certificate Transparency log enumeration via crt.sh
type CrtSh struct {
	enabled bool
	client  *http.Client
}

// crtshResponse represents the JSON response from crt.sh
type crtshResponse struct {
	NameValue string `json:"name_value"`
}

// NewCrtSh creates a new crt.sh source
func NewCrtSh(enabled bool) *CrtSh {
	return &CrtSh{
		enabled: enabled,
		client: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// Name returns the source identifier
func (c *CrtSh) Name() string {
	return "crtsh"
}

// Type returns the source category
func (c *CrtSh) Type() sources.SourceType {
	return sources.TypePassive
}

// IsEnabled checks if the source is enabled
func (c *CrtSh) IsEnabled() bool {
	return c.enabled
}

// RateLimit returns the rate limit (requests per second)
func (c *CrtSh) RateLimit() int {
	return 10 // Be respectful to crt.sh
}

// Enumerate performs subdomain discovery via Certificate Transparency
func (c *CrtSh) Enumerate(ctx context.Context, domain string) (*types.SourceResult, error) {
	startTime := time.Now()
	
	result := &types.SourceResult{
		Source:    c.Name(),
		Duration:  0,
	}
	
	// Query crt.sh API
	url := fmt.Sprintf("https://crt.sh/?q=%%25.%s&output=json", domain)
	
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		result.Error = err
		result.Duration = time.Since(startTime)
		return result, err
	}
	
	req.Header.Set("User-Agent", "USR/1.0 (Universal Subdomain Reconnaissance)")
	
	resp, err := c.client.Do(req)
	if err != nil {
		result.Error = err
		result.Duration = time.Since(startTime)
		return result, err
	}
	defer resp.Body.Close()
	
	if resp.StatusCode != http.StatusOK {
		err = fmt.Errorf("crt.sh returned status %d", resp.StatusCode)
		result.Error = err
		result.Duration = time.Since(startTime)
		return result, err
	}
	
	// Parse JSON response
	var entries []crtshResponse
	if err := json.NewDecoder(resp.Body).Decode(&entries); err != nil {
		result.Error = err
		result.Duration = time.Since(startTime)
		return result, err
	}
	
	// Extract unique subdomains
	subdomainMap := make(map[string]bool)
	
	for _, entry := range entries {
		// Handle multiple domains in name_value (newline separated)
		domains := strings.Split(entry.NameValue, "\n")
		for _, d := range domains {
			d = strings.TrimSpace(d)
			d = strings.ToLower(d)
			
			// Remove wildcard prefix
			d = strings.TrimPrefix(d, "*.")
			
			// Only include subdomains of the target domain
			if strings.HasSuffix(d, "."+domain) || d == domain {
				subdomainMap[d] = true
			}
		}
	}
	
	// Convert map to slice
	subdomains := make([]string, 0, len(subdomainMap))
	for subdomain := range subdomainMap {
		subdomains = append(subdomains, subdomain)
	}
	
	result.Subdomains = subdomains
	result.Duration = time.Since(startTime)
	
	return result, nil
}