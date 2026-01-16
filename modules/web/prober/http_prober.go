package prober

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/yourusername/usr/internal/types"
	"go.uber.org/zap"
)

// HTTPProber performs HTTP/HTTPS probing on subdomains
type HTTPProber struct {
	client     *http.Client
	logger     *zap.Logger
	maxWorkers int
}

// NewHTTPProber creates a new HTTP prober
func NewHTTPProber(logger *zap.Logger, maxWorkers int) *HTTPProber {
	return &HTTPProber{
		client: &http.Client{
			Timeout: 10 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					InsecureSkipVerify: true, // For reconnaissance purposes
				},
				MaxIdleConns:        100,
				MaxIdleConnsPerHost: 10,
				IdleConnTimeout:     30 * time.Second,
			},
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				// Allow up to 3 redirects
				if len(via) >= 3 {
					return http.ErrUseLastResponse
				}
				return nil
			},
		},
		logger:     logger,
		maxWorkers: maxWorkers,
	}
}

// Probe performs HTTP/HTTPS probing on a single subdomain
func (p *HTTPProber) Probe(ctx context.Context, subdomain string) *types.HTTPInfo {
	// Try HTTPS first, then HTTP
	if info := p.probeScheme(ctx, "https", subdomain); info != nil {
		return info
	}
	
	return p.probeScheme(ctx, "http", subdomain)
}

// probeScheme probes a specific scheme (http or https)
func (p *HTTPProber) probeScheme(ctx context.Context, scheme, subdomain string) *types.HTTPInfo {
	url := fmt.Sprintf("%s://%s", scheme, subdomain)
	
	startTime := time.Now()
	
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil
	}
	
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; USR/1.0; +https://github.com/usr)")
	
	resp, err := p.client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	
	responseTime := time.Since(startTime)
	
	// Read body (limit to 1MB)
	bodyBytes, err := io.ReadAll(io.LimitReader(resp.Body, 1024*1024))
	if err != nil {
		p.logger.Debug("Failed to read response body",
			zap.String("url", url),
			zap.Error(err),
		)
		bodyBytes = []byte{}
	}
	
	body := string(bodyBytes)
	
	info := &types.HTTPInfo{
		StatusCode:   resp.StatusCode,
		ResponseTime: responseTime,
		Headers:      make(map[string]string),
	}
	
	// Extract key headers
	info.Server = resp.Header.Get("Server")
	info.ContentType = resp.Header.Get("Content-Type")
	
	// Store important headers
	importantHeaders := []string{
		"Server", "X-Powered-By", "X-AspNet-Version",
		"X-Generator", "X-Drupal-Cache", "X-Frame-Options",
	}
	
	for _, header := range importantHeaders {
		if value := resp.Header.Get(header); value != "" {
			info.Headers[header] = value
		}
	}
	
	// Extract title
	info.Title = extractTitle(body)
	
	// Detect technologies
	info.Technologies = detectTechnologies(body, resp.Header)
	
	return info
}

// ProbeBatch probes multiple subdomains concurrently
func (p *HTTPProber) ProbeBatch(ctx context.Context, subdomains []*types.Subdomain) {
	if len(subdomains) == 0 {
		return
	}
	
	p.logger.Info("Starting HTTP probing",
		zap.Int("count", len(subdomains)),
		zap.Int("workers", p.maxWorkers),
	)
	
	workChan := make(chan *types.Subdomain, len(subdomains))
	for _, sub := range subdomains {
		workChan <- sub
	}
	close(workChan)
	
	var wg sync.WaitGroup
	for i := 0; i < p.maxWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for sub := range workChan {
				select {
				case <-ctx.Done():
					return
				default:
					if sub.Validated && len(sub.IP) > 0 {
						info := p.Probe(ctx, sub.Domain)
						if info != nil {
							sub.HTTP = info
						}
					}
				}
			}
		}()
	}
	
	wg.Wait()
	
	p.logger.Info("HTTP probing complete")
}

// extractTitle extracts the <title> tag from HTML
func extractTitle(html string) string {
	// Simple title extraction
	start := strings.Index(strings.ToLower(html), "<title>")
	if start == -1 {
		return ""
	}
	
	start += 7 // len("<title>")
	end := strings.Index(strings.ToLower(html[start:]), "</title>")
	if end == -1 {
		return ""
	}
	
	title := html[start : start+end]
	title = strings.TrimSpace(title)
	
	// Limit title length
	if len(title) > 100 {
		title = title[:100] + "..."
	}
	
	return title
}

// detectTechnologies identifies technologies used by the web application
func detectTechnologies(body string, headers http.Header) []string {
	var technologies []string
	seen := make(map[string]bool)
	
	bodyLower := strings.ToLower(body)
	
	// Check headers
	if server := headers.Get("Server"); server != "" {
		if strings.Contains(server, "nginx") {
			technologies = addUnique(technologies, seen, "nginx")
		}
		if strings.Contains(server, "Apache") {
			technologies = addUnique(technologies, seen, "Apache")
		}
		if strings.Contains(server, "IIS") {
			technologies = addUnique(technologies, seen, "IIS")
		}
	}
	
	if poweredBy := headers.Get("X-Powered-By"); poweredBy != "" {
		if strings.Contains(poweredBy, "PHP") {
			technologies = addUnique(technologies, seen, "PHP")
		}
		if strings.Contains(poweredBy, "ASP.NET") {
			technologies = addUnique(technologies, seen, "ASP.NET")
		}
	}
	
	// Check body for common frameworks
	frameworks := map[string]string{
		"wp-content":         "WordPress",
		"wp-includes":        "WordPress",
		"joomla":             "Joomla",
		"drupal":             "Drupal",
		"__next":             "Next.js",
		"_next":              "Next.js",
		"nuxt":               "Nuxt.js",
		"react":              "React",
		"angular":            "Angular",
		"vue.js":             "Vue.js",
		"jquery":             "jQuery",
		"bootstrap":          "Bootstrap",
		"tailwind":           "Tailwind CSS",
		"django":             "Django",
		"laravel":            "Laravel",
		"symfony":            "Symfony",
		"spring":             "Spring",
		"express":            "Express",
		"flask":              "Flask",
		"rails":              "Ruby on Rails",
		"gatsby":             "Gatsby",
		"shopify":            "Shopify",
		"magento":            "Magento",
		"wix":                "Wix",
		"squarespace":        "Squarespace",
		"cloudflare":         "Cloudflare",
	}
	
	for signature, tech := range frameworks {
		if strings.Contains(bodyLower, signature) {
			technologies = addUnique(technologies, seen, tech)
		}
	}
	
	return technologies
}

// addUnique adds a technology if not already present
func addUnique(slice []string, seen map[string]bool, tech string) []string {
	if !seen[tech] {
		slice = append(slice, tech)
		seen[tech] = true
	}
	return slice
}