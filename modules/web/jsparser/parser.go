package jsparser

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"

	"go.uber.org/zap"
)

// Parser extracts subdomains and endpoints from JavaScript files
type Parser struct {
	client *http.Client
	logger *zap.Logger
	
	// Regex patterns for extraction
	domainPattern   *regexp.Regexp
	urlPattern      *regexp.Regexp
	endpointPattern *regexp.Regexp
}

// NewParser creates a new JavaScript parser
func NewParser(logger *zap.Logger) *Parser {
	return &Parser{
		client: &http.Client{
			Timeout: 15 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					InsecureSkipVerify: true,
				},
			},
		},
		logger: logger,
		
		// Compile regex patterns
		domainPattern: regexp.MustCompile(
			`(?i)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}`,
		),
		urlPattern: regexp.MustCompile(
			`(?i)https?://[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*`,
		),
		endpointPattern: regexp.MustCompile(
			`(?i)['"\`](/[a-z0-9_/-]+)['"\`]`,
		),
	}
}

// ParseHTML extracts JavaScript URLs from HTML content
func (p *Parser) ParseHTML(ctx context.Context, url string) ([]string, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}
	
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; USR/1.0)")
	
	resp, err := p.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	
	bodyBytes, err := io.ReadAll(io.LimitReader(resp.Body, 2*1024*1024)) // 2MB limit
	if err != nil {
		return nil, err
	}
	
	body := string(bodyBytes)
	
	return p.extractJSURLs(body, url), nil
}

// extractJSURLs finds JavaScript file URLs in HTML
func (p *Parser) extractJSURLs(html, baseURL string) []string {
	var jsURLs []string
	seen := make(map[string]bool)
	
	// Find <script src="...">
	scriptRegex := regexp.MustCompile(`<script[^>]+src=["']([^"']+)["']`)
	matches := scriptRegex.FindAllStringSubmatch(html, -1)
	
	for _, match := range matches {
		if len(match) > 1 {
			jsURL := match[1]
			
			// Convert relative URLs to absolute
			if !strings.HasPrefix(jsURL, "http") {
				if strings.HasPrefix(jsURL, "//") {
					jsURL = "https:" + jsURL
				} else if strings.HasPrefix(jsURL, "/") {
					// Extract base domain from URL
					parts := strings.Split(baseURL, "/")
					if len(parts) >= 3 {
						jsURL = parts[0] + "//" + parts[2] + jsURL
					}
				}
			}
			
			// Filter out common CDNs and third-party scripts
			if !p.isThirdParty(jsURL) && !seen[jsURL] {
				jsURLs = append(jsURLs, jsURL)
				seen[jsURL] = true
			}
		}
	}
	
	return jsURLs
}

// ParseJS analyzes JavaScript content and extracts subdomains/endpoints
func (p *Parser) ParseJS(ctx context.Context, jsURL, targetDomain string) ([]string, []string, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", jsURL, nil)
	if err != nil {
		return nil, nil, err
	}
	
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; USR/1.0)")
	
	resp, err := p.client.Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()
	
	bodyBytes, err := io.ReadAll(io.LimitReader(resp.Body, 5*1024*1024)) // 5MB limit
	if err != nil {
		return nil, nil, err
	}
	
	content := string(bodyBytes)
	
	subdomains := p.extractSubdomains(content, targetDomain)
	endpoints := p.extractEndpoints(content)
	
	return subdomains, endpoints, nil
}

// extractSubdomains finds potential subdomains in JavaScript
func (p *Parser) extractSubdomains(content, targetDomain string) []string {
	var subdomains []string
	seen := make(map[string]bool)
	
	// Find all domain-like strings
	matches := p.domainPattern.FindAllString(content, -1)
	
	for _, match := range matches {
		match = strings.ToLower(strings.TrimSpace(match))
		
		// Only include subdomains of target domain
		if strings.HasSuffix(match, "."+targetDomain) || match == targetDomain {
			if !seen[match] && p.isValidDomain(match) {
				subdomains = append(subdomains, match)
				seen[match] = true
			}
		}
	}
	
	// Also look for URLs
	urlMatches := p.urlPattern.FindAllString(content, -1)
	for _, url := range urlMatches {
		domain := p.extractDomainFromURL(url)
		if domain != "" && !seen[domain] {
			if strings.HasSuffix(domain, "."+targetDomain) || domain == targetDomain {
				subdomains = append(subdomains, domain)
				seen[domain] = true
			}
		}
	}
	
	return subdomains
}

// extractEndpoints finds API endpoints in JavaScript
func (p *Parser) extractEndpoints(content string) []string {
	var endpoints []string
	seen := make(map[string]bool)
	
	matches := p.endpointPattern.FindAllStringSubmatch(content, -1)
	
	for _, match := range matches {
		if len(match) > 1 {
			endpoint := match[1]
			
			// Filter out non-API paths
			if p.looksLikeEndpoint(endpoint) && !seen[endpoint] {
				endpoints = append(endpoints, endpoint)
				seen[endpoint] = true
			}
		}
	}
	
	// Limit results
	if len(endpoints) > 100 {
		endpoints = endpoints[:100]
	}
	
	return endpoints
}

// extractDomainFromURL extracts domain from URL
func (p *Parser) extractDomainFromURL(url string) string {
	// Remove protocol
	url = strings.TrimPrefix(url, "https://")
	url = strings.TrimPrefix(url, "http://")
	
	// Get domain part (before first /)
	parts := strings.Split(url, "/")
	if len(parts) > 0 {
		return parts[0]
	}
	
	return ""
}

// isThirdParty checks if a JS URL is from a third-party CDN
func (p *Parser) isThirdParty(url string) bool {
	thirdPartyDomains := []string{
		"googleapis.com",
		"cloudflare.com",
		"jquery.com",
		"bootstrap",
		"cdnjs",
		"unpkg.com",
		"jsdelivr.net",
		"fontawesome",
		"google-analytics",
		"googletagmanager",
		"facebook.net",
		"twitter.com",
		"linkedin.com",
	}
	
	urlLower := strings.ToLower(url)
	for _, domain := range thirdPartyDomains {
		if strings.Contains(urlLower, domain) {
			return true
		}
	}
	
	return false
}

// isValidDomain performs basic domain validation
func (p *Parser) isValidDomain(domain string) bool {
	if len(domain) == 0 || len(domain) > 253 {
		return false
	}
	
	parts := strings.Split(domain, ".")
	if len(parts) < 2 {
		return false
	}
	
	for _, part := range parts {
		if len(part) == 0 || len(part) > 63 {
			return false
		}
	}
	
	return true
}

// looksLikeEndpoint determines if a path looks like an API endpoint
func (p *Parser) looksLikeEndpoint(path string) bool {
	// Must start with /
	if !strings.HasPrefix(path, "/") {
		return false
	}
	
	// Too short
	if len(path) < 3 {
		return false
	}
	
	// Common API patterns
	apiPatterns := []string{
		"/api/", "/v1/", "/v2/", "/v3/",
		"/rest/", "/graphql", "/endpoint",
		"/service/", "/data/",
	}
	
	pathLower := strings.ToLower(path)
	for _, pattern := range apiPatterns {
		if strings.Contains(pathLower, pattern) {
			return true
		}
	}
	
	// Looks like a file path
	if strings.Contains(path, ".html") || strings.Contains(path, ".css") ||
	   strings.Contains(path, ".jpg") || strings.Contains(path, ".png") {
		return false
	}
	
	// Has reasonable structure
	return strings.Count(path, "/") >= 2 && strings.Count(path, "/") <= 6
}

// AnalyzeDomain performs comprehensive JS analysis on a domain
func (p *Parser) AnalyzeDomain(ctx context.Context, domain string) ([]string, error) {
	p.logger.Info("Analyzing JavaScript for domain", zap.String("domain", domain))
	
	// Try common URLs
	urls := []string{
		fmt.Sprintf("https://%s", domain),
		fmt.Sprintf("http://%s", domain),
	}
	
	var allSubdomains []string
	seen := make(map[string]bool)
	
	for _, url := range urls {
		// Get JS files from HTML
		jsURLs, err := p.ParseHTML(ctx, url)
		if err != nil {
			p.logger.Debug("Failed to parse HTML",
				zap.String("url", url),
				zap.Error(err),
			)
			continue
		}
		
		// Analyze each JS file
		for _, jsURL := range jsURLs {
			subdomains, _, err := p.ParseJS(ctx, jsURL, domain)
			if err != nil {
				p.logger.Debug("Failed to parse JS",
					zap.String("url", jsURL),
					zap.Error(err),
				)
				continue
			}
			
			for _, sub := range subdomains {
				if !seen[sub] {
					allSubdomains = append(allSubdomains, sub)
					seen[sub] = true
				}
			}
		}
	}
	
	p.logger.Info("JS analysis complete",
		zap.String("domain", domain),
		zap.Int("subdomains_found", len(allSubdomains)),
	)
	
	return allSubdomains, nil
}