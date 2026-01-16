package cloud

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	"go.uber.org/zap"
)

// Extractor identifies cloud storage buckets and services
type Extractor struct {
	logger *zap.Logger
	
	// Patterns for different cloud providers
	s3Pattern        *regexp.Regexp
	gcsPattern       *regexp.Regexp
	azurePattern     *regexp.Regexp
	firebasePattern  *regexp.Regexp
	digitalOceanPattern *regexp.Regexp
}

// CloudAsset represents a discovered cloud asset
type CloudAsset struct {
	Provider string
	Bucket   string
	Region   string
	URL      string
	Type     string // s3, gcs, azure-blob, firebase, etc.
}

// NewExtractor creates a new cloud asset extractor
func NewExtractor(logger *zap.Logger) *Extractor {
	return &Extractor{
		logger: logger,
		
		// AWS S3 patterns
		s3Pattern: regexp.MustCompile(
			`(?i)(?:https?://)?([a-z0-9][a-z0-9.-]*?)\.s3(?:[.-]([a-z0-9-]+))?\.amazonaws\.com|` +
			`(?i)(?:https?://)?s3(?:[.-]([a-z0-9-]+))?\.amazonaws\.com/([a-z0-9][a-z0-9.-]*?)`,
		),
		
		// Google Cloud Storage patterns
		gcsPattern: regexp.MustCompile(
			`(?i)(?:https?://)?([a-z0-9][a-z0-9._-]*?)\.storage\.googleapis\.com|` +
			`(?i)(?:https?://)?storage\.googleapis\.com/([a-z0-9][a-z0-9._-]*?)`,
		),
		
		// Azure Blob Storage patterns
		azurePattern: regexp.MustCompile(
			`(?i)(?:https?://)?([a-z0-9][a-z0-9-]*?)\.blob\.core\.windows\.net`,
		),
		
		// Firebase patterns
		firebasePattern: regexp.MustCompile(
			`(?i)(?:https?://)?([a-z0-9][a-z0-9-]*?)\.firebaseio\.com|` +
			`(?i)(?:https?://)?([a-z0-9][a-z0-9-]*?)\.firebaseapp\.com`,
		),
		
		// DigitalOcean Spaces patterns
		digitalOceanPattern: regexp.MustCompile(
			`(?i)(?:https?://)?([a-z0-9][a-z0-9.-]*?)\.([a-z0-9-]+)\.digitaloceanspaces\.com`,
		),
	}
}

// ExtractFromContent extracts cloud assets from text content
func (e *Extractor) ExtractFromContent(ctx context.Context, content, targetDomain string) []CloudAsset {
	var assets []CloudAsset
	seen := make(map[string]bool)
	
	// Extract S3 buckets
	s3Assets := e.extractS3(content, targetDomain)
	for _, asset := range s3Assets {
		key := fmt.Sprintf("%s:%s", asset.Type, asset.Bucket)
		if !seen[key] {
			assets = append(assets, asset)
			seen[key] = true
		}
	}
	
	// Extract GCS buckets
	gcsAssets := e.extractGCS(content, targetDomain)
	for _, asset := range gcsAssets {
		key := fmt.Sprintf("%s:%s", asset.Type, asset.Bucket)
		if !seen[key] {
			assets = append(assets, asset)
			seen[key] = true
		}
	}
	
	// Extract Azure blobs
	azureAssets := e.extractAzure(content, targetDomain)
	for _, asset := range azureAssets {
		key := fmt.Sprintf("%s:%s", asset.Type, asset.Bucket)
		if !seen[key] {
			assets = append(assets, asset)
			seen[key] = true
		}
	}
	
	// Extract Firebase
	firebaseAssets := e.extractFirebase(content, targetDomain)
	for _, asset := range firebaseAssets {
		key := fmt.Sprintf("%s:%s", asset.Type, asset.Bucket)
		if !seen[key] {
			assets = append(assets, asset)
			seen[key] = true
		}
	}
	
	// Extract DigitalOcean Spaces
	doAssets := e.extractDigitalOcean(content, targetDomain)
	for _, asset := range doAssets {
		key := fmt.Sprintf("%s:%s", asset.Type, asset.Bucket)
		if !seen[key] {
			assets = append(assets, asset)
			seen[key] = true
		}
	}
	
	e.logger.Info("Cloud asset extraction complete",
		zap.Int("assets_found", len(assets)),
	)
	
	return assets
}

// extractS3 extracts AWS S3 bucket references
func (e *Extractor) extractS3(content, targetDomain string) []CloudAsset {
	var assets []CloudAsset
	
	matches := e.s3Pattern.FindAllStringSubmatch(content, -1)
	
	for _, match := range matches {
		var bucket, region string
		
		// Parse different S3 URL formats
		if match[1] != "" {
			bucket = match[1]
			region = match[2]
		} else if match[4] != "" {
			bucket = match[4]
			region = match[3]
		}
		
		if bucket != "" && e.isRelevant(bucket, targetDomain) {
			asset := CloudAsset{
				Provider: "AWS",
				Bucket:   bucket,
				Region:   region,
				Type:     "s3",
			}
			
			if region != "" {
				asset.URL = fmt.Sprintf("https://%s.s3.%s.amazonaws.com", bucket, region)
			} else {
				asset.URL = fmt.Sprintf("https://%s.s3.amazonaws.com", bucket)
			}
			
			assets = append(assets, asset)
		}
	}
	
	return assets
}

// extractGCS extracts Google Cloud Storage buckets
func (e *Extractor) extractGCS(content, targetDomain string) []CloudAsset {
	var assets []CloudAsset
	
	matches := e.gcsPattern.FindAllStringSubmatch(content, -1)
	
	for _, match := range matches {
		bucket := ""
		if match[1] != "" {
			bucket = match[1]
		} else if match[2] != "" {
			bucket = match[2]
		}
		
		if bucket != "" && e.isRelevant(bucket, targetDomain) {
			asset := CloudAsset{
				Provider: "Google Cloud",
				Bucket:   bucket,
				Type:     "gcs",
				URL:      fmt.Sprintf("https://storage.googleapis.com/%s", bucket),
			}
			
			assets = append(assets, asset)
		}
	}
	
	return assets
}

// extractAzure extracts Azure Blob Storage containers
func (e *Extractor) extractAzure(content, targetDomain string) []CloudAsset {
	var assets []CloudAsset
	
	matches := e.azurePattern.FindAllStringSubmatch(content, -1)
	
	for _, match := range matches {
		if len(match) > 1 {
			account := match[1]
			
			if e.isRelevant(account, targetDomain) {
				asset := CloudAsset{
					Provider: "Azure",
					Bucket:   account,
					Type:     "azure-blob",
					URL:      fmt.Sprintf("https://%s.blob.core.windows.net", account),
				}
				
				assets = append(assets, asset)
			}
		}
	}
	
	return assets
}

// extractFirebase extracts Firebase project references
func (e *Extractor) extractFirebase(content, targetDomain string) []CloudAsset {
	var assets []CloudAsset
	
	matches := e.firebasePattern.FindAllStringSubmatch(content, -1)
	
	for _, match := range matches {
		project := ""
		urlType := ""
		
		if match[1] != "" {
			project = match[1]
			urlType = "firebaseio"
		} else if match[2] != "" {
			project = match[2]
			urlType = "firebaseapp"
		}
		
		if project != "" && e.isRelevant(project, targetDomain) {
			asset := CloudAsset{
				Provider: "Firebase",
				Bucket:   project,
				Type:     "firebase",
			}
			
			if urlType == "firebaseio" {
				asset.URL = fmt.Sprintf("https://%s.firebaseio.com", project)
			} else {
				asset.URL = fmt.Sprintf("https://%s.firebaseapp.com", project)
			}
			
			assets = append(assets, asset)
		}
	}
	
	return assets
}

// extractDigitalOcean extracts DigitalOcean Spaces
func (e *Extractor) extractDigitalOcean(content, targetDomain string) []CloudAsset {
	var assets []CloudAsset
	
	matches := e.digitalOceanPattern.FindAllStringSubmatch(content, -1)
	
	for _, match := range matches {
		if len(match) > 2 {
			bucket := match[1]
			region := match[2]
			
			if e.isRelevant(bucket, targetDomain) {
				asset := CloudAsset{
					Provider: "DigitalOcean",
					Bucket:   bucket,
					Region:   region,
					Type:     "do-spaces",
					URL:      fmt.Sprintf("https://%s.%s.digitaloceanspaces.com", bucket, region),
				}
				
				assets = append(assets, asset)
			}
		}
	}
	
	return assets
}

// isRelevant checks if a bucket name is relevant to the target domain
func (e *Extractor) isRelevant(bucket, targetDomain string) bool {
	if bucket == "" || targetDomain == "" {
		return false
	}
	
	bucketLower := strings.ToLower(bucket)
	domainLower := strings.ToLower(targetDomain)
	
	// Extract domain name without TLD
	domainParts := strings.Split(domainLower, ".")
	if len(domainParts) == 0 {
		return false
	}
	
	domainName := domainParts[0]
	
	// Check if bucket contains domain name
	if strings.Contains(bucketLower, domainName) {
		return true
	}
	
	// Check if bucket contains company name variations
	variations := []string{
		domainName,
		strings.ReplaceAll(domainName, "-", ""),
		strings.ReplaceAll(domainName, "-", "_"),
	}
	
	for _, variant := range variations {
		if strings.Contains(bucketLower, variant) {
			return true
		}
	}
	
	return false
}

// GeneratePermutations creates common bucket name permutations
func (e *Extractor) GeneratePermutations(domain string) []string {
	parts := strings.Split(domain, ".")
	if len(parts) == 0 {
		return nil
	}
	
	baseName := parts[0]
	var permutations []string
	
	// Common prefixes/suffixes
	prefixes := []string{"", "prod-", "dev-", "staging-", "test-", "backup-", "static-", "assets-"}
	suffixes := []string{"", "-prod", "-dev", "-staging", "-test", "-backup", "-static", "-assets", "-data", "-files"}
	
	for _, prefix := range prefixes {
		for _, suffix := range suffixes {
			permutations = append(permutations, prefix+baseName+suffix)
		}
	}
	
	// Without hyphens
	baseNameNoHyphen := strings.ReplaceAll(baseName, "-", "")
	for _, prefix := range prefixes {
		for _, suffix := range suffixes {
			if prefix != "" || suffix != "" {
				permutations = append(permutations, prefix+baseNameNoHyphen+suffix)
			}
		}
	}
	
	return permutations
}