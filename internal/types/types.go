package types

import (
	"time"
)

// Subdomain represents a discovered subdomain with all metadata
type Subdomain struct {
	Domain      string                 `json:"domain"`
	IP          []string               `json:"ip,omitempty"`
	Sources     []string               `json:"sources"`
	Confidence  int                    `json:"confidence"`
	Validated   bool                   `json:"validated"`
	FirstSeen   time.Time              `json:"first_seen"`
	LastSeen    time.Time              `json:"last_seen"`
	HTTP        *HTTPInfo              `json:"http,omitempty"`
	TLS         *TLSInfo               `json:"tls,omitempty"`
	DNSRecords  *DNSRecords            `json:"dns_records,omitempty"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
}

// HTTPInfo contains HTTP probe results
type HTTPInfo struct {
	StatusCode   int               `json:"status_code"`
	Title        string            `json:"title,omitempty"`
	Server       string            `json:"server,omitempty"`
	ContentType  string            `json:"content_type,omitempty"`
	ResponseTime time.Duration     `json:"response_time"`
	Headers      map[string]string `json:"headers,omitempty"`
	Technologies []string          `json:"technologies,omitempty"`
}

// TLSInfo contains TLS certificate information
type TLSInfo struct {
	Valid       bool      `json:"valid"`
	Subject     string    `json:"subject"`
	Issuer      string    `json:"issuer"`
	NotBefore   time.Time `json:"not_before"`
	NotAfter    time.Time `json:"not_after"`
	SANs        []string  `json:"sans,omitempty"`
	Organization string   `json:"organization,omitempty"`
}

// DNSRecords contains various DNS record types
type DNSRecords struct {
	A     []string `json:"a,omitempty"`
	AAAA  []string `json:"aaaa,omitempty"`
	CNAME []string `json:"cname,omitempty"`
	MX    []string `json:"mx,omitempty"`
	NS    []string `json:"ns,omitempty"`
	TXT   []string `json:"txt,omitempty"`
}

// SourceResult represents raw output from a single source
type SourceResult struct {
	Source    string
	Subdomains []string
	Error     error
	Duration  time.Duration
}

// ScanContext contains all information needed for a scan
type ScanContext struct {
	Domain      string
	Mode        ScanMode
	Config      interface{} // Will be *config.Config
	ResultsChan chan *Subdomain
	ErrorsChan  chan error
}

// ScanMode defines the type of scan
type ScanMode string

const (
	ModePassive    ScanMode = "passive"
	ModeActive     ScanMode = "active"
	ModeAggressive ScanMode = "aggressive"
	ModeStealth    ScanMode = "stealth"
)

// WildcardInfo contains wildcard detection information
type WildcardInfo struct {
	IsWildcard    bool
	Patterns      []string
	TestResults   map[string][]string // test subdomain -> IPs
	DetectedAt    time.Time
}