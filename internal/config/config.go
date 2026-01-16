package config

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/viper"
)

type Config struct {
	// Core settings
	LogLevel    string `mapstructure:"log_level"`
	LogFile     string `mapstructure:"log_file"`
	ScanMode    string `mapstructure:"scan_mode"`
	OutputDir   string `mapstructure:"output_dir"`
	
	// Concurrency
	MaxThreads      int `mapstructure:"max_threads"`
	DNSWorkers      int `mapstructure:"dns_workers"`
	HTTPWorkers     int `mapstructure:"http_workers"`
	
	// DNS Configuration
	DNS DNSConfig `mapstructure:"dns"`
	
	// AI Configuration
	AI AIConfig `mapstructure:"ai"`
	
	// Sources Configuration
	Sources SourcesConfig `mapstructure:"sources"`
	
	// Validation
	Validation ValidationConfig `mapstructure:"validation"`
	
	// Storage
	Storage StorageConfig `mapstructure:"storage"`
}

type DNSConfig struct {
	Resolvers       []string `mapstructure:"resolvers"`
	Timeout         int      `mapstructure:"timeout"`
	Retries         int      `mapstructure:"retries"`
	RateLimit       int      `mapstructure:"rate_limit"`
	WildcardTests   int      `mapstructure:"wildcard_tests"`
}

type AIConfig struct {
	Enabled       bool   `mapstructure:"enabled"`
	OllamaURL     string `mapstructure:"ollama_url"`
	Model         string `mapstructure:"model"`
	Temperature   float64 `mapstructure:"temperature"`
	MaxTokens     int    `mapstructure:"max_tokens"`
	PromptVersion string `mapstructure:"prompt_version"`
}

type SourcesConfig struct {
	Passive  PassiveSourcesConfig  `mapstructure:"passive"`
	Active   ActiveSourcesConfig   `mapstructure:"active"`
	Web      WebSourcesConfig      `mapstructure:"web"`
}

type PassiveSourcesConfig struct {
	CertificateTransparency bool     `mapstructure:"certificate_transparency"`
	VirusTotal              bool     `mapstructure:"virustotal"`
	PassiveDNS              bool     `mapstructure:"passive_dns"`
	WaybackMachine          bool     `mapstructure:"wayback_machine"`
	CommonCrawl             bool     `mapstructure:"common_crawl"`
	GitHub                  bool     `mapstructure:"github"`
	Shodan                  bool     `mapstructure:"shodan"`
	APIs                    []string `mapstructure:"apis"`
}

type ActiveSourcesConfig struct {
	DNSBruteforce bool     `mapstructure:"dns_bruteforce"`
	Recursive     bool     `mapstructure:"recursive"`
	Permutations  bool     `mapstructure:"permutations"`
	Wordlists     []string `mapstructure:"wordlists"`
}

type WebSourcesConfig struct {
	HTTPProbing   bool `mapstructure:"http_probing"`
	JSParsing     bool `mapstructure:"js_parsing"`
	CloudAssets   bool `mapstructure:"cloud_assets"`
	LinkCrawling  bool `mapstructure:"link_crawling"`
}

type ValidationConfig struct {
	DNSValidation  bool `mapstructure:"dns_validation"`
	HTTPValidation bool `mapstructure:"http_validation"`
	TLSValidation  bool `mapstructure:"tls_validation"`
	MinConfidence  int  `mapstructure:"min_confidence"`
}

type StorageConfig struct {
	Engine   string `mapstructure:"engine"` // sqlite, postgres, memory
	Path     string `mapstructure:"path"`
	CacheDir string `mapstructure:"cache_dir"`
}

// Load reads configuration from file or creates default config
func Load(configFile string) (*Config, error) {
	v := viper.New()
	
	// Set defaults
	setDefaults(v)
	
	// Determine config file location
	if configFile != "" {
		v.SetConfigFile(configFile)
	} else {
		home, err := os.UserHomeDir()
		if err != nil {
			return nil, fmt.Errorf("unable to find home directory: %w", err)
		}
		
		configPath := filepath.Join(home, ".usr")
		configFile = filepath.Join(configPath, "config.yaml")
		
		// Create config directory if it doesn't exist
		if err := os.MkdirAll(configPath, 0755); err != nil {
			return nil, fmt.Errorf("unable to create config directory: %w", err)
		}
		
		v.AddConfigPath(configPath)
		v.SetConfigName("config")
		v.SetConfigType("yaml")
	}
	
	// Read config file if it exists
	if err := v.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); ok {
			// Config file not found, create default
			if err := createDefaultConfig(configFile); err != nil {
				return nil, fmt.Errorf("unable to create default config: %w", err)
			}
			// Read the newly created config
			if err := v.ReadInConfig(); err != nil {
				return nil, fmt.Errorf("unable to read config: %w", err)
			}
		} else {
			return nil, fmt.Errorf("unable to read config: %w", err)
		}
	}
	
	// Unmarshal config
	var cfg Config
	if err := v.Unmarshal(&cfg); err != nil {
		return nil, fmt.Errorf("unable to decode config: %w", err)
	}
	
	return &cfg, nil
}

func setDefaults(v *viper.Viper) {
	// Core
	v.SetDefault("log_level", "info")
	v.SetDefault("log_file", "")
	v.SetDefault("scan_mode", "passive")
	v.SetDefault("output_dir", "./output")
	
	// Concurrency
	v.SetDefault("max_threads", 50)
	v.SetDefault("dns_workers", 100)
	v.SetDefault("http_workers", 50)
	
	// DNS
	v.SetDefault("dns.timeout", 5)
	v.SetDefault("dns.retries", 2)
	v.SetDefault("dns.rate_limit", 100)
	v.SetDefault("dns.wildcard_tests", 5)
	v.SetDefault("dns.resolvers", []string{
		"8.8.8.8",
		"8.8.4.4",
		"1.1.1.1",
		"1.0.0.1",
	})
	
	// AI
	v.SetDefault("ai.enabled", false)
	v.SetDefault("ai.ollama_url", "http://localhost:11434")
	v.SetDefault("ai.model", "mistral")
	v.SetDefault("ai.temperature", 0.7)
	v.SetDefault("ai.max_tokens", 1000)
	v.SetDefault("ai.prompt_version", "v1")
	
	// Passive Sources
	v.SetDefault("sources.passive.certificate_transparency", true)
	v.SetDefault("sources.passive.virustotal", true)
	v.SetDefault("sources.passive.passive_dns", true)
	v.SetDefault("sources.passive.wayback_machine", true)
	v.SetDefault("sources.passive.common_crawl", false)
	v.SetDefault("sources.passive.github", false)
	v.SetDefault("sources.passive.shodan", false)
	
	// Active Sources
	v.SetDefault("sources.active.dns_bruteforce", false)
	v.SetDefault("sources.active.recursive", false)
	v.SetDefault("sources.active.permutations", false)
	
	// Web Sources
	v.SetDefault("sources.web.http_probing", true)
	v.SetDefault("sources.web.js_parsing", false)
	v.SetDefault("sources.web.cloud_assets", true)
	v.SetDefault("sources.web.link_crawling", false)
	
	// Validation
	v.SetDefault("validation.dns_validation", true)
	v.SetDefault("validation.http_validation", true)
	v.SetDefault("validation.tls_validation", false)
	v.SetDefault("validation.min_confidence", 50)
	
	// Storage
	v.SetDefault("storage.engine", "sqlite")
	v.SetDefault("storage.path", "./data/usr.db")
	v.SetDefault("storage.cache_dir", "./cache")
}

func createDefaultConfig(path string) error {
	defaultConfig := `# USR Configuration File
# Universal Subdomain Reconnaissance Engine

# Core Settings
log_level: info
log_file: ""
scan_mode: passive
output_dir: ./output

# Concurrency
max_threads: 50
dns_workers: 100
http_workers: 50

# DNS Configuration
dns:
  resolvers:
    - 8.8.8.8
    - 8.8.4.4
    - 1.1.1.1
    - 1.0.0.1
  timeout: 5
  retries: 2
  rate_limit: 100
  wildcard_tests: 5

# AI Configuration (Local Ollama)
ai:
  enabled: false
  ollama_url: http://localhost:11434
  model: mistral
  temperature: 0.7
  max_tokens: 1000
  prompt_version: v1

# Sources Configuration
sources:
  passive:
    certificate_transparency: true
    virustotal: true
    passive_dns: true
    wayback_machine: true
    common_crawl: false
    github: false
    shodan: false
    apis: []
  
  active:
    dns_bruteforce: false
    recursive: false
    permutations: false
    wordlists:
      - ./assets/wordlists/subdomains-top1million-5000.txt
  
  web:
    http_probing: true
    js_parsing: false
    cloud_assets: true
    link_crawling: false

# Validation
validation:
  dns_validation: true
  http_validation: true
  tls_validation: false
  min_confidence: 50

# Storage
storage:
  engine: sqlite
  path: ./data/usr.db
  cache_dir: ./cache
`
	
	return os.WriteFile(path, []byte(defaultConfig), 0644)
}