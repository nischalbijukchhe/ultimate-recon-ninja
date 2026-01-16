package prompts

import (
	"fmt"
	"strings"
)

// PromptVersion defines the version of prompts being used
const PromptVersion = "v1"

// Template represents a prompt template
type Template struct {
	Version     string
	Name        string
	Description string
	Template    string
}

var templates = map[string]Template{
	"wordlist_generation": {
		Version:     PromptVersion,
		Name:        "wordlist_generation",
		Description: "Generate contextual subdomain wordlist",
		Template: `You are a subdomain enumeration expert. Generate a list of potential subdomains for the domain: {{.Domain}}

Context:
{{if .Industry}}- Industry: {{.Industry}}{{end}}
{{if .CompanyType}}- Company Type: {{.CompanyType}}{{end}}
{{if .KnownSubdomains}}- Known Subdomains: {{.KnownSubdomains}}{{end}}

Based on common naming patterns, generate 50 likely subdomain names. Consider:
- Environment indicators (dev, staging, prod, test, qa)
- Service types (api, mail, www, cdn, static)
- Geographic locations (us, eu, asia, uk)
- Technology stacks (jenkins, gitlab, jira, confluence)
- Department functions (hr, finance, sales, marketing)
- Infrastructure (vpn, proxy, gateway, firewall)

Output ONLY subdomain names, one per line, without the domain suffix.
Do not include explanations or numbering.`,
	},
	
	"pattern_inference": {
		Version:     PromptVersion,
		Name:        "pattern_inference",
		Description: "Infer subdomain naming patterns",
		Template: `Analyze these discovered subdomains and identify naming patterns:

{{.Subdomains}}

Identify:
1. Naming conventions (prefixes, suffixes, separators)
2. Numbering schemes
3. Service categories
4. Geographic patterns
5. Environment patterns

Generate 30 new subdomain names following these patterns.
Output ONLY subdomain names, one per line.`,
	},
	
	"mutation_suggestions": {
		Version:     PromptVersion,
		Name:        "mutation_suggestions",
		Description: "Suggest subdomain mutations",
		Template: `Given this subdomain: {{.Subdomain}}

Generate 20 variations using:
- Common typos and alternatives
- Hyphen/underscore variations
- Number additions (1, 2, 01, 02, etc)
- Environment prefixes/suffixes
- Regional variations

Output ONLY subdomain names, one per line.`,
	},
	
	"confidence_analysis": {
		Version:     PromptVersion,
		Name:        "confidence_analysis",
		Description: "Analyze subdomain confidence",
		Template: `Analyze this subdomain discovery:

Domain: {{.Subdomain}}
Sources: {{.Sources}}
DNS Validated: {{.DNSValidated}}
HTTP Response: {{.HTTPStatus}}

Rate the confidence (0-100) that this is a legitimate, active subdomain.
Consider source reliability, validation status, and naming patterns.

Output format:
SCORE: [number]
REASONING: [brief explanation]`,
	},
	
	"noise_detection": {
		Version:     PromptVersion,
		Name:        "noise_detection",
		Description: "Detect false positives and noise",
		Template: `Review these subdomains and identify likely false positives or noise:

{{.Subdomains}}

Look for:
- CDN artifacts
- Wildcard patterns
- Third-party services
- Malformed entries
- Obvious noise

Output suspicious entries, one per line, with reason:
FORMAT: subdomain | reason`,
	},
	
	"recursive_discovery": {
		Version:     PromptVersion,
		Name:        "recursive_discovery",
		Description: "Generate recursive discovery targets",
		Template: `Based on this discovered subdomain: {{.Subdomain}}

The subdomain suggests {{.InferredPurpose}}.

Generate 15 related subdomains that might exist in the same infrastructure.
Consider logical groupings, parallel services, and infrastructure patterns.

Output ONLY subdomain names, one per line.`,
	},
}

// Get retrieves a template by name
func Get(name string) (Template, error) {
	template, exists := templates[name]
	if !exists {
		return Template{}, fmt.Errorf("template %q not found", name)
	}
	return template, nil
}

// Render renders a template with provided variables
func Render(templateName string, vars map[string]interface{}) (string, error) {
	template, err := Get(templateName)
	if err != nil {
		return "", err
	}
	
	result := template.Template
	
	// Simple variable replacement
	for key, value := range vars {
		placeholder := fmt.Sprintf("{{.%s}}", key)
		
		var replacement string
		switch v := value.(type) {
		case string:
			replacement = v
		case []string:
			replacement = strings.Join(v, ", ")
		case bool:
			if v {
				replacement = "Yes"
			} else {
				replacement = "No"
			}
		case int:
			replacement = fmt.Sprintf("%d", v)
		default:
			replacement = fmt.Sprintf("%v", v)
		}
		
		result = strings.ReplaceAll(result, placeholder, replacement)
	}
	
	// Clean up unused placeholders
	result = cleanUnusedPlaceholders(result)
	
	return result, nil
}

// cleanUnusedPlaceholders removes conditional blocks with unused variables
func cleanUnusedPlaceholders(text string) string {
	lines := strings.Split(text, "\n")
	var cleaned []string
	
	for _, line := range lines {
		// Skip lines that still have unreplaced placeholders in conditionals
		if strings.Contains(line, "{{if") && strings.Contains(line, "}}") {
			continue
		}
		if strings.Contains(line, "{{end}}") {
			continue
		}
		
		cleaned = append(cleaned, line)
	}
	
	return strings.Join(cleaned, "\n")
}

// ListTemplates returns all available template names
func ListTemplates() []string {
	names := make([]string, 0, len(templates))
	for name := range templates {
		names = append(names, name)
	}
	return names
}