package output

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"html/template"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/yourusername/usr/internal/types"
	"go.uber.org/zap"
)

// Exporter handles output formatting and export
type Exporter struct {
	logger *zap.Logger
}

// NewExporter creates a new exporter
func NewExporter(logger *zap.Logger) *Exporter {
	return &Exporter{
		logger: logger,
	}
}

// Export exports subdomains in the specified format
func (e *Exporter) Export(ctx context.Context, subdomains []*types.Subdomain, format, outputPath string) error {
	e.logger.Info("Exporting results",
		zap.String("format", format),
		zap.String("path", outputPath),
		zap.Int("count", len(subdomains)),
	)
	
	switch strings.ToLower(format) {
	case "json":
		return e.ExportJSON(ctx, subdomains, outputPath)
	case "csv":
		return e.ExportCSV(ctx, subdomains, outputPath)
	case "txt", "text":
		return e.ExportText(ctx, subdomains, outputPath)
	case "html":
		return e.ExportHTML(ctx, subdomains, outputPath)
	case "nuclei":
		return e.ExportNuclei(ctx, subdomains, outputPath)
	case "burp":
		return e.ExportBurp(ctx, subdomains, outputPath)
	default:
		return fmt.Errorf("unsupported format: %s", format)
	}
}

// ExportJSON exports subdomains as JSON
func (e *Exporter) ExportJSON(ctx context.Context, subdomains []*types.Subdomain, outputPath string) error {
	file, err := os.Create(outputPath)
	if err != nil {
		return fmt.Errorf("failed to create file: %w", err)
	}
	defer file.Close()
	
	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	
	output := map[string]interface{}{
		"generated_at": time.Now().Format(time.RFC3339),
		"total_count":  len(subdomains),
		"subdomains":   subdomains,
	}
	
	if err := encoder.Encode(output); err != nil {
		return fmt.Errorf("failed to encode JSON: %w", err)
	}
	
	e.logger.Info("JSON export complete", zap.String("path", outputPath))
	return nil
}

// ExportCSV exports subdomains as CSV
func (e *Exporter) ExportCSV(ctx context.Context, subdomains []*types.Subdomain, outputPath string) error {
	file, err := os.Create(outputPath)
	if err != nil {
		return fmt.Errorf("failed to create file: %w", err)
	}
	defer file.Close()
	
	writer := csv.NewWriter(file)
	defer writer.Flush()
	
	// Write header
	header := []string{
		"Domain", "IP", "Confidence", "Validated", "Sources",
		"HTTP_Status", "HTTP_Title", "Technologies", "First_Seen", "Last_Seen",
	}
	if err := writer.Write(header); err != nil {
		return fmt.Errorf("failed to write header: %w", err)
	}
	
	// Write data
	for _, sub := range subdomains {
		record := []string{
			sub.Domain,
			strings.Join(sub.IP, ";"),
			fmt.Sprintf("%d", sub.Confidence),
			fmt.Sprintf("%v", sub.Validated),
			strings.Join(sub.Sources, ";"),
		}
		
		// HTTP info
		if sub.HTTP != nil {
			record = append(record,
				fmt.Sprintf("%d", sub.HTTP.StatusCode),
				sub.HTTP.Title,
				strings.Join(sub.HTTP.Technologies, ";"),
			)
		} else {
			record = append(record, "", "", "")
		}
		
		// Timestamps
		record = append(record,
			sub.FirstSeen.Format(time.RFC3339),
			sub.LastSeen.Format(time.RFC3339),
		)
		
		if err := writer.Write(record); err != nil {
			return fmt.Errorf("failed to write record: %w", err)
		}
	}
	
	e.logger.Info("CSV export complete", zap.String("path", outputPath))
	return nil
}

// ExportText exports subdomains as plain text (one per line)
func (e *Exporter) ExportText(ctx context.Context, subdomains []*types.Subdomain, outputPath string) error {
	file, err := os.Create(outputPath)
	if err != nil {
		return fmt.Errorf("failed to create file: %w", err)
	}
	defer file.Close()
	
	for _, sub := range subdomains {
		if _, err := fmt.Fprintln(file, sub.Domain); err != nil {
			return fmt.Errorf("failed to write line: %w", err)
		}
	}
	
	e.logger.Info("Text export complete", zap.String("path", outputPath))
	return nil
}

// ExportHTML exports subdomains as an interactive HTML report
func (e *Exporter) ExportHTML(ctx context.Context, subdomains []*types.Subdomain, outputPath string) error {
	tmpl := `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>USR Reconnaissance Report</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; background: #0a0e27; color: #e0e0e0; padding: 20px; }
        .container { max-width: 1400px; margin: 0 auto; }
        h1 { color: #00ff88; margin-bottom: 10px; font-size: 2.5em; }
        .stats { background: #151932; border-radius: 8px; padding: 20px; margin: 20px 0; display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; }
        .stat { text-align: center; }
        .stat-value { font-size: 2em; color: #00ff88; font-weight: bold; }
        .stat-label { color: #888; margin-top: 5px; }
        table { width: 100%; border-collapse: collapse; margin-top: 20px; background: #151932; border-radius: 8px; overflow: hidden; }
        th { background: #1a1f3a; padding: 15px; text-align: left; color: #00ff88; font-weight: 600; }
        td { padding: 12px 15px; border-top: 1px solid #1a1f3a; }
        tr:hover { background: #1a1f3a; }
        .confidence { display: inline-block; padding: 4px 12px; border-radius: 12px; font-size: 0.85em; font-weight: 600; }
        .confidence-high { background: #00ff8844; color: #00ff88; }
        .confidence-medium { background: #ffaa0044; color: #ffaa00; }
        .confidence-low { background: #ff444444; color: #ff4444; }
        .badge { display: inline-block; padding: 3px 8px; background: #2a2f4a; border-radius: 4px; font-size: 0.8em; margin: 2px; }
        .http-ok { color: #00ff88; }
        .http-error { color: #ff4444; }
        .filter { margin: 20px 0; padding: 15px; background: #151932; border-radius: 8px; }
        .filter input { background: #0a0e27; border: 1px solid #2a2f4a; color: #e0e0e0; padding: 10px; border-radius: 4px; width: 300px; font-size: 1em; }
        .filter input:focus { outline: none; border-color: #00ff88; }
    </style>
</head>
<body>
    <div class="container">
        <h1>🔍 USR Reconnaissance Report</h1>
        <p style="color: #888; margin-bottom: 30px;">Generated: {{.GeneratedAt}}</p>
        
        <div class="stats">
            <div class="stat">
                <div class="stat-value">{{.TotalCount}}</div>
                <div class="stat-label">Total Subdomains</div>
            </div>
            <div class="stat">
                <div class="stat-value">{{.ValidatedCount}}</div>
                <div class="stat-label">Validated</div>
            </div>
            <div class="stat">
                <div class="stat-value">{{.HTTPActiveCount}}</div>
                <div class="stat-label">HTTP Active</div>
            </div>
        </div>
        
        <div class="filter">
            <input type="text" id="searchInput" placeholder="Filter subdomains..." onkeyup="filterTable()">
        </div>
        
        <table id="subdomainTable">
            <thead>
                <tr>
                    <th>Domain</th>
                    <th>IP</th>
                    <th>Confidence</th>
                    <th>HTTP</th>
                    <th>Technologies</th>
                    <th>Sources</th>
                </tr>
            </thead>
            <tbody>
            {{range .Subdomains}}
                <tr>
                    <td><strong>{{.Domain}}</strong></td>
                    <td>{{range .IP}}<div class="badge">{{.}}</div>{{end}}</td>
                    <td><span class="confidence {{if ge .Confidence 70}}confidence-high{{else if ge .Confidence 40}}confidence-medium{{else}}confidence-low{{end}}">{{.Confidence}}</span></td>
                    <td>{{if .HTTP}}<span class="{{if and (ge .HTTP.StatusCode 200) (lt .HTTP.StatusCode 400)}}http-ok{{else}}http-error{{end}}">{{.HTTP.StatusCode}}</span>{{end}}</td>
                    <td>{{if .HTTP}}{{range .HTTP.Technologies}}<div class="badge">{{.}}</div>{{end}}{{end}}</td>
                    <td>{{range .Sources}}<div class="badge">{{.}}</div>{{end}}</td>
                </tr>
            {{end}}
            </tbody>
        </table>
    </div>
    
    <script>
        function filterTable() {
            const input = document.getElementById('searchInput');
            const filter = input.value.toUpperCase();
            const table = document.getElementById('subdomainTable');
            const tr = table.getElementsByTagName('tr');
            
            for (let i = 1; i < tr.length; i++) {
                const td = tr[i].getElementsByTagName('td')[0];
                if (td) {
                    const txtValue = td.textContent || td.innerText;
                    tr[i].style.display = txtValue.toUpperCase().indexOf(filter) > -1 ? '' : 'none';
                }
            }
        }
    </script>
</body>
</html>`
	
	file, err := os.Create(outputPath)
	if err != nil {
		return fmt.Errorf("failed to create file: %w", err)
	}
	defer file.Close()
	
	t, err := template.New("report").Parse(tmpl)
	if err != nil {
		return fmt.Errorf("failed to parse template: %w", err)
	}
	
	validatedCount := 0
	httpActiveCount := 0
	for _, sub := range subdomains {
		if sub.Validated {
			validatedCount++
		}
		if sub.HTTP != nil && sub.HTTP.StatusCode >= 200 && sub.HTTP.StatusCode < 500 {
			httpActiveCount++
		}
	}
	
	data := map[string]interface{}{
		"GeneratedAt":     time.Now().Format("2006-01-02 15:04:05 MST"),
		"TotalCount":      len(subdomains),
		"ValidatedCount":  validatedCount,
		"HTTPActiveCount": httpActiveCount,
		"Subdomains":      subdomains,
	}
	
	if err := t.Execute(file, data); err != nil {
		return fmt.Errorf("failed to execute template: %w", err)
	}
	
	e.logger.Info("HTML export complete", zap.String("path", outputPath))
	return nil
}

// ExportNuclei exports in Nuclei-compatible format
func (e *Exporter) ExportNuclei(ctx context.Context, subdomains []*types.Subdomain, outputPath string) error {
	file, err := os.Create(outputPath)
	if err != nil {
		return fmt.Errorf("failed to create file: %w", err)
	}
	defer file.Close()
	
	// Nuclei expects URLs, prefer HTTPS
	for _, sub := range subdomains {
		if sub.Validated {
			url := fmt.Sprintf("https://%s", sub.Domain)
			if _, err := fmt.Fprintln(file, url); err != nil {
				return fmt.Errorf("failed to write line: %w", err)
			}
		}
	}
	
	e.logger.Info("Nuclei export complete", zap.String("path", outputPath))
	return nil
}

// ExportBurp exports in Burp Suite compatible format
func (e *Exporter) ExportBurp(ctx context.Context, subdomains []*types.Subdomain, outputPath string) error {
	// Burp Suite uses simple text file with one domain per line
	return e.ExportText(ctx, subdomains, outputPath)
}

// ExportMultiple exports to multiple formats at once
func (e *Exporter) ExportMultiple(ctx context.Context, subdomains []*types.Subdomain, formats []string, outputDir string) error {
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		return fmt.Errorf("failed to create output directory: %w", err)
	}
	
	for _, format := range formats {
		outputPath := filepath.Join(outputDir, fmt.Sprintf("results.%s", format))
		if err := e.Export(ctx, subdomains, format, outputPath); err != nil {
			e.logger.Error("Failed to export format",
				zap.String("format", format),
				zap.Error(err),
			)
			// Continue with other formats
		}
	}
	
	return nil
}