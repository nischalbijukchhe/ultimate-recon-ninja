package ollama

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/yourusername/usr/internal/config"
	"go.uber.org/zap"
)

// Client handles communication with Ollama API
type Client struct {
	baseURL    string
	model      string
	httpClient *http.Client
	logger     *zap.Logger
	config     *config.AIConfig
}

// GenerateRequest represents a request to Ollama's generate endpoint
type GenerateRequest struct {
	Model       string  `json:"model"`
	Prompt      string  `json:"prompt"`
	Stream      bool    `json:"stream"`
	Temperature float64 `json:"temperature,omitempty"`
	MaxTokens   int     `json:"num_predict,omitempty"`
}

// GenerateResponse represents Ollama's response
type GenerateResponse struct {
	Model     string `json:"model"`
	Response  string `json:"response"`
	Done      bool   `json:"done"`
	Context   []int  `json:"context,omitempty"`
	TotalDuration     int64  `json:"total_duration,omitempty"`
	LoadDuration      int64  `json:"load_duration,omitempty"`
	PromptEvalCount   int    `json:"prompt_eval_count,omitempty"`
	EvalCount         int    `json:"eval_count,omitempty"`
}

// NewClient creates a new Ollama client
func NewClient(cfg *config.AIConfig, logger *zap.Logger) *Client {
	return &Client{
		baseURL: cfg.OllamaURL,
		model:   cfg.Model,
		config:  cfg,
		logger:  logger,
		httpClient: &http.Client{
			Timeout: 120 * time.Second, // AI generation can take time
		},
	}
}

// Generate sends a prompt to Ollama and returns the response
func (c *Client) Generate(ctx context.Context, prompt string) (string, error) {
	req := GenerateRequest{
		Model:       c.model,
		Prompt:      prompt,
		Stream:      false,
		Temperature: c.config.Temperature,
		MaxTokens:   c.config.MaxTokens,
	}
	
	jsonData, err := json.Marshal(req)
	if err != nil {
		return "", fmt.Errorf("failed to marshal request: %w", err)
	}
	
	url := fmt.Sprintf("%s/api/generate", c.baseURL)
	
	httpReq, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewBuffer(jsonData))
	if err != nil {
		return "", fmt.Errorf("failed to create request: %w", err)
	}
	
	httpReq.Header.Set("Content-Type", "application/json")
	
	c.logger.Debug("Sending request to Ollama",
		zap.String("model", c.model),
		zap.String("url", url),
	)
	
	startTime := time.Now()
	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return "", fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()
	
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("ollama returned status %d: %s", resp.StatusCode, string(body))
	}
	
	var genResp GenerateResponse
	if err := json.NewDecoder(resp.Body).Decode(&genResp); err != nil {
		return "", fmt.Errorf("failed to decode response: %w", err)
	}
	
	duration := time.Since(startTime)
	
	c.logger.Info("Ollama generation complete",
		zap.String("model", c.model),
		zap.Duration("duration", duration),
		zap.Int("eval_count", genResp.EvalCount),
	)
	
	return genResp.Response, nil
}

// IsAvailable checks if Ollama is running and accessible
func (c *Client) IsAvailable(ctx context.Context) bool {
	url := fmt.Sprintf("%s/api/tags", c.baseURL)
	
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return false
	}
	
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	
	return resp.StatusCode == http.StatusOK
}

// ListModels returns available models
func (c *Client) ListModels(ctx context.Context) ([]string, error) {
	url := fmt.Sprintf("%s/api/tags", c.baseURL)
	
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}
	
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	
	var result struct {
		Models []struct {
			Name string `json:"name"`
		} `json:"models"`
	}
	
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}
	
	models := make([]string, len(result.Models))
	for i, m := range result.Models {
		models[i] = m.Name
	}
	
	return models, nil
}