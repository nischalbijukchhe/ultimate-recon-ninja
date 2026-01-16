package plugins

import (
	"context"
	"fmt"
	"path/filepath"
	"plugin"
	"sync"

	"github.com/yourusername/usr/internal/types"
	"go.uber.org/zap"
)

// Plugin represents an external USR plugin
type Plugin interface {
	// Name returns the plugin identifier
	Name() string
	
	// Version returns the plugin version
	Version() string
	
	// Initialize initializes the plugin with configuration
	Initialize(config map[string]interface{}) error
	
	// Type returns the plugin type (source, processor, exporter)
	Type() PluginType
}

// PluginType defines plugin categories
type PluginType string

const (
	PluginTypeSource    PluginType = "source"
	PluginTypeProcessor PluginType = "processor"
	PluginTypeExporter  PluginType = "exporter"
	PluginTypeHook      PluginType = "hook"
)

// SourcePlugin extends Plugin for enumeration sources
type SourcePlugin interface {
	Plugin
	Enumerate(ctx context.Context, domain string) (*types.SourceResult, error)
}

// ProcessorPlugin extends Plugin for result processing
type ProcessorPlugin interface {
	Plugin
	Process(ctx context.Context, subdomains []*types.Subdomain) ([]*types.Subdomain, error)
}

// ExporterPlugin extends Plugin for output format
type ExporterPlugin interface {
	Plugin
	Export(ctx context.Context, subdomains []*types.Subdomain, outputPath string) error
}

// HookPlugin extends Plugin for lifecycle hooks
type HookPlugin interface {
	Plugin
	OnScanStart(ctx context.Context, domain string) error
	OnScanComplete(ctx context.Context, results []*types.Subdomain) error
	OnSubdomainDiscovered(ctx context.Context, subdomain *types.Subdomain) error
}

// Loader manages plugin loading and lifecycle
type Loader struct {
	plugins    map[string]Plugin
	pluginsMu  sync.RWMutex
	pluginDir  string
	logger     *zap.Logger
}

// NewLoader creates a new plugin loader
func NewLoader(pluginDir string, logger *zap.Logger) *Loader {
	return &Loader{
		plugins:   make(map[string]Plugin),
		pluginDir: pluginDir,
		logger:    logger,
	}
}

// LoadPlugin loads a plugin from a .so file
func (l *Loader) LoadPlugin(path string) error {
	l.logger.Info("Loading plugin", zap.String("path", path))
	
	// Load the plugin file
	p, err := plugin.Open(path)
	if err != nil {
		return fmt.Errorf("failed to open plugin: %w", err)
	}
	
	// Look up the Plugin symbol
	symPlugin, err := p.Lookup("Plugin")
	if err != nil {
		return fmt.Errorf("plugin missing Plugin symbol: %w", err)
	}
	
	// Assert to Plugin interface
	plg, ok := symPlugin.(Plugin)
	if !ok {
		return fmt.Errorf("plugin does not implement Plugin interface")
	}
	
	// Register plugin
	l.pluginsMu.Lock()
	l.plugins[plg.Name()] = plg
	l.pluginsMu.Unlock()
	
	l.logger.Info("Plugin loaded successfully",
		zap.String("name", plg.Name()),
		zap.String("version", plg.Version()),
		zap.String("type", string(plg.Type())),
	)
	
	return nil
}

// LoadAll loads all plugins from the plugin directory
func (l *Loader) LoadAll() error {
	if l.pluginDir == "" {
		l.logger.Info("No plugin directory configured, skipping plugin loading")
		return nil
	}
	
	matches, err := filepath.Glob(filepath.Join(l.pluginDir, "*.so"))
	if err != nil {
		return fmt.Errorf("failed to glob plugin directory: %w", err)
	}
	
	l.logger.Info("Loading plugins", zap.Int("count", len(matches)))
	
	for _, match := range matches {
		if err := l.LoadPlugin(match); err != nil {
			l.logger.Error("Failed to load plugin",
				zap.String("path", match),
				zap.Error(err),
			)
			// Continue loading other plugins
		}
	}
	
	return nil
}

// GetPlugin retrieves a loaded plugin by name
func (l *Loader) GetPlugin(name string) (Plugin, bool) {
	l.pluginsMu.RLock()
	defer l.pluginsMu.RUnlock()
	
	plg, exists := l.plugins[name]
	return plg, exists
}

// GetPluginsByType returns all plugins of a specific type
func (l *Loader) GetPluginsByType(pluginType PluginType) []Plugin {
	l.pluginsMu.RLock()
	defer l.pluginsMu.RUnlock()
	
	var result []Plugin
	for _, plg := range l.plugins {
		if plg.Type() == pluginType {
			result = append(result, plg)
		}
	}
	
	return result
}

// GetSourcePlugins returns all source plugins
func (l *Loader) GetSourcePlugins() []SourcePlugin {
	plugins := l.GetPluginsByType(PluginTypeSource)
	var sources []SourcePlugin
	
	for _, plg := range plugins {
		if src, ok := plg.(SourcePlugin); ok {
			sources = append(sources, src)
		}
	}
	
	return sources
}

// GetProcessorPlugins returns all processor plugins
func (l *Loader) GetProcessorPlugins() []ProcessorPlugin {
	plugins := l.GetPluginsByType(PluginTypeProcessor)
	var processors []ProcessorPlugin
	
	for _, plg := range plugins {
		if proc, ok := plg.(ProcessorPlugin); ok {
			processors = append(processors, proc)
		}
	}
	
	return processors
}

// GetExporterPlugins returns all exporter plugins
func (l *Loader) GetExporterPlugins() []ExporterPlugin {
	plugins := l.GetPluginsByType(PluginTypeExporter)
	var exporters []ExporterPlugin
	
	for _, plg := range plugins {
		if exp, ok := plg.(ExporterPlugin); ok {
			exporters = append(exporters, exp)
		}
	}
	
	return exporters
}

// GetHookPlugins returns all hook plugins
func (l *Loader) GetHookPlugins() []HookPlugin {
	plugins := l.GetPluginsByType(PluginTypeHook)
	var hooks []HookPlugin
	
	for _, plg := range plugins {
		if hook, ok := plg.(HookPlugin); ok {
			hooks = append(hooks, hook)
		}
	}
	
	return hooks
}

// InitializeAll initializes all loaded plugins
func (l *Loader) InitializeAll(config map[string]interface{}) error {
	l.pluginsMu.RLock()
	defer l.pluginsMu.RUnlock()
	
	for name, plg := range l.plugins {
		l.logger.Info("Initializing plugin", zap.String("name", name))
		
		// Get plugin-specific config
		pluginConfig := make(map[string]interface{})
		if cfg, ok := config[name].(map[string]interface{}); ok {
			pluginConfig = cfg
		}
		
		if err := plg.Initialize(pluginConfig); err != nil {
			l.logger.Error("Failed to initialize plugin",
				zap.String("name", name),
				zap.Error(err),
			)
			return fmt.Errorf("plugin %s initialization failed: %w", name, err)
		}
	}
	
	return nil
}

// Count returns the number of loaded plugins
func (l *Loader) Count() int {
	l.pluginsMu.RLock()
	defer l.pluginsMu.RUnlock()
	return len(l.plugins)
}

// ListPlugins returns information about all loaded plugins
func (l *Loader) ListPlugins() []PluginInfo {
	l.pluginsMu.RLock()
	defer l.pluginsMu.RUnlock()
	
	var info []PluginInfo
	for _, plg := range l.plugins {
		info = append(info, PluginInfo{
			Name:    plg.Name(),
			Version: plg.Version(),
			Type:    string(plg.Type()),
		})
	}
	
	return info
}

// PluginInfo contains plugin metadata
type PluginInfo struct {
	Name    string
	Version string
	Type    string
}