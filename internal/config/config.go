package config

// Config is the top-level application configuration.
// It is loaded from ~/.config/devops-proxy/config.yaml and must never be
// committed with real secrets.
type Config struct {
	LLM  LLMConfig  `yaml:"llm"  json:"llm"`
	SaaS SaaSConfig `yaml:"saas" json:"saas"`
	AWS  AWSConfig  `yaml:"aws"  json:"aws"`
}

// LLMConfig configures the optional AI backend.
type LLMConfig struct {
	// Provider selects the AI backend: "anthropic", "openai", or "none".
	Provider string `yaml:"provider" json:"provider"`

	// APIKey is the secret key for the selected provider.
	// Never committed to version control.
	APIKey string `yaml:"api_key" json:"api_key"`

	// Model is the specific model identifier (e.g. "claude-sonnet-4-6").
	Model string `yaml:"model" json:"model"`

	// MaxTokens caps the LLM response length.
	MaxTokens int `yaml:"max_tokens" json:"max_tokens"`
}

// SaaSConfig holds future SaaS backend connection details.
type SaaSConfig struct {
	// Endpoint is the base URL of the SaaS API.
	Endpoint string `yaml:"endpoint" json:"endpoint"`

	// Token is the bearer token for SaaS authentication.
	Token string `yaml:"token" json:"token"`
}

// AWSConfig holds AWS-specific defaults used when flags are not provided.
type AWSConfig struct {
	// DefaultRegion is used when no region flag or profile region is set.
	DefaultRegion string `yaml:"default_region" json:"default_region"`

	// DefaultProfile is used when no --profile flag is provided.
	DefaultProfile string `yaml:"default_profile" json:"default_profile"`
}

// Loader is the interface for reading Config from disk.
// Default implementation reads from ~/.config/devops-proxy/config.yaml.
type Loader interface {
	// Load reads, parses, and validates the configuration file.
	Load() (*Config, error)

	// ConfigPath returns the absolute path to the configuration file.
	ConfigPath() string
}
