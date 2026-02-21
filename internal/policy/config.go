package policy

type PolicyConfig struct {
	Version int                       `yaml:"version"`
	Domains map[string]DomainConfig   `yaml:"domains"`
	Rules   map[string]RuleConfig     `yaml:"rules"`
}

type DomainConfig struct {
	Enabled     bool   `yaml:"enabled"`
	MinSeverity string `yaml:"min_severity,omitempty"`
}

type RuleConfig struct {
	Enabled  *bool              `yaml:"enabled,omitempty"`
	Severity string             `yaml:"severity,omitempty"`
	Params   map[string]float64 `yaml:"params,omitempty"`
}