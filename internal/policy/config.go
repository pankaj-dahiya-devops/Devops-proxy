package policy

type PolicyConfig struct {
	Version     int                           `yaml:"version"`
	Domains     map[string]DomainConfig       `yaml:"domains"`
	Rules       map[string]RuleConfig         `yaml:"rules"`
	Enforcement map[string]EnforcementConfig  `yaml:"enforcement,omitempty"`
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

type EnforcementConfig struct {
	FailOnSeverity string `yaml:"fail_on_severity,omitempty"`
}